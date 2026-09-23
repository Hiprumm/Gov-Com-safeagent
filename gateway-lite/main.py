r"""
gov-safeagent-gateway-lite —— 阶段2 轻量统一鉴权网关（/ai 与 /biz 分流）

职责（沿用 FastAPI ai_service/main.py 现有横切实现，只换归属、不重写逻辑底线）：
  1. 统一鉴权：按 _PROTECTED_ROUTES 权限表校验（单一事实来源）
  2. 滑动窗口限流：计数落共享库（rate_limit_hits），多 worker 一致
  3. 应急 IP 封锁 / 全局熔断：实时读共享库 emergency_controls；只读研判接口放行
  4. 请求体大小限制 / CORS
  5. 前缀分流：/api/auth /api/admin(及后续迁出域) → Spring Boot biz(:8300)，其余 → FastAPI AI(:8080)

启动:
    python gateway-lite/main.py                     # 端口 8090
环境变量:
    GATEWAY_LITE_PORT  网关端口（默认 8090）
    AI_UPSTREAM        FastAPI AI 上游（默认 http://127.0.0.1:8080）
    BIZ_UPSTREAM       Spring Boot 业务上游（默认 http://127.0.0.1:8300）
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys
import time
from pathlib import Path

import httpx
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response, StreamingResponse

# 复用 ai_service 的共享单例与配置（storage / emergency / permission / auth / settings）
_SERVICE_DIR = Path(__file__).resolve().parent.parent / "ai_service"
for _p in (_SERVICE_DIR, str(_SERVICE_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, str(_p))

from config import settings  # noqa: E402
from auth import current_identity  # noqa: E402
from security.permission_engine import get_permission_engine  # noqa: E402

GATEWAY_PORT = int(os.environ.get("GATEWAY_LITE_PORT", "8090"))
AI_UPSTREAM = os.environ.get("AI_UPSTREAM", "http://127.0.0.1:8080").rstrip("/")
BIZ_UPSTREAM = os.environ.get("BIZ_UPSTREAM", "http://127.0.0.1:8300").rstrip("/")

# ----- 前缀 → 上游：业务治理域（Spring Boot）逐步迁出；其余归 FastAPI AI 域 -----
# 阶段2：auth/admin 已在 biz 落地；后续 config/audit/governance 迁出时在此追加前缀。
# 阶段3：governance（emergency/ecosystem/pipl）、audit 读取、notifications 迁入 biz。
# 注意：audit 仅迁「读取」端点；验签/锚点/TSA/归档/外发等强绑 AI 的写端点仍留在 FastAPI。
_BIZ_PREFIXES = (
    "/api/auth",
    "/api/admin",
    "/api/emergency",
    "/api/ecosystem",
    "/api/pipl",
    "/api/notifications",
    "/api/audit",
    "/api/security/approval",
    "/api/security/tool_management",
)

# audit 域下仍留在 FastAPI 的端点（验签/锚点/TSA/归档/外发/留存——强绑 AI 内核或写操作）
_AI_KEPT_AUDIT_PREFIXES = (
    "/api/audit/logs/verify-graded",
    "/api/audit/logs/verify",
    "/api/audit/forward",
    "/api/audit/config",
    "/api/audit/protection",
    "/api/audit/retention",
    "/api/audit/anchor",
    "/api/audit/tsa",
    "/api/audit/archives",
)

_OPEN_PATHS = {"/", "/api/health", "/docs", "/openapi.json", "/redoc",
               "/favicon.ico", "/swagger-ui.html", "/v3/api-docs", "/swagger-ui/"}

app = FastAPI(title="gov-safeagent-gateway-lite", version="0.2.0",
              description="阶段2 轻量统一鉴权 + /ai /biz 分流网关")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in getattr(settings, "ALLOWED_ORIGINS", "*").split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_ai = httpx.AsyncClient(base_url=AI_UPSTREAM, timeout=httpx.Timeout(600.0, connect=10.0))
_biz = httpx.AsyncClient(base_url=BIZ_UPSTREAM, timeout=httpx.Timeout(600.0, connect=10.0))


def _route_to_biz(path: str) -> bool:
    """判定 path 应由 Spring Boot(biz) 还是 FastAPI(ai) 承接。"""
    if path.startswith(("/api/auth", "/api/admin", "/api/emergency", "/api/ecosystem",
                        "/api/pipl", "/api/security/approval", "/api/security/tool_management")):
        return True
    if path.startswith("/api/notifications"):
        # 通知中心（list/read/clear）迁 biz；webhook/channels 配置仍留 FastAPI(config.py)
        if path.startswith(("/api/notifications/webhook", "/api/notifications/channels")):
            return False
        return True
    if path.startswith("/api/audit"):
        # audit 域：除强绑 AI 的写/验签端点外，读取类走 biz
        if any(path.startswith(p) for p in _AI_KEPT_AUDIT_PREFIXES):
            return False
        return True
    return False


def _upstream_client(path: str) -> httpx.AsyncClient:
    return _biz if _route_to_biz(path) else _ai


def _is_open(path: str) -> bool:
    return path in _OPEN_PATHS or path.startswith(("/docs", "/swagger-ui", "/v3/api-docs"))


# ============================================================================
# 统一鉴权权限表（沿用 ai_service/main.py 的 _PROTECTED_ROUTES，并补 biz 域规则）
#   "<perm>"  需登录且具备该权限点（来自 permission_engine）
#   "login"   任何已登录账号
#   "integration"  服务间调用：登录令牌 或 已配置 X-API-Key
# ============================================================================
_PROTECTED_ROUTES: list[tuple] = [
    # ---- 安全策略与安全控制 ----
    ("GET", "/api/security/policy", "policy.view"),
    ("PUT", "/api/security/policy", "policy.manage"),
    ("POST", "/api/security/tool_management/toggle", "tools.manage"),
    ("POST", "/api/security/runtime/terminate", "runtime.terminate"),
    ("POST", "/api/security/operation_guard/clear", "system.maintain"),
    ("POST", "/api/security/session_risk/clear", "system.maintain"),
    ("POST", "/api/security/cross_source/clear", "system.maintain"),
    ("POST", "/api/kb/rebuild", "system.maintain"),
    ("POST", "/api/kb/upload", "system.maintain"),
    ("POST", "/api/kb/delete_document", "system.maintain"),
    # ---- 治理中心 ----
    ("POST", "/api/emergency/", "system.maintain"),
    ("POST", "/api/ecosystem/", "system.maintain"),
    ("POST", "/api/pipl/", "system.maintain"),
    ("GET", "/api/emergency/status", "system.view"),
    ("GET", "/api/ecosystem/", "system.view"),
    ("GET", "/api/pipl/", "system.view"),
    ("GET", "/api/compliance/", "audit.view"),
    # ---- 可观测性大盘 ----
    ("GET", "/api/metrics", "system.view"),
    # ---- 安全检测 / 工具管控 / 扫描 ----
    ("POST", "/api/security/detect_input", "security.detect"),
    ("POST", "/api/security/detect_single", "security.detect"),
    ("POST", "/api/security/detect_file", "security.detect"),
    ("POST", "/api/security/plugin_scan", "security.scan"),
    ("POST", "/api/security/mcp_scan", "security.scan"),
    ("POST", "/api/security/skill_scan", "security.scan"),
    ("GET", "/api/security/tool_management/status", "tools.view"),
    # ---- 检测调优 / 对抗评测 / 回放 ----
    ("POST", "/api/optimization/", "security.scan"),
    # ---- 检测规则版本化热更新 / 误报标记（P0-5）----
    ("POST", "/api/security/feedback/", "system.maintain"),   # review 审核在前（长前缀优先）
    ("GET", "/api/security/rules", "login"),
    ("POST", "/api/security/rules", "system.maintain"),       # update/reload/rollback
    ("POST", "/api/security/feedback", "login"),              # 提交误报标记
    ("GET", "/api/security/feedback", "security.scan"),       # 队列查看（admin/operator）
    ("POST", "/api/security/bypass_test", "security.scan"),
    ("POST", "/api/security/bypass_batch_test", "security.scan"),
    ("POST", "/api/security/pssu/assess", "security.scan"),
    ("POST", "/api/scenarios/", "security.scan"),
    ("POST", "/api/replay/", "security.scan"),
    # ---- 会话管理（登录用户操作）----
    ("GET", "/api/agent/sessions", "login"),
    ("GET", "/api/agent/history", "login"),
    ("POST", "/api/agent/new_session", "login"),
    ("POST", "/api/agent/clear_session", "login"),
    ("POST", "/api/agent/delete_session", "login"),
    ("POST", "/api/agent/rename_session", "login"),
    ("POST", "/api/agent/recall_messages", "login"),
    ("POST", "/api/agent/delete_message", "login"),
    ("GET", "/api/agent/recall_preview", "login"),
    # ---- 审计链校验 / 合规报告（登录可访问）----
    ("GET", "/api/audit/logs/verify", "login"),
    ("GET", "/api/audit/logs/verify-graded", "login"),
    ("GET", "/api/compliance/report", "login"),
    # ---- 审计读取（已迁 biz，登录可访问；导出需 audit.export）----
    ("GET", "/api/audit/logs/recent", "login"),
    ("GET", "/api/audit/logs/page", "login"),
    ("GET", "/api/audit/logs/search", "login"),
    ("POST", "/api/audit/logs/search", "login"),
    ("POST", "/api/audit/logs", "login"),
    ("GET", "/api/audit/logs/", "login"),
    ("GET", "/api/audit/export", "audit.export"),
    ("GET", "/api/audit/stats", "login"),
    # ---- 站内通知（登录可访问）----
    ("GET", "/api/notifications", "login"),
    ("POST", "/api/notifications", "login"),
    # ---- 智能体执行入口：登录 或 服务间 API Key ----
    ("POST", "/api/agent/chat", "integration"),
    ("POST", "/api/agent/chat/stream", "integration"),
    ("POST", "/api/agent/run", "integration"),
    ("POST", "/api/agent/file_upload", "integration"),
    # ---- 业务治理域（biz）：用户与组织仅 admin；auth 个人端点需登录 ----
    ("GET", "/api/admin", "system.maintain"),
    ("POST", "/api/admin", "system.maintain"),
    ("PUT", "/api/admin", "system.maintain"),
    ("DELETE", "/api/admin", "system.maintain"),
    ("GET", "/api/auth/me", "login"),
    ("PUT", "/api/auth/profile", "login"),
    ("POST", "/api/auth/password", "login"),
    ("GET", "/api/auth/mfa", "login"),
    ("POST", "/api/auth/mfa", "login"),
    ("POST", "/api/auth/refresh", "login"),
]

# 请保持与 ai_service/main.py 一致：熔断期间只读研判接口放行
_READONLY_INTROSPECT_GET_PREFIXES = (
    "/api/audit/", "/api/compliance/", "/api/dashboard/", "/api/runtime/",
    "/api/pipl/", "/api/ecosystem/", "/api/notify/", "/api/notifications",
    "/api/policy/", "/api/agent/sessions", "/api/agent/history",
    "/api/agent/recall_preview", "/api/security/tool_management/status",
    "/api/metrics",
    "/api/auth/",
)


# ============================================================================
# 横切：CORS(已加)、请求体大小、EMERGENCY IP/熔断、统一鉴权
# ============================================================================
_MAX_BODY = getattr(settings, "MAX_REQUEST_SIZE_MB", 20) * 1024 * 1024


class GatewayReject(Exception):
    def __init__(self, status: int, content: dict):
        self.status = status
        self.content = content
        super().__init__(json.dumps(content, ensure_ascii=False))


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    # middleware 内抛出的异常不经过 @app.exception_handler（仅处理路由层），须就地捕获
    try:
        return await _security_guard(request, call_next)
    except GatewayReject as e:
        return JSONResponse(status_code=e.status, content=e.content)


def _check_integration_api_key(request: Request) -> bool:
    """服务间 API Key 校验（P0-2 密钥管理：多版本 + 可轮换 + 可吊销）。

    两条验证路径，任一通过即可：
    1. 环境变量静态 Key：AUTH_API_KEY（保留兼容，轮换需重启）；
    2. api_keys 表多版本 Key：sha256(presented) 哈希查库（verify_api_key_hash），
       支持多版本并存轮换、expires_at 过期与 status 吊销，无需重启网关。
    存储层故障时仅回退静态 Key 校验，不放大为服务中断。
    """
    presented = request.headers.get("X-API-Key") or ""
    if not presented:
        return False
    static_key = str(getattr(settings, "AUTH_API_KEY", "") or "")
    if static_key and hmac.compare_digest(presented, static_key):
        return True
    try:
        from storage import get_storage
        key_hash = hashlib.sha256(presented.encode("utf-8")).hexdigest()
        return bool(get_storage().verify_api_key_hash(key_hash))
    except Exception:
        return False


async def _security_guard(request: Request, call_next):
    path = request.url.path
    if _is_open(path):
        return await call_next(request)

    # 应急联动自身端点放行，避免处置时被误伤
    if path.startswith("/api/emergency"):
        return await call_next(request)

    # ---- 请求体大小 ----
    if request.headers.get("content-length"):
        try:
            if int(request.headers["content-length"]) > _MAX_BODY:
                raise GatewayReject(413, {"detail": f"Request body too large. Max {settings.MAX_REQUEST_SIZE_MB}MB"})
        except ValueError:
            pass

    # ---- 滑动窗口限流（计数落共享库 rate_limit_hits，多 worker 一致）----
    # 生产级改造：用户 + IP 双维度叠加检查（对齐改进清单 P0-2：
    # 登录用户按账号维度限流，未登录/匿名按 IP 维度限流，已登录用户同样计入 IP 维度）
    if getattr(settings, "RATE_LIMIT_ENABLED", False):
        try:
            from storage import get_storage
            client_ip = request.client.host if request.client else "unknown"
            identity = current_identity(request.headers.get("X-Auth-Token"))
            username = (identity or {}).get("username")
            window = getattr(settings, "RATE_LIMIT_WINDOW", 60)
            checks = []
            if username:
                checks.append((username, int(getattr(settings, "RATE_LIMIT_REQUESTS", 120))))
            checks.append((f"ip:{client_ip}", int(getattr(settings, "RATE_LIMIT_IP_REQUESTS", 120))))
            for key, limit in checks:
                if get_storage().rate_limit_check(key, limit, window):
                    raise GatewayReject(429, {"detail": "Too Many Requests"})
        except GatewayReject:
            raise
        except Exception:
            pass

    # ---- 应急 IP 封锁 / 全局熔断（实时读库）----
    try:
        from governance import get_emergency_center
        ec = get_emergency_center()
        client_ip = request.client.host if request.client else ""
        if client_ip and ec.is_ip_blocked(client_ip):
            raise GatewayReject(403, {"detail": f"IP {client_ip} 已被应急封锁，禁止访问", "code": "EMERGENCY_BLOCKED"})
        if ec.global_circuit_active():
            is_readonly = (request.method.upper() == "GET"
                           and path.startswith(_READONLY_INTROSPECT_GET_PREFIXES))
            if not is_readonly:
                raise GatewayReject(403, {"detail": "系统已全局熔断，暂停所有智能体执行", "code": "EMERGENCY_BLOCKED"})
    except GatewayReject:
        raise
    except Exception:
        pass

    # ---- 统一鉴权 ----
    method = request.method.upper()
    need = None
    for m, prefix, perm in _PROTECTED_ROUTES:
        if m == method and path.startswith(prefix):
            need = perm
            break
    if need is not None:
        # 服务间调用：X-API-Key 多版本校验（静态 env Key 兼容 + api_keys 表查库轮换）
        if need == "integration" and _check_integration_api_key(request):
            return await call_next(request)
        identity = current_identity(request.headers.get("X-Auth-Token"))
        if not identity:
            raise GatewayReject(401, {"detail": "未登录或登录已失效"})
        if need in ("login", "integration"):
            return await call_next(request)
        if not get_permission_engine().has_permission(identity.get("role"), need):
            raise GatewayReject(403, {"detail": f"无权限：需要 {need} 权限（当前角色 {identity.get('role')}）"})
    return await call_next(request)


@app.exception_handler(GatewayReject)
async def _handle_reject(_req: Request, exc: GatewayReject):
    return JSONResponse(status_code=exc.status, content=exc.content)


# ============================================================================
# 网关自检（须定义在 catch-all 代理之前，避免被 `/{path:path}` 抢先代理）
# ============================================================================
@app.get("/api/gateway/health")
async def health():
    ai_up = "unknown"
    biz_up = "unknown"
    try:
        r = await _ai.get("/api/health")
        ai_up = "up" if r.status_code < 500 else f"err:{r.status_code}"
    except Exception as e:
        ai_up = f"down:{type(e).__name__}"
    try:
        r = await _biz.get("/health")
        biz_up = "up" if r.status_code < 500 else f"err:{r.status_code}"
    except Exception as e:
        biz_up = f"down:{type(e).__name__}"
    return {
        "status": "ok",
        "ai_upstream": AI_UPSTREAM,
        "biz_upstream": BIZ_UPSTREAM,
        "ai_health": ai_up,
        "biz_health": biz_up,
        "biz_prefixes": list(_BIZ_PREFIXES),
    }


# ============================================================================
# 反向代理：SSE 流式逐块转发；普通请求透传原始体（含文件上传）
# ============================================================================

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def proxy(path: str, request: Request):
    client = _upstream_client(f"/{path}")
    headers = {k: v for k, v in request.headers.items()
               if k.lower() not in ("host", "content-length", "connection")}
    body = await request.body()
    upstream_path = f"/{path}" + (f"?{request.url.query}" if request.url.query else "")

    # 先用 HEAD 或快速 GET 判断上游是否是 SSE——不对，直接试 request，如果失败再走 stream
    # 更干净的方式：client.stream() 先看响应头，再决定用哪种处理
    # 但 client.stream() 需要 async with 上下文，且 Response 只能在上下文内存活
    # 所以我们需要：对于已知流式路径（/agent/chat/stream 等），直接走 stream；
    # 对于普通路径，走 request() + 正常 Response
    _STREAM_HINTS = ("/stream", "/sse")
    _path_lower = upstream_path.lower()
    _looks_stream = any(h in _path_lower for h in _STREAM_HINTS) or \
                    "agent/chat" in _path_lower and "stream" in _path_lower

    if _looks_stream:
        # === SSE / 流式 ===
        # httpx.AsyncClient.request() 会预读整个 body → SSE 场景下后续 aiter_raw() 报 StreamConsumed
        # 必须用 client.stream()。但 stream() 返回的上下文管理器在 async with 退出时会关闭连接，
        # 而 StreamingResponse.gen() 是在返回后才被迭代的，所以必须手动管理 enter/exit：
        #   1. __aenter__ → 拿到 status_code + headers（立即可用，无需读 body）
        #   2. 定义 gen() 引用这个 res，在 gen() 的 finally 里 __aexit__
        # 这样连接只在 gen() 被消费期间存活，SSE 流完全透传
        try:
            _cm = client.stream(
                request.method, upstream_path,
                headers=headers, content=body,
                follow_redirects=False,
            )
            _res = await _cm.__aenter__()
        except httpx.HTTPError as e:
            return JSONResponse(status_code=502,
                                content={"error": "upstream_unreachable",
                                         "detail": f"{type(e).__name__}: {getattr(e, 'request', None) and e.request.url or e}",
                                         "upstream": "biz" if _route_to_biz(f"/{path}") else "ai"})

        _upstream_status = _res.status_code
        _upstream_content_type = _res.headers.get("content-type", "")
        _upstream_headers = {k: v for k, v in _res.headers.items()
                             if k.lower() not in ("content-length", "transfer-encoding", "content-encoding")}

        async def gen():
            try:
                async for chunk in _res.aiter_raw():
                    yield chunk
            except httpx.HTTPError as e:
                err_payload = json.dumps(
                    {"error": "upstream_unreachable",
                     "detail": f"{type(e).__name__}: {str(e)[:200]}"},
                    ensure_ascii=False)
                yield f"event: error\ndata: {err_payload}\n\n".encode("utf-8")
            finally:
                await _cm.__aexit__(None, None, None)

        return StreamingResponse(
            gen(),
            status_code=_upstream_status,
            headers=_upstream_headers,
            media_type=_upstream_content_type or "text/event-stream",
        )

    # 普通请求：用 client.request()（会预读 body，方便直接构造 Response）
    try:
        res = await client.request(
            request.method, upstream_path,
            headers=headers, content=body,
            follow_redirects=False,
        )
    except httpx.HTTPError as e:
        return JSONResponse(status_code=502,
                            content={"error": "upstream_unreachable",
                                     "detail": f"{type(e).__name__}: {getattr(e, 'request', None) and e.request.url or e}",
                                     "upstream": "biz" if _route_to_biz(f"/{path}") else "ai"})

    out_headers = {k: v for k, v in res.headers.items()
                   if k.lower() not in ("content-length", "transfer-encoding", "content-encoding")}
    return Response(content=res.content, status_code=res.status_code,
                    headers=out_headers, media_type=res.headers.get("content-type"))


# ============================================================================
# WebSocket 事件通道透传（/ws/events → FastAPI）
# ============================================================================
@app.websocket("/ws/{ws_path:path}")
async def ws_proxy(ws: WebSocket, ws_path: str):
    await ws.accept()
    try:
        from websockets.asyncio.client import connect
    except Exception:
        from websockets.client import connect
    upstream_ws = AI_UPSTREAM.replace("http://", "ws://").replace("https://", "wss://") + f"/ws/{ws_path}"
    try:
        async with connect(upstream_ws) as up:
            async def pump_down():
                try:
                    async for msg in ws.iter_json():
                        await up.send(json.dumps(msg))
                except Exception:
                    pass
            import asyncio
            async def pump_up():
                try:
                    async for msg in up:
                        try:
                            parsed = json.loads(msg)
                        except Exception:
                            parsed = msg.decode("utf-8", "ignore")
                        await ws.send_json(parsed)
                except Exception:
                    pass
            await asyncio.gather(pump_down(), pump_up())
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        try:
            await ws.close()
        except Exception:
            pass


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=GATEWAY_PORT)