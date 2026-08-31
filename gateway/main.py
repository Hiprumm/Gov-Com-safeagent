"""
gov_safeagent_gateway —— Agent 前置反向代理（方向C-3 Middleware 形态）

客户 Agent **不改一行代码**：把流量从原 Agent 地址改指向网关即可。

    原拓扑:  客户端 ──▶ http://agent:8080
    新拓扑:  客户端 ──▶ http://gateway:8081 ──▶ http://agent:8080
                                │
                                └─ 请求前检测 / 响应后过滤 / 工具调用代理

启动:
    python gateway/main.py                        # 上游默认 http://127.0.0.1:8080
    UPSTREAM_URL=http://10.0.0.5:9000 python gateway/main.py

环境变量:
    UPSTREAM_URL   上游 Agent 地址（默认 http://127.0.0.1:8080）
    GATEWAY_PORT   网关端口（默认 8081）
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# 让 gateway 能 import gov_safeagent_sdk（源码部署；pip install 后无需此段）
_SDK_DIR = Path(__file__).resolve().parent.parent / "gov-safeagent-sdk"
if _SDK_DIR.is_dir() and str(_SDK_DIR) not in sys.path:
    sys.path.insert(0, str(_SDK_DIR))

from gov_safeagent_sdk import SecurityGuard, SafeAgentClient  # noqa: E402
from interceptors import GatewayInterceptors  # noqa: E402

UPSTREAM_URL = os.environ.get("UPSTREAM_URL", "http://127.0.0.1:8080").rstrip("/")
GATEWAY_PORT = int(os.environ.get("GATEWAY_PORT", "8081"))

app = FastAPI(title="gov-safeagent-gateway", version="1.0.0",
              description="Agent 前置安全网关：请求前检测 / 工具调用代理 / 响应后过滤")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
                   allow_headers=["*"], expose_headers=["*"])

interceptors = GatewayInterceptors(guard=SecurityGuard())
_upstream = httpx.AsyncClient(base_url=UPSTREAM_URL, timeout=120.0)

# 不做请求拦截的健康/诊断端点
_NON_INTERCEPT = ("/api/gateway/", "/api/sdk/", "/dify/", "/docs", "/openapi.json")


def _is_blocked_response(verdict: dict) -> JSONResponse:
    return JSONResponse(
        status_code=403,
        content={"error": "blocked_by_gateway", "verdict": verdict},
    )


# ============================================================================
# 网关管理/诊断端点
# ============================================================================

@app.get("/api/gateway/health")
async def health():
    return {
        "status": "ok",
        "upstream": UPSTREAM_URL,
        "interceptors": interceptors.stats,
    }


@app.get("/api/gateway/stats")
async def stats():
    return interceptors.stats


# ============================================================================
# ② 工具调用代理：客户 Agent 的工具执行走守卫（默认 deny + 审批解锁）
#    Agent 侧接入方式见 README（<10 行：把工具调用改为 HTTP 指向本端点）
# ============================================================================

@app.post("/api/gateway/tool-call")
async def tool_call_proxy(request: Request):
    payload = await request.json()
    session_id = payload.get("session_id", "default")
    tool_name = payload.get("tool_name", "")
    parameters = payload.get("parameters") or {}
    user_input = payload.get("user_input", "")

    allowed, verdict = interceptors.intercept_tool_call(
        session_id, tool_name, parameters, user_input)
    if not allowed:
        return JSONResponse(status_code=403,
                            content={"error": "tool_call_blocked", "verdict": verdict})

    # 校验通过 → 透传给上游 Agent 的工具执行端点（若配置）；否则仅返回放行判定
    upstream_tool_path = os.environ.get("UPSTREAM_TOOL_PATH", "")
    if upstream_tool_path:
        resp = await _upstream.post(upstream_tool_path, json=payload)
        return Response(content=resp.content, status_code=resp.status_code,
                        media_type=resp.headers.get("content-type", "application/json"))
    return {"allowed": True, "verdict": verdict,
            "note": "校验通过。设置 UPSTREAM_TOOL_PATH 可代理到上游真实工具执行端点。"}


@app.post("/api/gateway/grant-tool")
async def grant_tool(request: Request):
    """审批解锁：授予会话使用某工具的能力（对应人工审批动作）"""
    payload = await request.json()
    return interceptors.guard.grant_tool(
        payload.get("session_id", "default"), payload.get("tool_name", ""))


# ============================================================================
# SDK 远程 API（SafeAgentClient 的服务端）
# ============================================================================

@app.post("/api/sdk/detect")
async def sdk_detect(request: Request):
    payload = await request.json()
    verdict = await interceptors.guard.detect_async(
        payload.get("text", ""), session_id=payload.get("session_id", "default"),
        source=payload.get("source", "user_input"))
    return verdict.to_dict()


@app.post("/api/sdk/tool-check")
async def sdk_tool_check(request: Request):
    payload = await request.json()
    verdict = interceptors.guard.check_tool(
        payload.get("session_id", "default"), payload.get("tool_name", ""),
        payload.get("parameters") or {})
    return verdict.to_dict()


@app.post("/api/sdk/output-filter")
async def sdk_output_filter(request: Request):
    payload = await request.json()
    verdict = interceptors.guard.filter_output(payload.get("text", ""))
    d = verdict.to_dict()
    d["sanitized"] = verdict.sanitized
    return d


# ============================================================================
# 反向代理主路由：① 请求前检测 → 转发 → ③ 响应后过滤
# ============================================================================

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def proxy(path: str, request: Request):
    query_params = dict(request.query_params)
    headers = {k: v for k, v in request.headers.items() if k.lower() not in ("host", "content-length")}

    body_bytes = await request.body()
    body_json = None
    content_type = request.headers.get("content-type", "")
    if body_bytes and "application/json" in content_type:
        try:
            body_json = json.loads(body_bytes)
        except (json.JSONDecodeError, UnicodeDecodeError):
            body_json = None

    # ---- ① 请求前检测（含用户输入的请求；管理端点直通）----
    if not any(request.url.path.startswith(p) for p in _NON_INTERCEPT):
        allowed, verdict = interceptors.intercept_request(query_params, body_json, headers)
        if not allowed:
            return _is_blocked_response(verdict)

    # ---- 转发上游 ----
    try:
        resp = await _upstream.request(
            request.method,
            f"/{path}",
            params=request.query_params,
            headers=headers,
            content=body_bytes,
        )
    except httpx.HTTPError as e:
        return JSONResponse(status_code=502,
                            content={"error": "upstream_unreachable", "detail": str(e)})

    # ---- ③ 响应后过滤（JSON 体递归脱敏）----
    out_headers = {k: v for k, v in resp.headers.items()
                   if k.lower() not in ("content-length", "transfer-encoding", "content-encoding")}
    media_type = out_headers.get("content-type", "application/json")
    if "application/json" in media_type:
        try:
            resp_json = json.loads(resp.content)
            filtered_json, _ = interceptors.intercept_response(resp_json)
            return JSONResponse(status_code=resp.status_code, content=filtered_json,
                                headers=out_headers)
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass
    return Response(content=resp.content, status_code=resp.status_code,
                    media_type=media_type, headers=out_headers)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=GATEWAY_PORT)
