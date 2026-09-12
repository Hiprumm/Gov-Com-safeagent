import sys
import os
import time
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse
from typing import List, Dict, Any, Optional
from datetime import datetime

from models.schemas import (
    DetectionResult, BatchDetectionRequest, BatchDetectionResponse,
    FileDetectionRequest, FileUploadRequest,
    ToolCallRequest, ToolRiskResult,
    PluginScanRequest, PluginScanResult,
    AuditLog, EvaluationMetrics,
    ApprovalRequest, ApprovalResponse,
    RiskLevel
)

from security.input_detector import InputDetectionService
from security.tool_risk_evaluator import ToolRiskEvaluator
from security.approval_engine import ApprovalEngine
from security.kb_poisoning_detector import KBPoisoningDetector
from security.session_risk_accumulator import SessionRiskAccumulator, session_risk_accumulator
from security.adversarial_mutator import BypassTester
from security.cross_source_correlator import CrossSourceCorrelator, get_cross_source_correlator
from security.policy_manager import get_policy_manager
from security.permission_engine import get_permission_engine
from plugins.plugin_scanner import PluginScanner
from security.mcp_scanner import MCPScanner
from security.skill_analyzer import SkillAnalyzer
from security.mcp_combination_detector import MCPCombinationDetector
from security.operation_guard import get_operation_guard, OperationIntent, ActionType as GuardActionType
from audit.audit_logger import AuditLogger
from audit.evaluation_metrics import EvaluationMetricsCalculator
from gov_agent_graph.gov_agent import GovAgent
from websocket.manager import ws_manager, handle_ws_events, push_approval_update, push_risk_alert
from config import settings
from auth import (
    DEMO_USERS,
    verify_password,
    authenticate,
    create_token,
    revoke_token,
    get_user_by_token,
    current_identity,
    list_demo_accounts,
    check_password_policy,
    mfa_config,
    mfa_status,
    begin_mfa_enroll,
    confirm_mfa_enroll,
    disable_mfa,
    create_mfa_ticket,
    verify_mfa_ticket,
    sso_enabled,
    sso_header_name,
    resolve_sso_identity,
    sso_signature_required,
    sso_ip_restricted,
)

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="面向政企场景的大模型智能体安全关键技术研究 - FastAPI AI安全核心服务"
)

# ======== CORS ========
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.ALLOWED_ORIGINS.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ======== 来源IP审计中间件（等保2.0：审计日志记录来源IP） ========
@app.middleware("http")
async def audit_source_ip_middleware(request: Request, call_next):
    from audit.audit_logger import set_source_ip
    set_source_ip(request.client.host if request.client else "")
    return await call_next(request)

# ======== 基本 API Key 鉴权 (公网预览用) ========
_SKIP_AUTH_PATHS = {"/", "/api/health", "/docs", "/openapi.json", "/redoc"}

if settings.AUTH_ENABLED and settings.AUTH_API_KEY:
    @app.middleware("http")
    async def api_key_auth_middleware(request: Request, call_next):
        if request.url.path in _SKIP_AUTH_PATHS or request.url.path.startswith("/docs"):
            return await call_next(request)
        if request.headers.get("X-API-Key") != settings.AUTH_API_KEY:
            return JSONResponse(
                status_code=401,
                content={"detail": "Unauthorized: Missing or invalid X-API-Key header"}
            )
        return await call_next(request)

# ======== 简单限流 (滑动窗口)，计数落库保证多 worker 配额一致 ========

if settings.RATE_LIMIT_ENABLED:
    @app.middleware("http")
    async def rate_limit_middleware(request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        # 登录态按用户名限流更精确；匿名按 IP
        identity = None
        try:
            identity = current_identity(request.headers.get("X-Auth-Token"))
        except Exception:  # noqa: BLE001
            identity = None
        key = (identity or {}).get("username") or f"ip:{client_ip}"
        from storage import get_storage
        rl = get_storage()
        if rl.rate_limit_check(key, settings.RATE_LIMIT_REQUESTS, settings.RATE_LIMIT_WINDOW):
            return JSONResponse(status_code=429, content={"detail": "Too Many Requests"})
        return await call_next(request)

# ======== 请求体大小限制 ========
_MAX_BODY = settings.MAX_REQUEST_SIZE_MB * 1024 * 1024

@app.middleware("http")
async def request_size_limit_middleware(request: Request, call_next):
    if request.headers.get("content-length"):
        content_length = int(request.headers["content-length"])
        if content_length > _MAX_BODY:
            return JSONResponse(
                status_code=413,
                content={"detail": f"Request body too large. Max {settings.MAX_REQUEST_SIZE_MB}MB"}
            )
    return await call_next(request)

# ======== 应急联动：IP 封锁（全局中间件，IP 维度的第一道闸） ========
# 事故处置真实场景：全局熔断要"停止执行、但不能瞎眼"——
#   - IP 封锁：敌对源，任何请求（含只读研判）一律拦截；
#   - 全局熔断：阻断一切"执行/改数据"动作；但放行只读研判接口（审计/合规/台账/看板/运行时/会话史），
#     便于应急处置期间持续查看态势与取证。这些只读接口仍受登录+角色 ACL 双重约束。
_READONLY_INTROSPECT_GET_PREFIXES = (
    "/api/audit/", "/api/compliance/", "/api/dashboard/", "/api/runtime/",
    "/api/pipl/", "/api/ecosystem/", "/api/notify/", "/api/notifications",
    "/api/policy/", "/api/agent/sessions", "/api/agent/history",
    "/api/agent/recall_preview", "/api/security/tool_management/status",
    "/api/metrics",
    "/api/auth/",
)


@app.middleware("http")
async def emergency_ip_middleware(request: Request, call_next):
    path = request.url.path
    if path.startswith(("/api/emergency", "/openapi.json", "/docs", "/api/health")):
        return await call_next(request)
    try:
        from governance import get_emergency_center
        ec = get_emergency_center()
        client_ip = request.client.host if request.client else ""
        # 1) IP 封锁：源 IP 被应急封锁 → 一律拦截（含只读）——实时读库，多 worker 一致
        if client_ip and ec.is_ip_blocked(client_ip):
            return JSONResponse(status_code=403,
                                content={"detail": f"IP {client_ip} 已被应急封锁，禁止访问", "code": "EMERGENCY_BLOCKED"})
        # 2) 全局熔断：仅拦截执行/改数据动作；GET 只读研判接口放行（仍需角色权限）——实时读库
        if ec.global_circuit_active():
            is_readonly = (request.method.upper() == "GET"
                           and path.startswith(_READONLY_INTROSPECT_GET_PREFIXES))
            if not is_readonly:
                return JSONResponse(status_code=403,
                                    content={"detail": "系统已全局熔断，暂停所有智能体执行", "code": "EMERGENCY_BLOCKED"})
    except Exception:
        pass
    return await call_next(request)

# 共享单例（P1-1 收敛至 app_deps.py：main 与 routers/* 共用同一实例）
from app_deps import (
    input_detector, tool_evaluator, approval_engine, kb_poisoning_detector,
    cross_source_correlator, bypass_tester, plugin_scanner, mcp_scanner,
    skill_analyzer, combination_detector, operation_guard, audit_logger,
    metrics_calculator, gov_agent, policy_manager, permission_engine,
    _apply_policy_hot,
)
# 共享守卫（P1-1 收敛至 routers/auth.py：main 残留路由继续复用 _admin_guard）
from routers.auth import _admin_guard



# ==================== 统一鉴权中间件（生产化） ====================
# 设计动机：此前靠"每个端点手写 guard"，新增端点极易漏（审计复查实测仍有 11 个改数据端点可被匿名调用）。
# 改为声明式集中管控：把「方法 + 路径前缀 → 所需权限」登记到一张表，新增端点只加一行，杜绝漏写。
# 取值：
#   - "<perm>"        需登录且具备该权限点（权限点来自 permission_engine，单一事实来源）
#   - "login"         任何已登录账号
#   - "integration"   服务间调用：登录令牌 或 已配置的 X-API-Key（供 SDK / 网关）
_PROTECTED_ROUTES: List[tuple] = [
    # ---- 安全策略与安全控制（改这些等于改防线本身）----
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
    # ---- 治理中心（应急联动 / 开放生态 / PIPL / 合规报告）----
    ("POST", "/api/emergency/", "system.maintain"),
    ("POST", "/api/ecosystem/", "system.maintain"),
    ("POST", "/api/pipl/", "system.maintain"),
    ("GET", "/api/emergency/status", "system.view"),
    ("GET", "/api/ecosystem/", "system.view"),
    ("GET", "/api/pipl/", "system.view"),
    ("GET", "/api/compliance/", "audit.view"),
    # ---- 可观测性大盘（只读运维指标）----
    ("GET", "/api/metrics", "system.view"),
    # ---- 安全检测 / 工具管控 / 扫描（安全运维职责，业务用户不可用）----
    ("POST", "/api/security/detect_input", "security.detect"),
    ("POST", "/api/security/detect_single", "security.detect"),
    ("POST", "/api/security/detect_file", "security.detect"),
    ("POST", "/api/security/plugin_scan", "security.scan"),
    ("POST", "/api/security/mcp_scan", "security.scan"),
    ("POST", "/api/security/skill_scan", "security.scan"),
    ("GET", "/api/security/tool_management/status", "tools.view"),
    # ---- 检测调优 / 对抗评测 / 回放（安全分析类）----
    ("POST", "/api/optimization/", "security.scan"),
    ("POST", "/api/security/bypass_test", "security.scan"),
    ("POST", "/api/security/bypass_batch_test", "security.scan"),
    ("POST", "/api/security/pssu/assess", "security.scan"),
    ("POST", "/api/scenarios/", "security.scan"),
    ("POST", "/api/replay/", "security.scan"),
    # ---- 会话管理（用户操作；含查询：会话/历史按登录用户隔离）----
    ("GET", "/api/agent/sessions", "login"),
    ("GET", "/api/agent/history", "login"),
    ("POST", "/api/agent/new_session", "login"),
    ("POST", "/api/agent/clear_session", "login"),
    ("POST", "/api/agent/delete_session", "login"),
    ("POST", "/api/agent/rename_session", "login"),
    ("POST", "/api/agent/recall_messages", "login"),
    ("POST", "/api/agent/delete_message", "login"),
    ("GET", "/api/agent/recall_preview", "login"),
    # ---- 审计链校验 / 合规报告（登录可访问，匿名拒绝）----
    ("GET", "/api/audit/logs/verify", "login"),
    ("GET", "/api/audit/logs/verify-graded", "login"),
    ("GET", "/api/compliance/report", "login"),
    # ---- 智能体执行入口（会真实执行工具）→ 登录 或 服务间 API Key ----
    ("POST", "/api/agent/chat", "integration"),
    ("POST", "/api/agent/chat/stream", "integration"),
    ("POST", "/api/agent/run", "integration"),
    ("POST", "/api/agent/file_upload", "integration"),
]


@app.middleware("http")
async def unified_authorization_middleware(request: Request, call_next):
    """统一鉴权：按 _PROTECTED_ROUTES 表校验（未登记的路径不干预）。"""
    path = request.url.path
    method = request.method.upper()
    need: Optional[str] = None
    for m, prefix, perm in _PROTECTED_ROUTES:
        if m == method and path.startswith(prefix):
            need = perm
            break
    if need is None:
        return await call_next(request)

    # 服务间调用：已配置 API Key 且请求头匹配
    if (need == "integration" and settings.AUTH_API_KEY
            and request.headers.get("X-API-Key") == settings.AUTH_API_KEY):
        return await call_next(request)

    identity = current_identity(request.headers.get("X-Auth-Token"))
    if not identity:
        return JSONResponse(status_code=401, content={"detail": "未登录或登录已失效"})
    if need in ("login", "integration"):
        return await call_next(request)
    if not permission_engine.has_permission(identity.get("role"), need):
        return JSONResponse(
            status_code=403,
            content={"detail": f"无权限：需要 {need} 权限（当前角色 {identity.get('role')}）"},
        )
    return await call_next(request)


# ======== 可观测性：HTTP 请求指标采集（进程内，多 worker 各自计数） ========
@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    """按路径前缀 + 状态类统计请求量与耗时（置于鉴权之前，连被拦截的请求也计入）"""
    import time as _t
    from metrics_collector import get_metrics_collector
    start = _t.perf_counter()
    try:
        resp = await call_next(request)
        status = resp.status_code
    except Exception:
        status = 500
        raise
    finally:
        try:
            ms = (_t.perf_counter() - start) * 1000
            get_metrics_collector().record_http(request.url.path, status, ms)
        except Exception:  # noqa: BLE001
            pass
    return resp


# ======== 启动清理空会话 + 应用安全策略 ========
@app.on_event("startup")
async def startup_cleanup():
    try:
        from storage import get_storage
        storage = get_storage()
        cleaned = storage.cleanup_empty_sessions()
        if cleaned > 0:
            print(f"[STARTUP] 已清理 {cleaned} 个空会话")
    except Exception as e:
        print(f"[STARTUP] 清理空会话时出错: {e}")
    try:
        # 审计不可篡改（WORM）：启动即安装触发器，先于留存清理
        from audit.audit_protection import install_audit_protection
        prot = install_audit_protection()
        print(f"[STARTUP] 审计 WORM 保护：update_blocked={prot.get('update_blocked')}, "
              f"delete_blocked={prot.get('delete_blocked')}")
    except Exception as e:
        print(f"[STARTUP] 安装审计保护时出错: {e}")
    try:
        _apply_policy_hot()
        # 按策略留存天数处理过期审计日志（先归档再清理，走受控维护窗口）
        removed = audit_logger.apply_retention_policy(policy_manager.retention_days)
        print(f"[STARTUP] 安全策略 v{policy_manager.get_policy()['policy_version']} 已加载，"
              f"LLM分类层={'开' if input_detector.llm_classifier.enabled else '关'}，"
              f"清理过期日志 {removed} 条")
    except Exception as e:
        print(f"[STARTUP] 应用安全策略时出错: {e}")
    # 生产加固巡检：演示账号仍使用默认口令时显式告警（避免带默认口令上线）
    try:
        default_pw_users = [u for u in DEMO_USERS if verify_password(u, "admin123")]
        if default_pw_users:
            print("[STARTUP][WARN] 以下账号仍在使用默认口令 admin123，生产环境请立即修改或停用："
                  + ", ".join(default_pw_users))
    except Exception as e:
        print(f"[STARTUP] 默认口令巡检出错: {e}")
    # SSO 加固巡检：启用 SSO 但未配置共享密钥/IP 白名单 → 受信网关头可被伪造
    try:
        if sso_enabled() and not sso_signature_required() and not sso_ip_restricted():
            print("[STARTUP][WARN] 已启用 SSO 但既未配置 AUTH_SSO_SHARED_SECRET 也未配置 "
                  "AUTH_SSO_ALLOWED_IPS：受信网关头可被伪造，请确保网络层严格隔离或补充加固配置。")
    except Exception as e:
        print(f"[STARTUP] SSO 巡检出错: {e}")
    # 敏感字段加密巡检：TOTP 密钥应加密入库
    try:
        from security.secret_box import encryption_available
        if not encryption_available():
            print("[STARTUP][WARN] 敏感字段加密不可用（缺少 cryptography 或密钥），"
                  "MFA TOTP 密钥将明文入库。")
    except Exception as e:
        print(f"[STARTUP] 加密巡检出错: {e}")


@app.get("/")
async def root():
    return {"message": settings.APP_NAME, "version": settings.APP_VERSION}



# ---- P1-1: 本域路由已拆分至 routers/security.py（URL 全兼容） ----


# ---- P1-1: 本域路由已拆分至 routers/audit.py（URL 全兼容） ----


# ---- P1-1: 本域路由已拆分至 routers/config.py（URL 全兼容） ----


# ---- P1-1: 本域路由已拆分至 routers/audit.py（URL 全兼容） ----


# ---- P1-1: 本域路由已拆分至 routers/config.py（URL 全兼容） ----


# ---- P1-1: 本域路由已拆分至 routers/audit.py（URL 全兼容） ----



# ============================================================================
# 安全管控台：风险看板聚合接口（KPI + 攻击分布 + 7日趋势 + 最近风险事件）
# ============================================================================

def _parse_log_ts(ts):
    """审计日志时间戳 → naive datetime（解析失败返回 None）"""
    if isinstance(ts, str):
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
        except ValueError:
            return None
    if ts is not None and hasattr(ts, "replace"):
        try:
            return ts.replace(tzinfo=None)
        except Exception:
            return None
    return None


@app.get("/api/dashboard/overview")
async def dashboard_overview(request: Request):
    """风险看板总览：一次聚合返回 KPI 卡片、攻击类型分布、7 日趋势、最近风险事件

    按当前登录身份“角色收敛”：
    - admin / operator / auditor → 全平台数据；
    - manager → 仅本部门产生的检测/操作数据；
    - user → 仅本人发起的数据。
    未登录/无法识别时回退为全平台（兼容内部轮询与访客演示）。

    直接读 storage 原始行（detection_result 等 JSON 列已解析为 dict）；
    audit_logger._dict_to_log 重建日志时不携带 detection_result，故不走该路径。
    """
    try:
        from datetime import timedelta
        from storage import get_storage

        storage = get_storage()

        # ---- 解析当前登录身份，交由统一权限引擎决定数据收敛范围（RBAC+ABAC） ----
        identity = current_identity(request.headers.get("X-Auth-Token")) if request else {}
        username = identity.get("username", "")
        role = identity.get("role", "")
        dept = identity.get("department", "")
        display_name = identity.get("display_name", "")
        scope = permission_engine.data_scope_for(role, authenticated=bool(username))
        subject = {"username": username, "department": dept}
        # username -> department 反查表（用于把审计记录归属到部门）
        user_dept_map: Dict[str, str] = {}
        try:
            for u in storage.list_users():
                user_dept_map[u.get("username", "")] = u.get("department", "") or ""
        except Exception:
            user_dept_map = {}

        def _in_scope(d: Dict[str, Any]) -> bool:
            """审计/操作行是否在当前收敛范围可见（由权限引擎统一判定）"""
            return permission_engine.row_visible(scope, subject, d, user_dept_map)

        log_dicts = storage.get_audit_logs_recent(limit=5000)
        # 仅统计在收敛范围内的记录
        log_dicts = [d for d in log_dicts if _in_scope(d)]

        now = datetime.now()
        today_str = now.strftime("%Y-%m-%d")
        cutoff_24h = now - timedelta(hours=24)
        cutoff_7d = now - timedelta(days=7)

        today_blocked = 0
        today_risk_events = 0
        blocked_24h = 0
        total_24h = 0
        attack_dist: Dict[str, int] = {}
        risk_level_dist = {"low": 0, "medium": 0, "high": 0, "critical": 0}

        # 7 日趋势桶（日期键 MM-DD）
        trend_map: Dict[str, Dict[str, Any]] = {}
        for i in range(7):
            day = (now - timedelta(days=6 - i)).strftime("%m-%d")
            trend_map[day] = {"date": day, "total": 0, "blocked": 0}

        recent_events: List[Dict[str, Any]] = []
        risk_order = ("medium", "high", "critical")

        for d in log_dicts:
            ts = _parse_log_ts(d.get("timestamp"))
            risk_level = d.get("risk_level", "none")
            if hasattr(risk_level, "value"):
                risk_level = risk_level.value
            is_blocked = bool(d.get("is_blocked"))
            det = d.get("detection_result") or {}
            attack_type = det.get("attack_type") if isinstance(det, dict) else None
            if hasattr(attack_type, "value"):
                attack_type = attack_type.value

            if ts:
                if ts.strftime("%Y-%m-%d") == today_str:
                    if is_blocked:
                        today_blocked += 1
                    if risk_level in risk_order:
                        today_risk_events += 1
                if ts >= cutoff_24h:
                    total_24h += 1
                    if is_blocked:
                        blocked_24h += 1
                if ts >= cutoff_7d:
                    day_key = ts.strftime("%m-%d")
                    if day_key in trend_map:
                        trend_map[day_key]["total"] += 1
                        if is_blocked:
                            trend_map[day_key]["blocked"] += 1
                    if attack_type:
                        attack_dist[attack_type] = attack_dist.get(attack_type, 0) + 1
                    if risk_level in risk_level_dist:
                        risk_level_dist[risk_level] += 1

            # 日志按时间倒序，取前 10 条中高风险作为最近事件
            if risk_level in risk_order and len(recent_events) < 10:
                details = d.get("action_details") or {}
                preview = ""
                if isinstance(details, dict):
                    preview = details.get("text_preview") or details.get("original_text") or ""
                recent_events.append({
                    "log_id": d.get("log_id", ""),
                    "timestamp": d.get("timestamp"),
                    "risk_level": risk_level,
                    "attack_type": attack_type,
                    "action_type": d.get("action_type", ""),
                    "is_blocked": is_blocked,
                    "preview": str(preview)[:120],
                })

        # 待审批数量同样按收敛范围过滤（复用权限引擎的逐行 ABAC 判定）
        pending_approvals = 0
        try:
            for p in storage.list_pending_approvals():
                row = {"user_id": p.get("requester_id", ""),
                       "action_details": p.get("tool_args") or {}}
                if permission_engine.row_visible(scope, subject, row, user_dept_map):
                    pending_approvals += 1
        except Exception:
            pending_approvals = 0

        # scope 元信息：供前端标注“全平台 / 本部门 / 仅本人”视角（引擎统一生成）
        scope_meta = permission_engine.scope_meta(identity)

        return {
            "success": True,
            "scope": scope_meta,
            "kpi": {
                "today_blocked": today_blocked,
                "pending_approvals": pending_approvals,
                "risk_events_today": today_risk_events,
                "blocked_rate_24h": round(blocked_24h / total_24h * 100, 1) if total_24h else 0.0,
            },
            "attack_distribution": dict(sorted(attack_dist.items(), key=lambda x: -x[1])),
            "risk_level_distribution": risk_level_dist,
            "trend_7d": list(trend_map.values()),
            "recent_events": recent_events,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



# ---- P1-1: 本域路由已拆分至 routers/config.py（URL 全兼容） ----


# ---- P1-1: 本域路由已拆分至 routers/governance.py（URL 全兼容） ----


# ---- P1-1: 本域路由已拆分至 routers/config.py（URL 全兼容） ----


# ---- P1-1: 本域路由已拆分至 routers/security.py（URL 全兼容） ----


# ---- P1-1: 本域路由已拆分至 routers/agent.py（URL 全兼容） ----

@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION
    }


# ==================== 账号与角色（登录身份 / 角色导航 / 审计到人） ====================


# ---- P1-1: 本域路由已拆分至 routers/auth.py（URL 全兼容） ----


# ---- P1-1: 本域路由已拆分至 routers/admin.py（URL 全兼容） ----


# ---- P1-1: 本域路由已拆分至 routers/security.py（URL 全兼容） ----


# ---- P1-1: 本域路由已拆分至 routers/security.py（URL 全兼容） ----


# ---- P1-1: 本域路由已拆分至 routers/security.py（URL 全兼容） ----


# ---- P1-1: 本域路由已拆分至 routers/security.py（URL 全兼容） ----


# ---- P1-1: 本域路由已拆分至 routers/security.py（URL 全兼容） ----


# ---- P1-1: 本域路由已拆分至 routers/config.py（URL 全兼容） ----

@app.get("/api/metrics")
async def get_metrics(request: Request):
    """运维指标快照：HTTP/检测/LLM 三组计数 + 24h 分钟趋势。

    - 只读：登录 + system.view（见 _PROTECTED_ROUTES），熔断期间放行（见只读前缀白名单）
    - 多 worker 下返回 worker_pid，为当前 worker 进程视图
    """
    from metrics_collector import get_metrics_collector
    return get_metrics_collector().snapshot()


# ==================== 站内通知 & 外部通知渠道（P1-4） ====================


# ---- P1-1: 本域路由已拆分至 routers/config.py（URL 全兼容） ----

_SERVICE_START = datetime.now()


@app.get("/api/system/status")
async def system_status(request: Request):
    """聚合系统运行状态（仅管理员）：服务版本/在线时长、WebSocket、LLM 依赖、策略、数据规模"""
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    try:
        from storage import get_storage
        from websocket.manager import ws_manager as wsm
        storage = get_storage()
        policy = policy_manager.get_policy()
        return {
            "success": True,
            "health": "healthy",
            "service": {
                "name": settings.APP_NAME,
                "version": settings.APP_VERSION,
                "started_at": _SERVICE_START.strftime("%Y-%m-%d %H:%M:%S"),
                "uptime_seconds": int((datetime.now() - _SERVICE_START).total_seconds()),
            },
            "websocket": {
                "active_connections": wsm.active_connections,
                "channels": wsm.channel_count,
            },
            "llm": {
                "api_key_present": bool(getattr(input_detector.llm_classifier, "api_key", "")),
                "classifier_enabled": bool(getattr(input_detector.llm_classifier, "enabled", False)),
            },
            "policy": {
                "version": policy.get("policy_version", 0),
                "block_threshold": policy.get("block_threshold", "high"),
                "audit_retention_days": policy.get("audit_retention_days", 180),
            },
            "data": {
                "audit_logs": storage.count_audit_logs(),
                "approvals_total": storage.count_approvals(),
                "approvals_pending": len(approval_engine.list_pending()),
                "sessions_active": len(storage.list_sessions()),
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/system/maintenance/clean_sessions")
async def system_maintenance_clean_sessions(request: Request):
    """清理无消息的空会话（仅管理员）——演示/日常整理使用"""
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    try:
        from storage import get_storage
        storage = get_storage()
        removed = storage.cleanup_empty_sessions()
        audit_logger.create_log(
            user_id="admin", user_role="admin", agent_id="system_center",
            action_type="maintenance_clean_sessions",
            action_details={"removed_empty_sessions": removed},
            risk_level=RiskLevel.LOW,
            is_blocked=False,
        )
        return {"success": True, "removed": removed, "message": f"已清理 {removed} 个空会话"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== WebSocket 实时通信 ====================

@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    """WebSocket 事件通道 — 审批/风险/检测实时推送"""
    await handle_ws_events(websocket)


@app.get("/api/ws/status")
async def ws_status():
    """WebSocket 服务状态"""
    return {
        "active_connections": ws_manager.active_connections,
        "channels": ws_manager.channel_count,
    }


# ==================== 政务沙盒知识库（本地 RAG）API ====================

@app.get("/api/kb/status")
def kb_status():
    """知识库索引状态（用于前端展示语料规模与就绪度，含文档清单）"""
    from knowledge.rag_engine import get_kb, KnowledgeBase
    try:
        return {"success": True, "kb": get_kb().stats(), "documents": KnowledgeBase.list_documents()}
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": str(e), "kb": {"ready": False}, "documents": []}


@app.post("/api/kb/upload")
async def kb_upload(payload: dict):
    """上传一份知识文档（.md/.txt）到语料目录并重建索引"""
    from knowledge.rag_engine import get_kb, KnowledgeBase
    filename = str(payload.get("filename", "")).strip()
    content = str(payload.get("content", ""))
    if not filename:
        return {"success": False, "error": "缺少文件名", "documents": KnowledgeBase.list_documents()}
    try:
        name = KnowledgeBase.add_document(filename, content)
        get_kb().rebuild()
        return {"success": True, "document": name, "kb": get_kb().stats(), "documents": KnowledgeBase.list_documents()}
    except ValueError as e:
        return {"success": False, "error": str(e), "documents": KnowledgeBase.list_documents()}
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"上传失败：{e}", "documents": KnowledgeBase.list_documents()}


@app.post("/api/kb/delete_document")
async def kb_delete_document(payload: dict):
    """删除一份知识文档并重建索引"""
    from knowledge.rag_engine import get_kb, KnowledgeBase
    filename = str(payload.get("filename", "")).strip()
    if not filename:
        return {"success": False, "error": "缺少文件名", "documents": KnowledgeBase.list_documents()}
    try:
        KnowledgeBase.remove_document(filename)
        get_kb().rebuild()
        return {"success": True, "document": filename, "kb": get_kb().stats(), "documents": KnowledgeBase.list_documents()}
    except (ValueError, FileNotFoundError) as e:
        return {"success": False, "error": str(e), "documents": KnowledgeBase.list_documents()}
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": f"删除失败：{e}", "documents": KnowledgeBase.list_documents()}


@app.post("/api/kb/search")
def kb_search(payload: dict):
    """语义检索政务沙盒知识库"""
    from knowledge.rag_engine import get_kb
    query = str(payload.get("query", "")).strip()
    k = max(1, min(int(payload.get("k", 4)), 8))
    if not query:
        return {"success": False, "error": "query 不能为空", "hits": []}
    kb = get_kb()
    if not kb.ready():
        return {"success": False, "error": "知识库尚未就绪，请先重建索引", "hits": []}
    hits = kb.search(query, k=k, min_score=0.42)
    return {"success": True, "query": query, "hits": hits}


@app.post("/api/kb/rebuild")
def kb_rebuild():
    """重建知识库索引（语料更新后调用）"""
    from knowledge.rag_engine import get_kb
    try:
        get_kb().rebuild()
        return {"success": True, "kb": get_kb().stats()}
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": str(e)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)


# ==================== 治理中心：应急联动 / 开放生态 / PIPL / 合规报告 ====================


# ---- P1-1: 本域路由已拆分至 routers/governance.py（URL 全兼容） ----



# ---- P1-1: 本域路由已拆分至 routers/governance.py（URL 全兼容） ----



# ==================== 路由装配（P1-1 按业务域拆分） ====================
# 保持域间顺序与注册顺序一致：特定端点先于参数化端点（既有工程约定）。
from routers import security, audit, agent, auth, admin, config, governance
app.include_router(security.router)
app.include_router(audit.router)
app.include_router(agent.router)
app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(config.router)
app.include_router(governance.router)
