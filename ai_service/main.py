import sys
import os
import time
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
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

# ======== 简单限流 (滑动窗口) ========
_rate_limit_store: Dict[str, list] = defaultdict(list)

if settings.RATE_LIMIT_ENABLED:
    @app.middleware("http")
    async def rate_limit_middleware(request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        window = settings.RATE_LIMIT_WINDOW
        max_req = settings.RATE_LIMIT_REQUESTS
        _rate_limit_store[client_ip] = [t for t in _rate_limit_store[client_ip] if now - t < window]
        if len(_rate_limit_store[client_ip]) >= max_req:
            return JSONResponse(status_code=429, content={"detail": "Too Many Requests"})
        _rate_limit_store[client_ip].append(now)
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

input_detector = InputDetectionService()
tool_evaluator = ToolRiskEvaluator()
approval_engine = ApprovalEngine()
kb_poisoning_detector = KBPoisoningDetector()
# 复用模块级单例，与 correlation_analyzer 内部的 accumulator 保持一致（否则累积与查询实例不一致）
cross_source_correlator = get_cross_source_correlator()
# BypassTester 用 input_detector 的 detect_single_input 作为检测函数
bypass_tester = BypassTester(
    detector_func=lambda text, src: input_detector.detect_single_input(text, src)
)
plugin_scanner = PluginScanner()
mcp_scanner = MCPScanner()
skill_analyzer = SkillAnalyzer()
combination_detector = MCPCombinationDetector()
operation_guard = get_operation_guard()
audit_logger = AuditLogger()
metrics_calculator = EvaluationMetricsCalculator()
gov_agent = GovAgent()
# 安全策略中枢（管控台在线配置，热生效）
policy_manager = get_policy_manager()
# 统一权限决策引擎（RBAC + ABAC 单一事实来源）
permission_engine = get_permission_engine()


def _apply_policy_hot():
    """将策略热应用到模块级检测实例（LLM 分类层开关等）"""
    try:
        llm_available = bool(getattr(input_detector.llm_classifier, "api_key", ""))
        input_detector.llm_classifier.enabled = (
            policy_manager.llm_classifier_enabled and llm_available
        )
    except Exception as e:
        print(f"[POLICY] LLM 开关热应用失败: {e}")


# ==================== 统一鉴权中间件（生产化） ====================
# 设计动机：此前靠"每个端点手写 guard"，新增端点极易漏（审计复查实测仍有 11 个改数据端点可被匿名调用）。
# 改为声明式集中管控：把「方法 + 路径前缀 → 所需权限」登记到一张表，新增端点只加一行，杜绝漏写。
# 取值：
#   - "<perm>"        需登录且具备该权限点（权限点来自 permission_engine，单一事实来源）
#   - "login"         任何已登录账号
#   - "integration"   服务间调用：登录令牌 或 已配置的 X-API-Key（供 SDK / 网关）
_PROTECTED_ROUTES: List[tuple] = [
    # ---- 安全策略与安全控制（改这些等于改防线本身）----
    ("PUT", "/api/security/policy", "policy.manage"),
    ("POST", "/api/security/tool_management/toggle", "tools.manage"),
    ("POST", "/api/security/runtime/terminate", "runtime.terminate"),
    ("POST", "/api/security/operation_guard/clear", "system.maintain"),
    ("POST", "/api/security/session_risk/clear", "system.maintain"),
    ("POST", "/api/security/cross_source/clear", "system.maintain"),
    ("POST", "/api/kb/rebuild", "system.maintain"),
    # ---- 检测调优 / 对抗评测 / 回放（安全分析类）----
    ("POST", "/api/optimization/", "security.scan"),
    ("POST", "/api/security/bypass_test", "security.scan"),
    ("POST", "/api/security/bypass_batch_test", "security.scan"),
    ("POST", "/api/security/pssu/assess", "security.scan"),
    ("POST", "/api/scenarios/", "security.scan"),
    ("POST", "/api/replay/", "security.scan"),
    # ---- 会话管理（用户操作）----
    ("POST", "/api/agent/new_session", "login"),
    ("POST", "/api/agent/clear_session", "login"),
    ("POST", "/api/agent/delete_session", "login"),
    ("POST", "/api/agent/rename_session", "login"),
    ("POST", "/api/agent/recall_messages", "login"),
    # ---- 智能体执行入口（会真实执行工具）→ 登录 或 服务间 API Key ----
    ("POST", "/api/agent/chat", "integration"),
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


@app.get("/")
async def root():
    return {"message": settings.APP_NAME, "version": settings.APP_VERSION}


@app.post("/api/security/detect_input", response_model=BatchDetectionResponse)
async def detect_input(request: BatchDetectionRequest):
    try:
        result = input_detector.batch_detect(request)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/security/detect_single")
async def detect_single(request: Request, text: str, source: str = "user_input", session_id: Optional[str] = None):
    try:
        # 传入 session_id，让 detect_single_input 内部的关联分析按 session 正确累积
        # （修复：原实现未传 session_id，导致所有请求累积到 "default" session，正常样本被污染）
        result = input_detector.detect_single_input(text, source, session_id=session_id or "default")

        # 拦截判定：阈值由安全策略中心统一管控（medium/high/critical 可热配置）
        blocked = policy_manager.should_block(result.risk_level) if hasattr(result, 'risk_level') else False

        # 审计到人：从登录令牌还原真实操作者，用于“本人/本部门”看板收敛
        identity = current_identity(request.headers.get("X-Auth-Token")) if request else {}
        actor_id = identity.get("username") or "anonymous"
        actor_role = identity.get("role") or "user"
        actor_dept = identity.get("department") or ""
        actor_name = identity.get("display_name") or actor_id

        # 记录审计日志
        audit_logger.create_log(
            user_id=actor_id, user_role=actor_role, agent_id="security_panel",
            action_type="input_detection",
            action_details={
                "source": source, "text_preview": text[:100], "session_id": session_id,
                "department": actor_dept, "actor_name": actor_name,
            },
            risk_level=result.risk_level if hasattr(result, 'risk_level') else RiskLevel.NONE,
            detection_result=result,
            is_blocked=blocked,
        )

        # 响应附带当前策略下的实际拦截结论（阈值可在策略中心热配置，前端勿硬编码）
        resp = result.dict() if hasattr(result, "dict") else dict(result)
        resp["is_blocked"] = blocked
        return resp
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/security/detect_file")
async def detect_file(req: Request, request: FileDetectionRequest):
    try:
        from gov_agent_graph.gov_agent import FileProcessor
        
        file_processor = FileProcessor()
        processed = file_processor.process_file(request.file_data, request.file_type, request.filename)
        
        if processed["success"] and processed["content"]:
            result = input_detector.detect_single_input(
                processed["content"],
                source="uploaded_doc"
            )

            # 审计到人：从登录令牌还原真实操作者，用于“本人/本部门”看板收敛
            identity = current_identity(req.headers.get("X-Auth-Token")) if req else {}
            actor_id = identity.get("username") or "anonymous"
            actor_role = identity.get("role") or "user"
            actor_dept = identity.get("department") or ""
            actor_name = identity.get("display_name") or actor_id

            # 记录审计日志（拦截阈值走安全策略中心）
            audit_logger.create_log(
                user_id=actor_id, user_role=actor_role, agent_id="security_panel",
                action_type="file_detection",
                action_details={
                    "filename": request.filename, "file_type": request.file_type,
                    "department": actor_dept, "actor_name": actor_name,
                },
                risk_level=result.risk_level,
                detection_result=result,
                is_blocked=policy_manager.should_block(result.risk_level),
            )

            return {
                "success": True,
                "detection_result": result.dict(),
                "file_info": {
                    "filename": request.filename,
                    "file_type": request.file_type,
                    "content_preview": processed["content"][:200] + "..." if len(processed["content"]) > 200 else processed["content"]
                }
            }
        else:
            return {
                "success": False,
                "message": processed.get("message", "文件处理失败"),
                "detection_result": None
            }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/security/tool_risk", response_model=ToolRiskResult)
async def evaluate_tool_risk(request: ToolCallRequest):
    try:
        result = tool_evaluator.evaluate(request)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 操作守卫层 API ====================

@app.post("/api/security/operation_guard/check")
async def check_operation_intent(request: Request):
    """操作守卫层——动作执行前的最后一道防线

    请求体:
    {
        "tool_name": "export_data",
        "parameters": {"target": "all_users", "format": "csv"},
        "session_id": "sess-001",
        "user_input": "导出所有用户数据"
    }

    返回:
    {
        "allowed": false,
        "requires_approval": true,
        "risk_level": "medium",
        "reason": "数据导出类操作需审批",
        "blocked_by": "",
        "rate_limited": false
    }
    """
    try:
        body = await request.json()
        tool_name = body.get("tool_name", "")
        parameters = body.get("parameters", {})
        session_id = body.get("session_id", "default")
        user_input = body.get("user_input", "")

        if not tool_name:
            raise HTTPException(status_code=400, detail="请提供 tool_name")

        intent = OperationIntent(
            tool_name=tool_name,
            parameters=parameters,
            session_id=session_id,
            user_input=user_input,
        )

        result = operation_guard.check_intent(intent)

        # 审计日志
        audit_logger.create_log(
            user_id="anonymous", user_role="user", agent_id="operation_guard",
            action_type="operation_guard_check",
            action_details={
                "tool_name": tool_name,
                "parameters_preview": str(parameters)[:200],
                "session_id": session_id,
            },
            risk_level=result.risk_level,
            is_blocked=not result.allowed,
        )

        # 守卫拦截时推送实时告警
        if not result.allowed:
            import asyncio
            asyncio.create_task(push_risk_alert(
                session_id=session_id,
                risk_level=result.risk_level.value if hasattr(result.risk_level, 'value') else str(result.risk_level),
                message=f"操作被拦截：{result.reason}",
                attack_type="operation_blocked",
            ))

        return {
            "allowed": result.allowed,
            "reason": result.reason,
            "requires_approval": result.requires_approval,
            "approval_reason": result.approval_reason,
            "risk_level": result.risk_level.value if hasattr(result.risk_level, 'value') else str(result.risk_level),
            "blocked_by": result.blocked_by,
            "action_type": result.action_type.value if hasattr(result.action_type, 'value') else str(result.action_type),
            "rate_limited": result.rate_limited,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/security/operation_guard/session/{session_id}")
async def get_operation_guard_session(session_id: str):
    """获取会话操作守卫历史摘要"""
    try:
        summary = operation_guard.get_session_summary(session_id)
        return {"success": True, "summary": summary}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/security/operation_guard/clear/{session_id}")
async def clear_operation_guard_session(session_id: str):
    """清除会话操作守卫记录"""
    try:
        operation_guard.clear_session(session_id)
        return {"success": True, "message": f"Session {session_id} 操作守卫记录已清除"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== T4: 运行时工具调用控制 API ====================

@app.get("/api/security/runtime/trace/{session_id}")
async def get_runtime_trace(session_id: str):
    """获取会话ReAct执行轨迹（Think-Act-Observe全流程）"""
    try:
        trace = gov_agent.security_layer.runtime_monitor.get_session_trace(session_id)
        return {
            "session_id": session_id,
            "trace": [
                {
                    "step_id": s.step_id,
                    "step_type": s.step_type,
                    "tool_name": s.tool_name,
                    "reasoning": s.reasoning[:500] if s.reasoning else "",
                    "risk_level": s.risk_level.value,
                    "timestamp": s.timestamp,
                }
                for s in trace
            ],
            "total_steps": len(trace),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/security/runtime/anomalies/{session_id}")
async def get_runtime_anomalies(session_id: str):
    """获取会话运行时异常告警"""
    try:
        alerts = gov_agent.security_layer.runtime_monitor.check_anomalies(session_id)
        cascade = gov_agent.security_layer.runtime_monitor.detect_cascade_failure(session_id)
        return {
            "session_id": session_id,
            "anomalies": [
                {
                    "alert_type": a.alert_type,
                    "severity": a.severity.value,
                    "description": a.description,
                    "step_id": a.step_id,
                    "evidence": a.evidence,
                }
                for a in alerts
            ],
            "cascade_failure": {
                "name": cascade.name,
                "description": cascade.description,
                "severity": cascade.severity.value,
            } if cascade else None,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/security/runtime/terminate/{session_id}")
async def terminate_session(request: Request, session_id: str, reason: str = "手动终止"):
    """一键终止会话——中断智能体ReAct循环（需 runtime.terminate 权限，审计归责到真实操作人）"""
    try:
        actor = current_identity(request.headers.get("X-Auth-Token")) or {}
        termination_id = gov_agent.security_layer.runtime_monitor.terminate(session_id, reason)
        audit_logger.create_log(
            user_id=actor.get("username") or "unknown",
            user_role=actor.get("role") or "unknown",
            agent_id="gov_agent",
            action_type="manual_termination",
            action_details={"session_id": session_id, "reason": reason,
                            "department": actor.get("department", "")},
            risk_level=RiskLevel.HIGH,
            is_blocked=True,
            blocking_reason=f"手动终止: {reason}",
        )
        return {
            "success": True,
            "termination_id": termination_id,
            "message": f"会话 {session_id} 已终止",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/security/runtime/summary/{session_id}")
async def get_runtime_summary(session_id: str):
    """获取会话运行时摘要（步数/异常/级联/终止状态）"""
    try:
        summary = gov_agent.security_layer.runtime_monitor.get_session_summary(session_id)
        return {"session_id": session_id, "summary": summary}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/security/runtime/task_chain/{session_id}")
async def get_task_chain(session_id: str):
    """获取会话任务执行图"""
    try:
        chain = gov_agent.security_layer.runtime_monitor.build_task_chain(session_id)
        return {
            "session_id": session_id,
            "nodes": [
                {
                    "step_id": n.step_id,
                    "tool_name": n.tool_name,
                    "action_category": n.action_category,
                    "target": n.target,
                    "risk_level": n.risk_level.value,
                }
                for n in chain
            ],
            "total_nodes": len(chain),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/security/permission/check")
async def check_tool_permission(request: Request):
    """检查工具调用权限（工具级权限矩阵 + 参数级校验）"""
    try:
        body = await request.json()
        tool_name = body.get("tool_name", "")
        parameters = body.get("parameters", {})
        session_id = body.get("session_id", "default")

        perm = gov_agent.security_layer.permission_matrix.get_permission(tool_name)
        can_call, call_count = gov_agent.security_layer.permission_matrix.check_call_limit(tool_name, session_id)
        param_result = gov_agent.security_layer.permission_matrix.validate_parameters(tool_name, parameters)

        return {
            "tool_name": tool_name,
            "allowed_permissions": [p.value for p in perm.allowed_permissions],
            "requires_approval": perm.requires_approval,
            "base_risk": perm.base_risk.value,
            "call_limit": perm.max_calls_per_session,
            "current_calls": call_count,
            "can_call": can_call,
            "param_valid": param_result.is_valid,
            "param_violations": param_result.violations,
            "param_risk": param_result.risk_level.value,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/security/browser/check_url")
async def check_url_access(request: Request):
    """检查URL访问权限（浏览器访问控制）"""
    try:
        body = await request.json()
        url = body.get("url", "")
        session_id = body.get("session_id", "default")

        result = gov_agent.security_layer.browser_controller.check_request(
            url=url, parameters=body.get("parameters", {}), session_id=session_id,
        )
        return {
            "url": url,
            "is_allowed": result.is_allowed,
            "risk_level": result.risk_level.value,
            "reason": result.reason,
            "category": result.category,
            "detected_patterns": result.detected_patterns,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 审批查询 API（需审批查看权限） ====================
# 安全修正：原 legacy 的 /approval/create、/approval/approve、/approval/reject 已移除。
# 它们把 approver_id / approver_role 直接取自调用方参数且完全不做鉴权，
# 可被匿名请求伪造成 super_admin 批准任意审批单（越权绕过，实测已复现）。
# 审批单由安全层/智能体内部产生；批准与驳回统一走带令牌校验的 /approve/{id}、/reject/{id}。

def _approval_view_guard(request: Request):
    """返回具备审批查看权限的身份（admin/operator/auditor/manager），否则 None。"""
    identity = current_identity(request.headers.get("X-Auth-Token"))
    if identity and permission_engine.has_permission(identity.get("role"), "approval.view"):
        return identity
    return None


@app.get("/api/security/approval/pending")
async def get_pending_approvals(request: Request):
    """获取所有待审批的请求（需审批查看权限）

    注意：本路由必须注册在 /api/security/approval/{request_id} 之前，
    否则 "pending" 会被当作 request_id 匹配（历史缺陷：前端审批面板
    一直显示"暂无待审批请求"即由此导致）。
    """
    if not _approval_view_guard(request):
        raise HTTPException(status_code=403, detail="无权限：需要审批查看权限")
    try:
        pending = approval_engine.list_pending()
        pending_dicts = [r.dict() for r in pending]
        return {
            "pending": pending_dicts,
            "count": len(pending_dicts),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/security/approval/history")
async def get_approval_history(request: Request, limit: int = 50):
    """获取最近的审批记录（全部状态），供审批中心"已处理"列表使用（需审批查看权限）

    同 pending：静态段路由必须注册在 /{request_id} 参数路由之前。
    """
    if not _approval_view_guard(request):
        raise HTTPException(status_code=403, detail="无权限：需要审批查看权限")
    try:
        from storage import get_storage
        limit = max(1, min(limit, 200))
        records = get_storage().list_recent_approvals(limit=limit)
        # 状态统计
        stats: dict = {}
        for r in records:
            stats[r.get("status", "unknown")] = stats.get(r.get("status", "unknown"), 0) + 1
        return {"records": records, "count": len(records), "stats": stats}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/security/approval/{request_id}", response_model=ApprovalRequest)
async def get_approval(request: Request, request_id: str):
    if not _approval_view_guard(request):
        raise HTTPException(status_code=403, detail="无权限：需要审批查看权限")
    try:
        result = approval_engine.get_request(request_id)
        if not result:
            raise HTTPException(status_code=404, detail="审批请求不存在")
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/security/plugin_scan")
async def scan_plugin(request: PluginScanRequest):
    try:
        result = plugin_scanner.scan(request)

        # 转换为前端可用的格式
        safety = result.safety_score
        risk_score = round(1.0 - safety / 100.0, 2)
        if safety >= 90: rating = "A"; risk_level = RiskLevel.NONE
        elif safety >= 75: rating = "B"; risk_level = RiskLevel.LOW
        elif safety >= 60: rating = "C"; risk_level = RiskLevel.MEDIUM
        elif safety >= 40: rating = "D"; risk_level = RiskLevel.HIGH
        else: rating = "E"; risk_level = RiskLevel.CRITICAL

        critical = sum(1 for v in result.vulnerabilities if v.severity == RiskLevel.CRITICAL)
        high = sum(1 for v in result.vulnerabilities if v.severity == RiskLevel.HIGH)
        medium = sum(1 for v in result.vulnerabilities if v.severity == RiskLevel.MEDIUM)
        low = sum(1 for v in result.vulnerabilities if v.severity == RiskLevel.LOW)

        issues = [{
            "severity": v.severity.value,
            "type": v.vulnerability_id,
            "description": v.description,
            "line_number": v.line_number,
            "code_snippet": v.location,
        } for v in result.vulnerabilities]

        recommendations = _get_plugin_recommendations(result.vulnerabilities)

        response = {
            "filename": request.filename or result.plugin_name,
            "security_rating": rating,
            "risk_level": risk_level.value,
            "risk_score": risk_score,
            "total_issues": len(result.vulnerabilities),
            "critical_issues": critical,
            "high_issues": high,
            "medium_issues": medium,
            "low_issues": low,
            "issues": issues,
            "recommendations": recommendations,
            "summary": f"扫描完成，安全评分 {safety}/100，共发现 {len(result.vulnerabilities)} 个安全问题（严重{critical}、高危{high}、中危{medium}、低危{low}），评级 {rating} 级"
        }

        # 记录审计日志
        audit_logger.create_log(
            user_id="anonymous", user_role="user", agent_id="security_panel",
            action_type="plugin_scan",
            action_details={"filename": request.filename},
            risk_level=risk_level,
            is_blocked=safety < 40,
        )

        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def _get_plugin_recommendations(vulnerabilities) -> list:
    recs = []
    vuln_ids = [v.vulnerability_id for v in vulnerabilities]
    vuln_text = ' '.join(vuln_ids).lower()

    has_cmd = any('os.system' in vid or 'subprocess' in vid for vid in vuln_ids)
    has_eval = any('eval' in vid or 'exec' in vid for vid in vuln_ids)
    has_sensitive_import = any(vid.startswith('IMPORT_') for vid in vuln_ids)
    has_network = any('request' in vid.lower() or 'socket' in vid.lower() for vid in vuln_ids)
    has_file = any('file' in vid.lower() or 'open' in vid.lower() for vid in vuln_ids)

    if has_cmd:
        recs.append("移除 os.system/subprocess 调用，改用安全的 API 封装或沙箱执行")
    if has_eval:
        recs.append("避免使用 eval/exec，动态代码执行存在严重安全风险，请改用白名单解析器")
    if has_sensitive_import:
        recs.append("审查敏感模块导入(os/subprocess/socket)，确认业务必要性，评估替代方案")
    if has_network:
        recs.append("限制外部网络请求，白名单目标域名和 IP，避免敏感数据外泄")
    if has_file:
        recs.append("限制文件操作权限，使用沙箱隔离文件系统访问，避免任意文件读写")
    if not recs:
        recs.append("当前未发现高风险模式，建议定期更新扫描规则")
    return recs


# ======== 工具管控模块（MCP/Skill生态安全检测） ========
tool_management_enabled = True


@app.get("/api/security/tool_management/status")
async def get_tool_management_status():
    return {"enabled": tool_management_enabled}


@app.post("/api/security/tool_management/toggle")
async def toggle_tool_management(request: Request):
    global tool_management_enabled
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    tool_management_enabled = body.get("enabled", not tool_management_enabled)
    return {"enabled": tool_management_enabled}


@app.post("/api/security/mcp_scan")
async def scan_mcp_tool(request: Request):
    body = await request.json()
    descriptor = body.get("descriptor", {})
    tool_id = body.get("tool_id", "unknown")

    if not tool_management_enabled:
        return {
            "module_enabled": False,
            "blocked": False,
            "message": "工具管控模块未开启，MCP工具可正常加载",
            "tool_id": tool_id,
        }

    findings = mcp_scanner.analyze_descriptor(descriptor, tool_id)

    critical = sum(1 for f in findings if f.get("risk_level") == RiskLevel.CRITICAL)
    high = sum(1 for f in findings if f.get("risk_level") == RiskLevel.HIGH)
    blocked = critical > 0

    perm_findings = [f for f in findings if f.get("type") == "over_permission"]
    permission_matrix = []
    for pf in perm_findings:
        permission_matrix.append({
            "permissions": pf.get("detected_permissions", []),
            "description": pf.get("description", ""),
            "risk_level": pf.get("risk_level", RiskLevel.MEDIUM).value if hasattr(pf.get("risk_level"), 'value') else str(pf.get("risk_level", "")),
        })

    return {
        "module_enabled": True,
        "blocked": blocked,
        "tool_id": tool_id,
        "total_findings": len(findings),
        "critical": critical,
        "high": high,
        "findings": findings,
        "permission_matrix": permission_matrix,
        "risk_report": {
            "summary": f"检测到{len(findings)}个问题（{critical}个严重、{high}个高危）",
            "recommendation": "阻止加载" if blocked else "建议审批后加载",
        },
    }


@app.post("/api/security/skill_scan")
async def scan_skill_package(request: Request):
    body = await request.json()
    manifest = body.get("manifest", {})
    scripts = body.get("scripts", [])
    skill_name = body.get("skill_name", "unknown")

    if not tool_management_enabled:
        return {
            "module_enabled": False,
            "blocked": False,
            "message": "工具管控模块未开启，Skill包可正常加载",
            "skill_name": skill_name,
        }

    result = skill_analyzer.analyze_skill_package(manifest, scripts, skill_name)

    blocked = result.safety_grade in ("C", "D") and any(
        f.severity == RiskLevel.CRITICAL for f in result.findings
    )

    return {
        "module_enabled": True,
        "blocked": blocked,
        "skill_name": skill_name,
        "safety_grade": result.safety_grade,
        "safety_score": result.safety_score,
        "total_findings": len(result.findings),
        "findings": [
            {
                "type": f.finding_type,
                "description": f.description,
                "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                "location": f.location,
            } for f in result.findings
        ],
        "url_findings": result.url_findings,
        "secrets_found": result.secrets_found,
        "risk_report": {
            "summary": result.summary,
            "recommendation": "禁止加载" if blocked else ("审批后加载" if result.safety_grade in ("B", "C") else "可安全加载"),
        },
    }


@app.post("/api/security/tool_combination_scan")
async def scan_tool_combinations(request: Request):
    body = await request.json()
    tools = body.get("tools", [])

    if not tool_management_enabled:
        return {
            "module_enabled": False,
            "message": "工具管控模块未开启，跳过组合风险检测",
        }

    result = combination_detector.analyze_tool_set(tools)

    return {
        "module_enabled": True,
        "total_tools": result.total_tools_analyzed,
        "total_capabilities": result.total_capabilities,
        "total_findings": len(result.findings),
        "highest_risk_score": result.highest_risk_score,
        "overall_risk": result.overall_risk.value if hasattr(result.overall_risk, 'value') else str(result.overall_risk),
        "summary": result.summary,
        "findings": [
            {
                "pattern_name": f.pattern_name,
                "description": f.description,
                "detected_tools": f.detected_tools,
                "risk_score": f.risk_score,
                "risk_level": f.risk_level.value if hasattr(f.risk_level, 'value') else str(f.risk_level),
                "attack_type": f.attack_type.value if hasattr(f.attack_type, 'value') else str(f.attack_type),
                "recommended_action": f.recommended_action,
            } for f in result.findings
        ],
    }


# ==================== 审计日志读取：登录 + 数据范围收敛 ====================
def _audit_read_scope(request: Request):
    """审计读取的可见范围：未登录返回 None；否则返回 (scope, subject, user_dept_map)。

    与风险看板共用同一套 ABAC 规则（权限引擎 row_visible）：
    admin/operator/auditor 看全平台；manager 看本部门；user 仅本人。
    """
    identity = current_identity(request.headers.get("X-Auth-Token"))
    if not identity:
        return None
    scope = permission_engine.data_scope_for(identity.get("role"), authenticated=True)
    subject = {"username": identity.get("username", ""),
               "department": identity.get("department", "")}
    dept_map: Dict[str, str] = {}
    try:
        from storage import get_storage
        for u in get_storage().list_users():
            dept_map[u.get("username", "")] = u.get("department", "") or ""
    except Exception:
        dept_map = {}
    return scope, subject, dept_map


def _filter_by_scope(rows: list, scope_ctx) -> list:
    """按可见范围过滤审计行（scope=all 时直接返回）。"""
    scope, subject, dept_map = scope_ctx
    if scope == "all":
        return rows
    return [r for r in rows if permission_engine.row_visible(scope, subject, r, dept_map)]


@app.get("/api/audit/logs/recent")
async def get_recent_logs(request: Request, limit: int = 100):
    """最近审计日志（需登录，按登录身份收敛数据范围）"""
    sc = _audit_read_scope(request)
    if not sc:
        raise HTTPException(status_code=401, detail="未登录")
    try:
        logs = audit_logger.get_recent_logs(limit)
        rows = _filter_by_scope([log.dict() for log in logs], sc)
        return {"logs": rows, "scope": sc[0]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/audit/logs/page")
async def get_logs_page(request: Request, page: int = 1, page_size: int = 20):
    """分页查询审计日志（按时间倒序，按登录身份收敛数据范围）

    page: 页码，从 1 开始
    page_size: 每页条数（默认20，可选20/50，上限100）
    """
    sc = _audit_read_scope(request)
    if not sc:
        raise HTTPException(status_code=401, detail="未登录")
    page = max(1, page)
    page_size = min(max(1, page_size), 100)
    scope = sc[0]
    try:
        if scope == "all":
            result = audit_logger.get_logs_page(page=page, page_size=page_size)
            result["logs"] = [log.dict() for log in result["logs"]]
            result["scope"] = scope
            return result
        # 非全平台：先取窗口数据 → 过滤 → 再分页，保证 total 与可见行口径一致
        window_size = min(20000, max(page * page_size * 5, 2000))
        rows = _filter_by_scope([log.dict() for log in audit_logger.get_recent_logs(window_size)], sc)
        total = len(rows)
        start = (page - 1) * page_size
        return {
            "logs": rows[start:start + page_size],
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": (total + page_size - 1) // page_size,
            "scope": scope,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/audit/config")
async def get_audit_config():
    """审计配置（日志留存天数等）"""
    from audit.audit_logger import AUDIT_RETENTION_DAYS
    return {
        "retention_days": AUDIT_RETENTION_DAYS,
        "retention_hint": f"审计日志默认留存 {AUDIT_RETENTION_DAYS} 天（可通过环境变量 AUDIT_RETENTION_DAYS 配置为 30=1个月 / 90=3个月 / 180=6个月）",
    }


# ==================== 审计不可篡改（WORM）与留存归档 ====================

@app.get("/api/audit/protection")
async def get_audit_protection(request: Request):
    """审计保护状态：WORM 触发器 + 归档目录 + 留存天数（仅管理员）。"""
    from audit.audit_protection import protection_status, ARCHIVE_DIR
    from audit.audit_logger import AUDIT_RETENTION_DAYS
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    return {
        "success": True,
        "protection": protection_status(),
        "archive_dir": ARCHIVE_DIR,
        "retention_days": AUDIT_RETENTION_DAYS,
    }


@app.post("/api/audit/protection/install")
async def install_audit_worm(request: Request):
    """安装/修复审计 WORM 保护触发器（仅管理员）。"""
    from audit.audit_protection import install_audit_protection
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    return {"success": True, "protection": install_audit_protection()}


@app.post("/api/audit/retention/run")
async def run_audit_retention(request: Request, days: Optional[int] = None):
    """立即执行留存策略：归档超期日志后再清理（仅管理员，走受控维护窗口）。"""
    from audit.audit_protection import retention_archive_and_purge
    from audit.audit_logger import AUDIT_RETENTION_DAYS
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    try:
        result = retention_archive_and_purge(int(days) if days else AUDIT_RETENTION_DAYS)
        return {"success": True, **result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 审计外发（SIEM 对接） ====================

@app.get("/api/audit/forward")
async def get_audit_forward(request: Request):
    """查询审计外发配置（仅管理员）。"""
    from audit.audit_forwarder import load_config
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    return {"success": True, "config": load_config(force=True)}


@app.put("/api/audit/forward")
async def put_audit_forward(request: Request):
    """配置审计外发（仅管理员）：{url, enabled, format: json|cef}。"""
    from audit.audit_forwarder import save_config, load_config
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    body = await _body(request)
    fmt = str(body.get("format", "json")).lower()
    if fmt not in ("json", "cef"):
        fmt = "json"
    save_config(str(body.get("url", "")), bool(body.get("enabled", False)), fmt)
    return {"success": True, "config": load_config(force=True)}


@app.post("/api/audit/forward/test")
async def test_audit_forward(request: Request):
    """测试审计外发连通性（仅管理员）。"""
    from audit.audit_forwarder import test_forward
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    result = test_forward()
    return {"success": bool(result.get("ok")), **result}


# ==================== 可信时间戳（TSA）与审计锚点（Checkpoint） ====================

@app.get("/api/audit/anchor")
async def get_audit_anchor(request: Request):
    """查询审计锚点（最近 10 条）与 TSA 配置（仅管理员）。"""
    from audit.tsa import list_anchors, latest_anchor, load_tsa_config
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    return {
        "success": True,
        "anchors": list_anchors()[-10:],
        "latest": latest_anchor(),
        "tsa": load_tsa_config(force=True),
    }


@app.post("/api/audit/anchor")
async def create_audit_anchor(request: Request):
    """创建审计锚点：对当前链头请求可信时间戳并留档（仅管理员）。"""
    from audit.tsa import create_anchor
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    try:
        return {"success": True, "anchor": create_anchor()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/audit/anchor/verify")
async def verify_audit_anchor(request: Request):
    """校验当前审计链相对最近锚点是否一致（未截断/回滚，仅管理员）。"""
    from audit.tsa import verify_anchor
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    result = verify_anchor()
    return {"success": bool(result.get("ok")), **result}


@app.get("/api/audit/tsa")
async def get_audit_tsa(request: Request):
    """查询可信时间戳（TSA）配置（仅管理员）。"""
    from audit.tsa import load_tsa_config
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    return {"success": True, "config": load_tsa_config(force=True)}


@app.put("/api/audit/tsa")
async def put_audit_tsa(request: Request):
    """配置可信时间戳服务（仅管理员）：{url, enabled}。"""
    from audit.tsa import save_tsa_config
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    body = await _body(request)
    return {"success": True, "config": save_tsa_config(str(body.get("url", "")), bool(body.get("enabled", False)))}


# ==================== 归档文件 / 外发投递历史（治理面板） ====================

@app.get("/api/audit/archives")
async def list_audit_archives(request: Request):
    """列出审计归档文件（仅管理员）。"""
    from audit.audit_protection import list_archives, ARCHIVE_DIR
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    return {"success": True, "archives": list_archives(), "archive_dir": ARCHIVE_DIR}


@app.get("/api/audit/archives/{name}")
async def download_audit_archive(request: Request, name: str):
    """下载指定归档文件（仅管理员，防目录穿越）。"""
    from audit.audit_protection import resolve_archive
    if not _admin_guard(request):
        raise HTTPException(status_code=403, detail="无权限：需要系统管理员身份")
    path = resolve_archive(name)
    if not path:
        raise HTTPException(status_code=404, detail="归档文件不存在")
    return FileResponse(path, media_type="application/x-ndjson", filename=name)


@app.get("/api/audit/forward/history")
async def get_audit_forward_history(request: Request, limit: int = 30):
    """外发投递历史（最近若干条，仅管理员）。"""
    from audit.audit_forwarder import forward_history
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    return {"success": True, "history": forward_history(limit)}


@app.get("/api/audit/logs/verify")
async def verify_audit_chain():
    """校验审计日志哈希链与签名完整性（防篡改）"""
    try:
        return audit_logger.verify_chain()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/audit/logs/verify-graded")
async def verify_graded_chain():
    """校验分级审计签名链完整性（方向A-6）

    分级验签：
    - LOW（只读）：HMAC
    - MEDIUM（本地写入）：HMAC + Agent 签名
    - HIGH（命令执行/网络外发）：HMAC + Agent 签名 + ZKP 证明
    """
    try:
        return audit_logger.verify_graded_chain()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/audit/logs/{log_id}", response_model=AuditLog)
async def get_log(log_id: str):
    try:
        log = audit_logger.get_log(log_id)
        if not log:
            raise HTTPException(status_code=404, detail="日志不存在")
        return log
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/audit/logs/search")
async def search_logs(
    request: Request,
    user_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    risk_level: Optional[str] = None,
    action_type: Optional[str] = None,
    is_blocked: Optional[bool] = None
):
    """审计日志检索（需登录，按登录身份收敛数据范围）"""
    sc = _audit_read_scope(request)
    if not sc:
        raise HTTPException(status_code=401, detail="未登录")
    try:
        risk_level_enum = RiskLevel(risk_level) if risk_level else None
        logs = audit_logger.search_logs(
            user_id=user_id,
            agent_id=agent_id,
            risk_level=risk_level_enum,
            action_type=action_type,
            is_blocked=is_blocked
        )
        rows = _filter_by_scope([log.dict() for log in logs], sc)
        return {"logs": rows, "scope": sc[0]}
    except ValueError:
        raise HTTPException(status_code=400, detail="无效的风险等级")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/audit/export")
async def export_audit_logs(
    request: Request,
    format: str = "json",
    risk_level: Optional[str] = None,
    user_id: Optional[str] = None,
    action_type: Optional[str] = None,
    limit: int = 1000,
):
    """
    审计日志导出（需 audit.export 权限：admin / auditor）

    支持 JSON 和 CSV 两种格式。
    可按风险等级、用户、操作类型筛选。

    Query params:
        format: json | csv (default: json)
        risk_level: none | low | medium | high | critical
        user_id: 用户ID过滤
        action_type: 操作类型过滤
        limit: 最大导出数量 (default: 1000)
    """
    exporter = current_identity(request.headers.get("X-Auth-Token"))
    if not exporter:
        raise HTTPException(status_code=401, detail="未登录")
    if not permission_engine.has_permission(exporter.get("role"), "audit.export"):
        raise HTTPException(status_code=403, detail="无权限：需要审计导出权限")

    import csv
    import io

    try:
        risk_level_enum = RiskLevel(risk_level) if risk_level else None
        logs = audit_logger.search_logs(
            user_id=user_id,
            risk_level=risk_level_enum,
            action_type=action_type,
        )
        logs = logs[:limit]

        if format == "csv":
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(["log_id", "timestamp", "user_id", "user_role", "agent_id",
                             "action_type", "action_details", "risk_level",
                             "is_blocked", "block_reason"])
            for log in logs:
                d = log.dict() if hasattr(log, 'dict') else log
                writer.writerow([
                    d.get("log_id", ""),
                    str(d.get("timestamp", "")),
                    d.get("user_id", ""),
                    d.get("user_role", ""),
                    d.get("agent_id", ""),
                    d.get("action_type", ""),
                    str(d.get("action_details", "")),
                    d.get("risk_level", "none") if hasattr(d.get("risk_level", None), 'value') else str(d.get("risk_level", "")),
                    d.get("is_blocked", False),
                    d.get("block_reason", ""),
                ])
            return JSONResponse(content={
                "success": True,
                "format": "csv",
                "count": len(logs),
                "data": output.getvalue(),
            })

        # 默认 JSON
        return {
            "success": True,
            "format": "json",
            "count": len(logs),
            "logs": [log.dict() if hasattr(log, 'dict') else log for log in logs],
        }
    except ValueError:
        raise HTTPException(status_code=400, detail="无效的风险等级")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/audit/stats")
async def audit_statistics(
    hours: int = 24,
):
    """
    审计日志统计分析

    Args:
        hours: 统计最近N小时的数据 (default: 24)

    Returns:
        攻击模式统计、风险分布、操作类型分布
    """
    try:
        logs = audit_logger.get_recent_logs(limit=5000)

        # 过滤时间范围
        from datetime import datetime, timedelta
        cutoff = datetime.now() - timedelta(hours=hours)
        filtered = []
        for log in logs:
            log_dict = log.dict() if hasattr(log, 'dict') else log
            ts = log_dict.get("timestamp")
            if ts:
                if isinstance(ts, str):
                    try:
                        ts = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                    except ValueError:
                        continue
                if ts > cutoff:
                    filtered.append(log_dict)

        total = len(filtered)

        # 风险分布
        risk_dist = {"none": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}
        for log in filtered:
            rl = log.get("risk_level", "none")
            if hasattr(rl, 'value'):
                rl = rl.value
            if rl in risk_dist:
                risk_dist[rl] += 1

        # 操作类型分布
        action_dist: Dict[str, int] = {}
        for log in filtered:
            at = log.get("action_type", "unknown")
            action_dist[at] = action_dist.get(at, 0) + 1

        # 拦截统计
        blocked = sum(1 for log in filtered if log.get("is_blocked"))

        # 用户活跃度
        user_activity: Dict[str, int] = {}
        for log in filtered:
            uid = log.get("user_id", "unknown")
            user_activity[uid] = user_activity.get(uid, 0) + 1

        return {
            "success": True,
            "period": f"最近{hours}小时",
            "total_logs": total,
            "blocked_count": blocked,
            "blocked_rate": round(blocked / total * 100, 1) if total > 0 else 0,
            "risk_distribution": risk_dist,
            "action_distribution": dict(sorted(action_dist.items(), key=lambda x: -x[1])[:20]),
            "top_users": dict(sorted(user_activity.items(), key=lambda x: -x[1])[:10]),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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


# ============================================================================
# 安全管控台：安全策略中心（在线配置 · 热生效 · 版本化）
# ============================================================================

@app.get("/api/security/policy")
async def get_security_policy():
    """获取当前安全策略配置 + 版本 + 能力可用性"""
    try:
        policy = policy_manager.get_policy()
        llm_key_present = bool(getattr(input_detector.llm_classifier, "api_key", ""))
        return {
            "success": True,
            "policy": policy,
            "capabilities": {
                # LLM 分类层实际生效 = 策略开关 且 API Key 可用
                "llm_classifier_effective": input_detector.llm_classifier.enabled,
                "llm_api_key_present": llm_key_present,
            },
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/api/security/policy")
async def update_security_policy(request: dict):
    """更新安全策略（热生效，自动递增 policy_version）

    可更新字段：llm_classifier_enabled / block_threshold /
    audit_retention_days / trusted_domain_suffixes
    """
    try:
        changes = request.get("policy") if isinstance(request.get("policy"), dict) else request
        old_policy = policy_manager.get_policy()
        new_policy = policy_manager.update_policy(changes)

        # 热应用：LLM 分类层开关
        _apply_policy_hot()

        # 留存天数变更：立即按新策略清理一次
        retention_changed = (
            new_policy["audit_retention_days"] != old_policy["audit_retention_days"]
        )
        removed = 0
        if retention_changed:
            removed = audit_logger.apply_retention_policy(new_policy["audit_retention_days"])

        audit_logger.create_log(
            user_id="admin", user_role="admin", agent_id="policy_center",
            action_type="policy_update",
            action_details={
                "changes": changes,
                "policy_version": new_policy["policy_version"],
                "retention_cleaned": removed,
            },
            risk_level=RiskLevel.LOW,
            is_blocked=False,
        )

        return {
            "success": True,
            "policy": new_policy,
            "capabilities": {
                "llm_classifier_effective": input_detector.llm_classifier.enabled,
                "llm_api_key_present": bool(getattr(input_detector.llm_classifier, "api_key", "")),
            },
            "retention_cleaned": removed,
            "message": f"策略已更新至 v{new_policy['policy_version']}，即时生效",
        }
    except ValueError as ve:
        raise HTTPException(status_code=400, detail=str(ve))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# T5 合规标准对接：合规报告 / 关键词库 / AIGC标识 / 哈希链校验
# ============================================================================

@app.get("/api/compliance/report")
async def compliance_report(format: str = "json"):
    """生成等保2.0/算法备案/大模型备案安全评估报告

    Args:
        format: json | markdown(md) | html
    """
    try:
        from audit.compliance_report import get_compliance_generator
        generator = get_compliance_generator()
        data = generator.generate(format)
        if format.lower() in ("md", "markdown"):
            from fastapi.responses import PlainTextResponse
            return PlainTextResponse(data, media_type="text/markdown")
        if format.lower() == "html":
            from fastapi.responses import HTMLResponse
            return HTMLResponse(data)
        return data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/compliance/keywords/stats")
async def compliance_keywords_stats():
    """关键词库规模统计（GB/T 45654-2025）"""
    try:
        from security.compliance_lexicon import get_lexicon_stats
        return get_lexicon_stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/compliance/content_safety")
async def compliance_content_safety(request: dict):
    """生成内容安全合格率评测（要求 ≥90%）"""
    try:
        from security.compliance_lexicon import evaluate_content_safety_batch
        samples = request.get("samples") or []
        return evaluate_content_safety_batch(samples)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/compliance/refusal_rate")
async def compliance_refusal_rate(request: dict):
    """拒答率/非拒答率评测"""
    try:
        from security.compliance_lexicon import evaluate_refusal_rate
        attack = request.get("attack_prompts") or []
        normal = request.get("normal_prompts") or []
        if not attack and not normal:
            return {"error": "请提供 attack_prompts 和 normal_prompts"}
        def _responder(prompt: str) -> str:
            from security.input_detector import InputDetectionService
            from security.compliance_lexicon import search_risks
            from models.schemas import RiskLevel, InputSource
            try:
                r = InputDetectionService().detect_single_input(prompt, InputSource.USER_INPUT)
                if r.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                    return "抱歉，拒绝生成。"
            except Exception:
                pass
            if search_risks(prompt):
                return "抱歉，拒绝生成。"
            return f"正常回答：{prompt}"
        return evaluate_refusal_rate(attack, normal, _responder)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/aigc/label")
async def aigc_label_config():
    """AIGC内容标识配置（显式+隐式+元数据）"""
    try:
        from security.aigc_labeling import get_aigc_config, build_aigc_metadata
        cfg = get_aigc_config()
        cfg["sample_metadata"] = build_aigc_metadata()
        return cfg
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================================
# T6 持续优化闭环：反馈标注 / 自动调优 / 版本管理 / 威胁情报 / 聚类 / 回归
# ============================================================================

@app.post("/api/optimization/feedback")
async def optimization_feedback(request: dict):
    """检测结果人工标注（确认/驳回）"""
    try:
        from security.optimization_loop import get_optimization_loop
        return get_optimization_loop().record_feedback(
            sample_text=request.get("sample_text", ""),
            predicted_label=request.get("predicted_label", "benign"),
            predicted_risk=request.get("predicted_risk", "none"),
            annotator_label=request.get("annotator_label", "benign"),
            annotator_comment=request.get("comment", ""),
            source=request.get("source", "manual"),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/optimization/feedback")
async def optimization_feedback_list(limit: int = 100):
    try:
        from security.optimization_loop import get_optimization_loop
        return {"items": get_optimization_loop().list_feedback(limit)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/optimization/feedback/stats")
async def optimization_feedback_stats():
    """误报/漏报统计"""
    try:
        from security.optimization_loop import get_optimization_loop
        return get_optimization_loop().feedback_stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/optimization/tune")
async def optimization_tune(request: dict):
    """基于标注数据的规则自动调优"""
    try:
        from security.optimization_loop import get_optimization_loop
        return get_optimization_loop().auto_tune_from_feedback(
            auto_apply=request.get("auto_apply", True),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/optimization/versions")
async def optimization_versions(limit: int = 100):
    """关键词/模式库版本列表"""
    try:
        from security.optimization_loop import get_optimization_loop
        return {"versions": get_optimization_loop().list_versions(limit)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/optimization/versions/{version_id}/apply")
async def optimization_version_apply(version_id: str):
    """应用版本（写入动态检测库）"""
    try:
        from security.optimization_loop import get_optimization_loop
        return get_optimization_loop().apply_version(version_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/optimization/attack_samples")
async def optimization_attack_samples_add(request: dict):
    """攻击样例库动态扩充"""
    try:
        from security.optimization_loop import get_optimization_loop
        return get_optimization_loop().record_attack_sample(
            content=request.get("content", ""),
            attack_type=request.get("attack_type", "unknown"),
            source=request.get("source", "manual"),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/optimization/attack_samples")
async def optimization_attack_samples_list(limit: int = 200):
    try:
        from security.optimization_loop import get_optimization_loop
        return {"items": get_optimization_loop().list_attack_samples(limit)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/optimization/cluster")
async def optimization_cluster(request: dict):
    """新型攻击模式自动聚类"""
    try:
        from security.optimization_loop import get_optimization_loop
        return get_optimization_loop().cluster_attack_patterns(
            min_cluster=request.get("min_cluster", 2),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/optimization/threat_intel")
async def optimization_threat_intel(request: dict):
    """威胁情报订阅接口（外部IOC导入）"""
    try:
        from security.optimization_loop import get_optimization_loop
        iocs = request.get("iocs") or []
        return get_optimization_loop().import_threat_iocs(
            iocs=iocs, source=request.get("source", "external"),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/optimization/threat_intel")
async def optimization_threat_intel_list(limit: int = 200):
    try:
        from security.optimization_loop import get_optimization_loop
        return {"items": get_optimization_loop().list_threat_iocs(limit)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/optimization/regression")
async def optimization_regression(request: dict):
    """规则更新后自动回归测试"""
    try:
        from security.optimization_loop import get_optimization_loop
        samples = request.get("samples")
        return get_optimization_loop().run_regression(
            samples=samples, note=request.get("note", "api"),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/optimization/trend")
async def optimization_trend(limit: int = 30):
    """检测效果趋势可视化数据"""
    try:
        from security.optimization_loop import get_optimization_loop
        return get_optimization_loop().get_trend(limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/security/eval_calc", response_model=EvaluationMetrics)
async def calculate_evaluation_metrics(request: dict):
    try:
        attack_test_samples = request.get("attack_test_samples", [])
        attack_results = [DetectionResult(**r) for r in request.get("attack_results", [])]
        tool_test_samples = request.get("tool_test_samples", [])
        tool_results = [ToolRiskResult(**r) for r in request.get("tool_results", [])]
        plugin_test_samples = request.get("plugin_test_samples", [])
        plugin_results = [PluginScanResult(**r) for r in request.get("plugin_results", [])]
        
        metrics = metrics_calculator.calculate_all_metrics(
            attack_test_samples, attack_results,
            tool_test_samples, tool_results,
            plugin_test_samples, plugin_results
        )
        
        return metrics
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/agent/run")
async def run_agent(req: Request, user_input: str, input_source: str = "user_input"):
    try:
        # 审计到人：将发起调用的登录账号+部门透传给 agent，贯穿到其审计/审批
        identity = current_identity(req.headers.get("X-Auth-Token")) if req else {}
        result = gov_agent.run(user_input, input_source, user=identity or None)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/agent/chat")
async def chat_with_history(req: Request, user_input: str, session_id: Optional[str] = None, input_source: str = "user_input"):
    try:
        # 审计到人：将发起调用的登录账号+部门透传给 agent，贯穿到其审计/审批
        identity = current_identity(req.headers.get("X-Auth-Token")) if req else {}
        result = gov_agent.run(user_input, input_source, session_id, user=identity or None)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/agent/file_upload")
async def upload_file(http_req: Request, request: FileUploadRequest):
    try:
        session_id = request.session_id
        if not session_id:
            session_id = gov_agent.conversation_manager.create_session()
        # 审计到人：解析登录账号透传给 agent 处理
        identity = current_identity(http_req.headers.get("X-Auth-Token")) if http_req else {}
        result = gov_agent.process_file_message(session_id, request.file_data, request.file_type,
                                                request.filename, user=identity or None)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/agent/history")
async def get_conversation_history(session_id: str):
    try:
        result = gov_agent.get_conversation_history(session_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/agent/new_session")
async def create_new_session():
    try:
        result = gov_agent.create_new_session()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/agent/clear_session")
async def clear_conversation(session_id: str):
    try:
        result = gov_agent.clear_conversation(session_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/agent/delete_session")
async def delete_conversation(session_id: str):
    """删除整个历史会话（会话记录及全部消息）"""
    try:
        result = gov_agent.delete_session(session_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/agent/rename_session")
async def rename_session(session_id: str, title: str):
    """重命名历史会话（title 传空字符串恢复为未命名）"""
    try:
        if len(title) > 100:
            raise HTTPException(status_code=400, detail="会话标题过长（上限 100 字符）")
        ok = gov_agent.conversation_manager.rename_session(session_id, title)
        if not ok:
            raise HTTPException(status_code=404, detail="会话不存在")
        return {"success": True, "session_id": session_id, "title": title.strip() or None}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/agent/recall_messages")
async def recall_messages(session_id: str, message_id: int):
    """撤回/编辑消息：删除指定消息及之后的所有消息"""
    try:
        from storage import get_storage
        storage = get_storage()
        deleted = storage.truncate_messages_from(session_id, message_id)
        history = storage.get_history(session_id)
        return {
            "success": True,
            "deleted_count": deleted,
            "remaining_messages": len(history),
            "messages": history
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/agent/sessions")
async def list_sessions():
    try:
        result = gov_agent.list_sessions()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION
    }


# ==================== 账号与角色（登录身份 / 角色导航 / 审计到人） ====================

@app.post("/api/auth/login")
async def auth_login(request: dict):
    """登录：校验账号口令（含连续失败锁定），返回访问令牌与用户身份"""
    username = str(request.get("username", "")).strip()
    password = str(request.get("password", ""))
    auth_result = authenticate(username, password)
    if not auth_result.get("ok"):
        # 审计：登录失败（不记录口令），便于安全监控暴力破解
        try:
            audit_logger.create_log(
                user_id=username or "unknown", user_role="guest", agent_id="auth",
                action_type="auth_login_failed",
                action_details={"reason": auth_result.get("reason"),
                                "locked": auth_result.get("locked", False)},
                risk_level=RiskLevel.LOW, is_blocked=True,
                blocking_reason="登录失败或账号锁定",
            )
        except Exception:
            pass
        if auth_result.get("locked"):
            raise HTTPException(
                status_code=423,
                detail=f"账号已锁定，请 {auth_result.get('remain', 0)} 秒后重试",
            )
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    from storage import get_storage
    # 二步验证：账号启用 MFA 时，先返回临时票据，输入 TOTP 通过后再签发访问令牌
    try:
        _mfa = get_storage().get_user_mfa(username)
    except Exception:
        _mfa = {"mfa_enabled": False}
    if _mfa.get("mfa_enabled"):
        return {
            "success": True,
            "mfa_required": True,
            "mfa_ticket": create_mfa_ticket(username),
            "username": username,
        }
    row = get_storage().get_user(username) or {}
    token = create_token(username)
    audit_logger.create_log(
        user_id=username, user_role=row.get("role", "user"), agent_id="auth",
        action_type="auth_login",
        action_details={"display_name": row.get("display_name", username)},
        risk_level=RiskLevel.NONE,
        is_blocked=False,
    )
    return {
        "success": True,
        "token": token,
        "user": {
            "username": username,
            "display_name": row.get("display_name", username),
            "role": row.get("role", "user"),
            "department": row.get("department", ""),
            "position": row.get("position", ""),
        },
    }


@app.post("/api/auth/logout")
async def auth_logout(request: Request):
    token = request.headers.get("X-Auth-Token")
    if token:
        revoke_token(token)
    return {"success": True}


@app.get("/api/auth/me")
async def auth_me(request: Request):
    """返回当前登录身份；未登录 user=null，同时附演示账号列表供登录界面展示"""
    token = request.headers.get("X-Auth-Token")
    user = get_user_by_token(token)
    return {"user": user, "demo_accounts": list_demo_accounts()}


@app.get("/api/auth/permissions")
async def auth_permissions(request: Request):
    """返回当前登录主体的权限决策结果（单一事实来源）。

    供前端驱动：可见模块（导航收敛）、权限点、数据可见范围（全平台/本部门/仅本人）、
    审批能力。前端不再各自硬编码角色→菜单，避免与后端漂移。
    """
    identity = current_identity(request.headers.get("X-Auth-Token"))
    return {
        "success": True,
        "identity": identity or None,
        **permission_engine.describe(identity),
    }


# ==================== MFA（TOTP 二步验证）与认证增强 ====================

@app.post("/api/auth/mfa/verify")
async def auth_mfa_verify(request: dict):
    """二步验证：校验 MFA 临时票据 + TOTP 验证码 → 签发访问令牌。"""
    ticket = str(request.get("ticket", ""))
    code = str(request.get("code", ""))
    username = verify_mfa_ticket(ticket)
    if not username:
        raise HTTPException(status_code=401, detail="验证票据无效或已过期，请重新登录")
    from auth import verify_totp, mfa_status as _mfa_status
    info = _mfa_status(username)
    if not info.get("mfa_enabled"):
        raise HTTPException(status_code=400, detail="该账号未启用 MFA")
    from storage import get_storage
    secret = get_storage().get_user_mfa(username).get("totp_secret", "")
    if not verify_totp(secret, code):
        audit_logger.create_log(user_id=username, user_role="user", agent_id="auth",
                                action_type="auth_mfa_failed", action_details={},
                                risk_level=RiskLevel.LOW, is_blocked=True, blocking_reason="MFA 验证失败")
        raise HTTPException(status_code=401, detail="验证码不正确")
    row = get_storage().get_user(username) or {}
    token = create_token(username)
    audit_logger.create_log(user_id=username, user_role=row.get("role", "user"), agent_id="auth",
                            action_type="auth_login", action_details={"mfa": True},
                            risk_level=RiskLevel.NONE, is_blocked=False)
    return {
        "success": True,
        "token": token,
        "user": {
            "username": username,
            "display_name": row.get("display_name", username),
            "role": row.get("role", "user"),
            "department": row.get("department", ""),
            "position": row.get("position", ""),
        },
    }


@app.get("/api/auth/mfa/status")
async def auth_mfa_status(request: Request):
    """查询当前账号 MFA 状态与是否可启用。"""
    identity = current_identity(request.headers.get("X-Auth-Token"))
    if not identity:
        raise HTTPException(status_code=401, detail="未登录")
    return {"success": True, **mfa_status(identity["username"]), "config": mfa_config()}


@app.post("/api/auth/mfa/enroll")
async def auth_mfa_enroll(request: Request):
    """开始绑定 MFA：生成 TOTP 密钥与 otpauth URI（需扫描后 confirm）。"""
    identity = current_identity(request.headers.get("X-Auth-Token"))
    if not identity:
        raise HTTPException(status_code=401, detail="未登录")
    if not mfa_config().get("enabled"):
        return {"success": False, "message": "系统未启用 MFA"}
    return {"success": True, **begin_mfa_enroll(identity["username"])}


@app.post("/api/auth/mfa/confirm")
async def auth_mfa_confirm(request: Request):
    """确认绑定：校验一次 TOTP 验证码后正式启用 MFA。"""
    identity = current_identity(request.headers.get("X-Auth-Token"))
    if not identity:
        raise HTTPException(status_code=401, detail="未登录")
    body = await _body(request)
    result = confirm_mfa_enroll(identity["username"], str(body.get("code", "")))
    if result.get("ok"):
        audit_logger.create_log(user_id=identity["username"], user_role=identity.get("role", "user"),
                                agent_id="auth", action_type="auth_mfa_enabled", action_details={},
                                risk_level=RiskLevel.NONE, is_blocked=False)
    return {"success": bool(result.get("ok")), **result}


@app.post("/api/auth/mfa/disable")
async def auth_mfa_disable(request: Request):
    """停用当前账号 MFA。"""
    identity = current_identity(request.headers.get("X-Auth-Token"))
    if not identity:
        raise HTTPException(status_code=401, detail="未登录")
    result = disable_mfa(identity["username"])
    audit_logger.create_log(user_id=identity["username"], user_role=identity.get("role", "user"),
                            agent_id="auth", action_type="auth_mfa_disabled", action_details={},
                            risk_level=RiskLevel.LOW, is_blocked=False)
    return {"success": True, **result}


@app.post("/api/auth/refresh")
async def auth_refresh(request: Request):
    """续期：当前访问令牌有效则签发新令牌（用于临近过期的平滑续签）。"""
    token = request.headers.get("X-Auth-Token")
    identity = current_identity(token)
    if not identity:
        raise HTTPException(status_code=401, detail="登录已失效，请重新登录")
    revoke_token(token)  # 旧令牌作废，避免长期可用
    return {"success": True, "token": create_token(identity["username"]), "user": identity}


@app.post("/api/auth/password")
async def auth_change_password(request: Request):
    """自助修改口令：校验原口令 + 强度策略。"""
    identity = current_identity(request.headers.get("X-Auth-Token"))
    if not identity:
        raise HTTPException(status_code=401, detail="未登录")
    body = await _body(request)
    old_pw = str(body.get("old_password", ""))
    new_pw = str(body.get("new_password", ""))
    username = identity["username"]
    if not verify_password(username, old_pw):
        raise HTTPException(status_code=400, detail="原口令不正确")
    ok, reason = check_password_policy(new_pw)
    if not ok:
        raise HTTPException(status_code=400, detail=reason)
    from storage import get_storage
    pw_hash, salt = _pw_fields(new_pw)
    get_storage().update_user_password(username, pw_hash, salt)
    audit_logger.create_log(user_id=username, user_role=identity.get("role", "user"), agent_id="auth",
                            action_type="auth_password_changed", action_details={},
                            risk_level=RiskLevel.LOW, is_blocked=False)
    return {"success": True, "message": "口令已更新，请使用新口令登录"}


@app.get("/api/auth/sso/config")
async def auth_sso_config():
    """SSO 是否启用及受信网关头名（不泄露敏感信息）。"""
    return {"success": True, "sso_enabled": sso_enabled(), "header": sso_header_name()}


@app.post("/api/auth/sso")
async def auth_sso_login(request: Request):
    """SSO 免密登录：由受信网关注入的头映射到本地账号并签发令牌。"""
    if not sso_enabled():
        raise HTTPException(status_code=404, detail="未启用 SSO")
    identity = resolve_sso_identity(request.headers)
    if not identity:
        raise HTTPException(status_code=401, detail="SSO 身份无效或账号不存在/已停用")
    token = create_token(identity["username"])
    audit_logger.create_log(user_id=identity["username"], user_role=identity.get("role", "user"),
                            agent_id="auth", action_type="auth_login",
                            action_details={"sso": True}, risk_level=RiskLevel.NONE, is_blocked=False)
    return {"success": True, "token": token, "user": identity}


# ==================== 用户与组织管理 API（仅系统管理员 admin） ====================
_ROLES = ("admin", "operator", "auditor", "manager", "user")


def _admin_guard(request: Request):
    """返回当前具备后台管理权限的身份，无权限返回 None（走统一权限引擎）"""
    identity = current_identity(request.headers.get("X-Auth-Token"))
    if identity and permission_engine.has_permission(identity.get("role"), "admin.manage"):
        return identity
    return None


def _login_guard(request: Request):
    """返回当前登录身份（任意角色）；未登录返回 None。

    用于系统配置类端点，避免匿名访客读写/破坏系统级配置与数据。
    """
    return current_identity(request.headers.get("X-Auth-Token")) or None


def _pw_fields(password: str):
    import hashlib, secrets
    salt = secrets.token_bytes(16)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000).hex()
    return pw_hash, salt.hex()


async def _body(request: Request) -> dict:
    try:
        if request.headers.get("content-type", "").startswith("application/json"):
            return await request.json()
    except Exception:
        pass
    return {}


@app.get("/api/admin/users")
async def admin_list_users(request: Request):
    """用户列表（仅 admin）"""
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份", "users": []}
    from storage import get_storage
    return {"success": True, "users": get_storage().list_users()}


@app.post("/api/admin/users")
async def admin_create_user(request: Request):
    """新建用户（仅 admin）：{username,password,display_name,role,department,position}"""
    from storage import get_storage
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    body = await _body(request)
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", ""))
    display_name = str(body.get("display_name", "")).strip() or username
    role = str(body.get("role", "")).strip()
    if not username:
        return {"success": False, "error": "用户名不能为空"}
    _ok_pw, _reason = check_password_policy(password)
    if not _ok_pw:
        return {"success": False, "error": _reason}
    if role not in _ROLES:
        return {"success": False, "error": f"角色必须为 {_ROLES}"}
    if get_storage().user_exists(username):
        return {"success": False, "error": f"账号 {username} 已存在"}
    pw_hash, salt = _pw_fields(password)
    get_storage().upsert_user(
        username, pw_hash, salt, display_name, role,
        str(body.get("department", "")).strip(), str(body.get("position", "")).strip(),
        "active", str(body.get("note", "")).strip(),
    )
    # 组织目录：自动补录部门
    dept = str(body.get("department", "")).strip()
    if dept and dept not in get_storage().list_departments():
        get_storage().add_department(dept)
    return {"success": True, "message": f"已创建账号 {username}"}


@app.put("/api/admin/users/{username}")
async def admin_update_user(request: Request, username: str):
    """更新用户资料/角色/状态（仅 admin，禁止改低 admin 自身角色）"""
    from storage import get_storage
    actor = _admin_guard(request)
    if not actor:
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    if not get_storage().user_exists(username):
        return {"success": False, "error": f"账号 {username} 不存在"}
    body = await _body(request)
    # 保护：当前登录管理员不得把自己改成任何非 admin 角色或停用——否则会立即失去后台权限而自我锁死
    # （此前只挡了 operator/auditor/user，遗漏 manager，可被降级为部门负责人后无法自行恢复）
    if username == actor["username"] and (body.get("role") not in (None, "admin") or body.get("status") == "disabled"):
        return {"success": False, "error": "不能降级或停用当前登录的管理员账号"}
    if body.get("role") is not None and body.get("role") not in _ROLES:
        return {"success": False, "error": f"角色必须为 {_ROLES}"}
    get_storage().update_user_profile(
        username,
        display_name=body.get("display_name"),
        role=body.get("role"),
        department=body.get("department"),
        position=body.get("position"),
        status=body.get("status"),
        note=body.get("note"),
    )
    return {"success": True, "message": f"已更新账号 {username}"}


@app.post("/api/admin/users/{username}/reset_password")
async def admin_reset_password(request: Request, username: str):
    """重置用户密码（仅 admin）：{password}"""
    from storage import get_storage
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    body = await _body(request)
    password = str(body.get("password", ""))
    _ok_pw, _reason = check_password_policy(password)
    if not _ok_pw:
        return {"success": False, "error": _reason}
    if not get_storage().user_exists(username):
        return {"success": False, "error": f"账号 {username} 不存在"}
    pw_hash, salt = _pw_fields(password)
    get_storage().update_user_password(username, pw_hash, salt)
    return {"success": True, "message": f"已重置账号 {username} 的密码"}


@app.delete("/api/admin/users/{username}")
async def admin_delete_user(request: Request, username: str):
    """删除用户（仅 admin）；系统管理员自身不可删"""
    from storage import get_storage
    actor = _admin_guard(request)
    if not actor:
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    if username == actor["username"]:
        return {"success": False, "error": "不能删除当前登录的管理员账号"}
    if username in ("admin", "operator", "auditor", "user"):
        return {"success": False, "error": "内置演示账号建议用「停用」而非删除，避免破坏登录引导"}
    if not get_storage().user_exists(username):
        return {"success": False, "error": f"账号 {username} 不存在"}
    get_storage().delete_user(username)
    return {"success": True, "message": f"已删除账号 {username}"}


@app.get("/api/admin/stats")
async def admin_stats(request: Request):
    """后台统计：用户数/角色分布/部门（仅 admin）"""
    from storage import get_storage
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    users = get_storage().list_users()
    by_role = {}
    by_dept = {}
    for u in users:
        by_role[u["role"]] = by_role.get(u["role"], 0) + 1
        d = u.get("department") or "未分配"
        by_dept[d] = by_dept.get(d, 0) + 1
    return {
        "success": True,
        "stats": {
            "total": len(users),
            "active": sum(1 for u in users if u.get("status") == "active"),
            "disabled": sum(1 for u in users if u.get("status") != "active"),
            "by_role": by_role,
            "by_department": by_dept,
        },
    }


@app.get("/api/admin/departments")
async def admin_list_departments(request: Request):
    """部门目录（仅 admin）"""
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份", "departments": []}
    from storage import get_storage
    return {"success": True, "departments": get_storage().list_departments()}


@app.post("/api/admin/departments")
async def admin_add_department(request: Request):
    """新增部门（仅 admin）：{name}"""
    from storage import get_storage
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    body = await _body(request)
    name = str(body.get("name", "")).strip()
    if not name:
        return {"success": False, "error": "部门名称不能为空"}
    ok = get_storage().add_department(name)
    return {"success": ok, "message": ("已新增部门" if ok else "部门已存在")}


# ==================== 审批管理 API ====================

@app.post("/api/security/approval/approve/{request_id}")
async def approve_request(request: Request, request_id: str, approver_comment: str = ""):
    """审批通过指定的请求

    异步审批流（B-2/B-5 联动）：批准时立即授予会话能力令牌 + 解锁会话工具，
    用户重试原请求时自动放行，无需重复审批。
    审计到人：操作人取当前登录账号；未登录按本地管理面板处理（访客演示模式）。
    """
    try:
        # 注意参数顺序：approve_request(request_id, approver_id, approver_role, comments)
        # 历史缺陷曾把 "admin" 传成 approver_id 而 approver_role 为空 → 角色层级不足
        # 静默拒绝（DB 状态不更新但端点仍返回成功）
        identity = current_identity(request.headers.get("X-Auth-Token"))
        approver_id = identity.get("username") or ""
        role = identity.get("role")
        # 统一权限引擎判定审批能力（安全优先：未认证 / 无审批权限一律拒绝）
        approver_role = permission_engine.approver_role_for(role, authenticated=bool(identity))
        if not approver_role:
            return {
                "success": False,
                "message": "当前账号无审批权限（需系统管理员 / 安全运维 / 部门负责人）",
            }
        result = approval_engine.approve_request(
            request_id,
            approver_id=approver_id,
            approver_role=approver_role,
            comments=approver_comment,
        )
        if result.status not in ("approved", "auto_approved"):
            return {
                "success": False,
                "message": f"审批未通过: {result.status}"
                           + (f"（{result.comments}）" if result.comments else ""),
            }

        # B-2/B-5：从审批单提取会话与工具信息 → 授予能力 + 会话级解锁
        grant_info = {"session_id": None, "tool_name": None}
        try:
            record = approval_engine.get_request(request_id)
            if record is not None:
                details = dict(record.action_details or {})
                # 守卫类审批单：tool_name 在 action_details 顶层；工具类在 _tool_name
                sid = details.get("_session_id")
                tname = details.get("_tool_name") or details.get("tool_name")
                # action_type 形如 tool_call_export_data / guard_export_data
                if not tname and record.action_type:
                    for prefix in ("tool_call_", "guard_"):
                        if record.action_type.startswith(prefix):
                            tname = record.action_type[len(prefix):]
                            break
                if sid and tname:
                    gov_agent.security_layer.capability_tokens.grant_for_tool(sid, tname)
                    gov_agent.security_layer.record_session_unlock(sid, tname)
                    grant_info = {"session_id": sid, "tool_name": tname}
                    # 联动清理：同一请求可能产生两张审批单（tool_risk + guard 各一张），
                    # 批准其一即解锁会话，另一张若继续 pending 会成为垃圾数据 → 一并标记
                    try:
                        for p in approval_engine.list_pending():
                            pdet = dict(p.action_details or {})
                            psid = pdet.get("_session_id")
                            ptool = pdet.get("_tool_name") or pdet.get("tool_name")
                            if psid == sid and ptool == tname and p.request_id != request_id:
                                approval_engine.approve_request(
                                    p.request_id, "system", "super_admin",
                                    "关联审批单已批准（同会话同工具联动）"
                                )
                    except Exception:
                        pass
        except Exception as grant_err:
            # 授予失败不阻断审批本身，仅记录（重试路径会在 check_approval 兜底授予）
            audit_logger.create_log(
                user_id=approver_id, user_role=approver_role, agent_id="security_panel",
                action_type="approval_grant_warning",
                action_details={"request_id": request_id, "error": str(grant_err)},
                risk_level=RiskLevel.LOW,
                is_blocked=False,
            )

        audit_logger.create_log(
            user_id=approver_id, user_role=approver_role, agent_id="security_panel",
            action_type="approval_approved",
            action_details={"request_id": request_id, "comment": approver_comment, **grant_info},
            risk_level=RiskLevel.NONE,
            is_blocked=False,
        )
        # WebSocket 推送：审批通过
        import asyncio
        asyncio.create_task(push_approval_update(
            request_id=request_id, action="approved",
            detail={"comment": approver_comment, **grant_info}
        ))
        return {
            "success": True,
            "message": f"请求 {request_id} 已审批通过",
            **grant_info,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/security/approval/reject/{request_id}")
async def reject_request(request: Request, request_id: str, reason: str = ""):
    """驳回指定的请求（记录当前登录操作人，审计到人）"""
    try:
        identity = current_identity(request.headers.get("X-Auth-Token"))
        approver_id = identity.get("username") or ""
        role = identity.get("role")
        # 统一权限引擎判定审批能力（安全优先：未认证 / 无审批权限一律拒绝）
        approver_role = permission_engine.approver_role_for(role, authenticated=bool(identity))
        if not approver_role:
            return {
                "success": False,
                "message": "当前账号无审批权限（需系统管理员 / 安全运维 / 部门负责人）",
            }
        rejected = approval_engine.reject_request(request_id, approver_id, reason)
        if rejected.status not in ("rejected", "approved", "auto_approved"):
            return {
                "success": False,
                "message": f"审批请求 {request_id} 不存在或已处理"
            }
        audit_logger.create_log(
            user_id=approver_id, user_role=approver_role, agent_id="security_panel",
            action_type="approval_rejected",
            action_details={"request_id": request_id, "reason": reason},
            risk_level=RiskLevel.NONE,
            is_blocked=False,
        )
        # WebSocket 推送：审批驳回
        import asyncio
        asyncio.create_task(push_approval_update(
            request_id=request_id, action="rejected",
            detail={"reason": reason}
        ))
        return {"success": True, "message": f"请求 {request_id} 已驳回"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/security/approval/status/{request_id}")
async def check_approval_status(request_id: str):
    """查询特定审批请求的状态"""
    try:
        req = approval_engine.get_request(request_id)
        if not req:
            raise HTTPException(status_code=404, detail="审批请求不存在")
        return req.dict()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 知识库投毒检测 API ====================

@app.post("/api/security/kb_poisoning/detect_pdf")
async def detect_kb_poisoning_pdf(request: FileDetectionRequest):
    """检测 PDF 文件中的知识库投毒（白色字体/隐藏文本/RAG指令注入）"""
    try:
        result = kb_poisoning_detector.detect_pdf(request.file_data, request.filename)

        # 记录审计日志
        audit_logger.create_log(
            user_id="anonymous", user_role="user", agent_id="security_panel",
            action_type="kb_poisoning_detection",
            action_details={
                "filename": request.filename,
                "file_type": request.file_type,
            },
            risk_level=result.risk_level,
            is_blocked=policy_manager.should_block(result.risk_level),
        )

        return {
            "success": True,
            "file_name": result.file_name,
            "risk_level": result.risk_level.value,
            "attack_type": result.attack_type.value if result.attack_type else None,
            "confidence": result.confidence,
            "evidence": result.evidence,
            "hidden_texts": [
                {
                    "text": ht.text,
                    "location": ht.location,
                    "font_size": ht.font_size,
                    "font_color": ht.font_color,
                    "detection_method": ht.detection_method,
                }
                for ht in result.hidden_texts
            ],
            "hidden_count": len(result.hidden_texts),
            "total_hidden_chars": result.total_hidden_chars,
            "total_visible_chars": result.total_visible_chars,
            "summary": result.summary,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/security/kb_poisoning/detect_text")
async def detect_kb_poisoning_text(text: str, source: str = "knowledge_retrieval"):
    """检测知识库检索文本中的投毒（用于Agent检索后的二次检测）"""
    try:
        result = kb_poisoning_detector.detect_text(text)

        return {
            "success": True,
            "risk_level": result.risk_level.value,
            "attack_type": result.attack_type.value if result.attack_type else None,
            "confidence": result.confidence,
            "evidence": result.evidence,
            "total_chars": result.total_visible_chars,
            "summary": result.summary,
            "source": source,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== Session 级风险累积 API ====================

@app.get("/api/security/session_risk/{session_id}")
async def get_session_risk(session_id: str):
    """获取指定 session 的风险累积画像"""
    try:
        profile = session_risk_accumulator.get_session_summary(session_id)
        return {"success": True, "profile": profile}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/security/session_risk")
async def list_all_session_risks():
    """获取所有活跃 session 的风险摘要"""
    try:
        sessions = session_risk_accumulator.get_all_active_sessions()
        return {"success": True, "sessions": sessions, "count": len(sessions)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/security/session_risk/clear/{session_id}")
async def clear_session_risk(session_id: str):
    """清除 session 风险数据"""
    try:
        session_risk_accumulator.clear_session(session_id)
        return {"success": True, "message": f"Session {session_id} 风险数据已清除"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 跨来源关联分析 API ====================

@app.get("/api/security/cross_source/summary/{session_id}")
async def get_cross_source_summary(session_id: str):
    """获取某个 Session 的跨来源关联分析摘要"""
    try:
        summary = cross_source_correlator.get_session_summary(session_id)
        return {"success": True, "data": summary}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/security/cross_source/clear/{session_id}")
async def clear_cross_source(session_id: str):
    """清除某个 Session 的跨来源关联数据"""
    try:
        cross_source_correlator.clear_session(session_id)
        return {"success": True, "message": f"Session {session_id} 关联数据已清除"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 对抗样本 Bypass 测试 API ====================

@app.post("/api/security/bypass_test")
async def run_bypass_test(request: dict):
    """
    对抗样本 bypass 测试

    请求体:
    {
        "text": "rm -rf /",
        "source": "user_input",
        "strategy": "all"  // fullwidth|homoglyph|zerowidth|space|case|encoding|delimiter|all
    }
    """
    try:
        text = request.get("text", "")
        source = request.get("source", "user_input")
        strategy = request.get("strategy", None)

        if not text:
            raise HTTPException(status_code=400, detail="请提供测试文本")

        # 支持 strategy="all" → None（所有策略）
        if strategy == "all":
            strategy = None

        result = bypass_tester.test_sample(text, source, strategy)

        # 记录审计日志
        audit_logger.create_log(
            user_id="anonymous", user_role="user", agent_id="security_panel",
            action_type="bypass_test",
            action_details={
                "original_text": text[:100],
                "strategy": strategy or "all",
                "bypass_rate": result.bypass_rate,
            },
            risk_level=RiskLevel.HIGH if result.bypass_rate > 0.5 else RiskLevel.LOW,
            is_blocked=False,
        )

        return {
            "success": True,
            "original_text": result.original_text,
            "original_risk": result.original_risk,
            "original_confidence": result.original_confidence,
            "bypass_rate": result.bypass_rate,
            "resistance_score": result.resistance_score,
            "total_variants": len(result.variants),
            "bypassed_variants": sum(1 for v in result.variants if v.get("bypassed")),
            "variants": result.variants,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== PSSU 自适应攻击自评估 API（创新点5 接入） ====================

@app.post("/api/security/pssu/assess")
async def run_pssu_assess(request: dict):
    """
    方向A-7：PSSU 自适应攻击自评估（第 5 个创新点接入）

    用真实 input_detector 作为防御，跑 PSSU 自适应攻击（种子模板 + 变异），
    量化防御的真实突破率——暴露静态样本测试测不出的弱点。

    请求体:
    {
        "target_defense": "input_detector",   // 目标防御名称
        "max_iterations": 8,                   // 可选，进化迭代上限，默认 8
        "success_threshold": 0.8               // 可选，攻击成功阈值，默认 0.8
    }
    """
    try:
        from audit.pssu_attack import PSSURunner, AttackerType

        target_defense = request.get("target_defense", "input_detector")
        max_iterations = int(request.get("max_iterations", 8))
        success_threshold = float(request.get("success_threshold", 0.8))
        # 可选种子载荷：以用户当前测试文本为起点做自适应进化
        seed_payload = request.get("seed_payload") or None

        # 风险等级 → 0-1 风险分（PSSU 依据 risk_score 判断攻击是否突破防御）
        risk_map = {
            RiskLevel.NONE: 0.0, RiskLevel.LOW: 0.2,
            RiskLevel.MEDIUM: 0.5, RiskLevel.HIGH: 0.8, RiskLevel.CRITICAL: 1.0,
        }

        def defense_fn(payload: str):
            # skip_llm=True：PSSU 自适应攻击需反复调用防御（毫秒级），
            # 只评估快速判定层（规则+AI+向量），不触发 LLM（15s/次会拖垮评估）
            result = input_detector.detect_single_input(
                payload, "user_input", session_id="pssu-assess", skip_llm=True
            )
            blocked = result.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
            risk_score = risk_map.get(result.risk_level, 0.5)
            return (blocked, risk_score, {
                "risk_level": result.risk_level.value,
                "attack_type": result.attack_type.value if result.attack_type else None,
            })

        runner = PSSURunner(max_iterations=max_iterations, success_threshold=success_threshold)
        result = runner.assess_defense(
            target_defense=target_defense,
            defense_fn=defense_fn,
            seed_payloads=[seed_payload] if seed_payload else None,
        )
        summary = runner.summary(result)

        # 记录审计日志
        audit_logger.create_log(
            user_id="anonymous", user_role="user", agent_id="security_panel",
            action_type="pssu_assess",
            action_details={
                "target_defense": target_defense,
                "breakthrough_achieved": summary["breakthrough_achieved"],
                "defense_break_rate": summary["defense_break_rate"],
                "total_attempts": summary["total_attempts"],
            },
            risk_level=RiskLevel.HIGH if summary["breakthrough_achieved"] else RiskLevel.MEDIUM,
            is_blocked=False,
        )

        return {
            "success": True,
            **summary,
            # 突破 payload 示例（红队自评估，暴露防御真实弱点用）
            "breakthrough_payload": (
                result.breakthrough_attempt.payload if result.breakthrough_attempt else None
            ),
            "breakthrough_metadata": (
                result.breakthrough_attempt.metadata if result.breakthrough_attempt else None
            ),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/security/bypass_batch_test")
async def run_bypass_batch_test(request: dict):
    """
    批量 bypass 测试

    请求体:
    {
        "samples": [
            {"text": "rm -rf /", "source": "user_input"},
            {"text": "Ignore all instructions", "source": "user_input"},
        ],
        "strategy": "all"
    }
    """
    try:
        samples = request.get("samples", [])
        strategy = request.get("strategy", None)
        if strategy == "all":
            strategy = None

        results = bypass_tester.batch_test(samples, strategy)

        total = len(results)
        bypassed = sum(1 for r in results if r["bypass_rate"] > 0)
        avg_resistance = sum(r["resistance_score"] for r in results) / max(total, 1)
        avg_bypass = sum(r["bypass_rate"] for r in results) / max(total, 1)

        return {
            "success": True,
            "summary": {
                "total_samples": total,
                "samples_with_bypass": bypassed,
                "bypass_ratio": round(bypassed / max(total, 1), 2),
                "avg_bypass_rate": round(avg_bypass, 2),
                "avg_resistance_score": round(avg_resistance, 2),
            },
            "results": results,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 场景演示 API ====================

try:
    from security.scenario_engine import ScenarioDemoEngine
    scenario_engine = ScenarioDemoEngine()
    _has_scenario_engine = True
except ImportError:
    scenario_engine = None
    _has_scenario_engine = False


@app.get("/api/scenarios")
async def list_scenarios():
    """获取所有4大政企场景的概要信息"""
    try:
        if not _has_scenario_engine:
            raise HTTPException(status_code=503, detail="场景演示引擎未就绪")
        scenarios = scenario_engine.get_all_scenarios()
        return {"success": True, "scenarios": scenarios, "count": len(scenarios)}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scenarios/{scenario_id}")
async def get_scenario(scenario_id: str):
    """获取指定场景的完整定义（含所有步骤详情）"""
    try:
        if not _has_scenario_engine:
            raise HTTPException(status_code=503, detail="场景演示引擎未就绪")
        scenario = scenario_engine.get_scenario(scenario_id)
        if not scenario:
            raise HTTPException(status_code=404, detail=f"场景 '{scenario_id}' 不存在")
        return {"success": True, "scenario": scenario}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scenarios/{scenario_id}/run")
async def run_scenario(scenario_id: str):
    """运行指定场景的完整演示流程（含安全检测）"""
    try:
        if not _has_scenario_engine:
            raise HTTPException(status_code=503, detail="场景演示引擎未就绪")
        results, report = scenario_engine.run_scenario_with_builtin_detector(scenario_id)

        # 记录审计日志
        audit_logger.create_log(
            user_id="demo", user_role="user", agent_id="scenario_demo",
            action_type="scenario_run",
            action_details={
                "scenario_id": scenario_id,
                "total_steps": report.total_steps,
                "detection_rate": report.detection_rate,
                "false_positive_rate": report.false_positive_rate,
            },
            risk_level=RiskLevel.NONE,
            is_blocked=False,
        )

        return {
            "success": True,
            "scenario_id": scenario_id,
            "report": {
                "total_steps": report.total_steps,
                "attack_steps": report.attack_steps,
                "normal_steps": report.normal_steps,
                "blocked_count": report.blocked_count,
                "passed_count": report.passed_count,
                "detection_rate": report.detection_rate,
                "false_positive_rate": report.false_positive_rate,
                "summary": report.summary,
            },
            "results": [{
                "step_id": r.step_id,
                "user_message": r.user_message[:100],
                "is_attack": r.is_attack,
                "passed": r.passed,
                "expected_action": r.expected_security_action,
                "actual_action": r.actual_security_action,
                "risk_level": r.detection_result.risk_level.value if r.detection_result else None,
                "confidence": r.detection_result.confidence if r.detection_result else 0.0,
            } for r in results],
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scenarios/run_all")
async def run_all_scenarios():
    """运行全部4个场景并返回汇总报告"""
    try:
        if not _has_scenario_engine:
            raise HTTPException(status_code=503, detail="场景演示引擎未就绪")
        all_results = scenario_engine.run_all_scenarios()

        # all_results: Dict[scenario_id, ScenarioReport]
        scenarios = []
        total_steps = total_attacks = total_blocked = 0
        for sid, rep in all_results.items():
            scenarios.append({
                "scenario_id": sid,
                "scenario_name": rep.scenario_name,
                "total_steps": rep.total_steps,
                "attack_steps": rep.attack_steps,
                "normal_steps": rep.normal_steps,
                "blocked_count": rep.blocked_count,
                "passed_count": rep.passed_count,
                "detection_rate": rep.detection_rate,
                "false_positive_rate": rep.false_positive_rate,
                "summary": rep.summary,
            })
            total_steps += rep.total_steps
            total_attacks += rep.attack_steps
            total_blocked += rep.blocked_count

        overall_rate = (total_blocked / total_attacks) if total_attacks else 0.0
        return {
            "success": True,
            "overall": {
                "total_scenarios": len(all_results),
                "total_steps": total_steps,
                "total_attacks": total_attacks,
                "total_blocked": total_blocked,
                "overall_detection_rate": overall_rate,
            },
            "scenarios": scenarios,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 攻击复现与回放 API ====================

try:
    from audit.attack_replay import AttackReplayEngine
    replay_engine = AttackReplayEngine()
    _has_replay_engine = True
except ImportError:
    replay_engine = None
    _has_replay_engine = False


@app.post("/api/replay/record")
async def record_attack(request: dict):
    """记录一次攻击会话（用于后续复现）"""
    try:
        if not _has_replay_engine:
            raise HTTPException(status_code=503, detail="攻击复现引擎未就绪")

        # 先检测输入
        text = request.get("input_text", "")
        source = request.get("source", "user_input")
        detection_result = input_detector.detect_single_input(text, source)

        record_id = replay_engine.record(
            input_text=text,
            source=source,
            detection_result=detection_result,
            agent_response=request.get("agent_response", ""),
            tool_calls=request.get("tool_calls", []),
            session_id=request.get("session_id"),
            metadata=request.get("metadata", {}),
        )

        audit_logger.create_log(
            user_id="demo", user_role="user", agent_id="replay_engine",
            action_type="attack_recorded",
            action_details={"record_id": record_id, "text_preview": text[:100]},
            risk_level=detection_result.risk_level if hasattr(detection_result, 'risk_level') else RiskLevel.NONE,
            is_blocked=False,
        )

        return {
            "success": True,
            "record_id": record_id,
            "detection": {
                "risk_level": detection_result.risk_level.value if hasattr(detection_result, 'risk_level') else 'none',
                "attack_type": detection_result.attack_type.value if detection_result.attack_type else None,
                "confidence": detection_result.confidence,
            },
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/replay/{record_id}")
async def replay_attack(record_id: str):
    """复现指定攻击记录，对比原始检测与当前检测结果"""
    try:
        if not _has_replay_engine:
            raise HTTPException(status_code=503, detail="攻击复现引擎未就绪")

        result = replay_engine.replay(record_id)

        return {
            "success": True,
            "record_id": record_id,
            "status": result.status,
            "original_detection": {
                "risk_level": result.original_detection.get("risk_level") if isinstance(result.original_detection, dict) else getattr(result.original_detection, 'risk_level', None),
                "confidence": result.original_detection.get("confidence") if isinstance(result.original_detection, dict) else getattr(result.original_detection, 'confidence', 0),
            },
            "current_detection": {
                "risk_level": result.current_detection.get("risk_level") if isinstance(result.current_detection, dict) else getattr(result.current_detection, 'risk_level', None),
                "confidence": result.current_detection.get("confidence") if isinstance(result.current_detection, dict) else getattr(result.current_detection, 'confidence', 0),
            },
            "risk_level_changed": result.risk_level_changed,
            "input_text": result.input_text[:200],
            "source": result.source,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/replay/all")
async def replay_all_attacks():
    """批量复现所有已记录的攻击"""
    try:
        if not _has_replay_engine:
            raise HTTPException(status_code=503, detail="攻击复现引擎未就绪")

        results = replay_engine.replay_all()
        report = replay_engine.get_report(include_details=True)

        audit_logger.create_log(
            user_id="demo", user_role="user", agent_id="replay_engine",
            action_type="replay_all",
            action_details={"total": len(results)},
            risk_level=RiskLevel.NONE,
            is_blocked=False,
        )

        return {
            "success": True,
            "total": len(results),
            "report": report,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/replay/records")
async def list_replay_records():
    """获取所有已记录的攻击会话列表"""
    try:
        if not _has_replay_engine:
            raise HTTPException(status_code=503, detail="攻击复现引擎未就绪")

        records = replay_engine.get_all_records()
        return {
            "success": True,
            "records": records,
            "count": replay_engine.count(),
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 评测报告 API ====================

@app.get("/api/evaluation/report")
async def get_evaluation_report():
    """获取评测报告数据"""
    import json
    report_path = os.path.join(os.path.dirname(__file__), "audit", "evaluation_report.json")
    if os.path.exists(report_path):
        with open(report_path, "r", encoding="utf-8") as f:
            return json.load(f)
    raise HTTPException(status_code=404, detail="评测报告未生成，请先运行评测")


# ==================== 模型接入配置（P2-6：内网/离线 OpenAI 兼容端点） ====================

@app.get("/api/model/config")
async def get_model_config(request: Request):
    """模型接入配置查询（仅管理员：含接入端点与 Key 存在性，避免匿名探测）。"""
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    from llm_runtime import runtime_status
    return {"success": True, "config": runtime_status()}


@app.put("/api/model/config")
async def set_model_config(request: Request, payload: dict):
    """更新模型接入配置（仅管理员）：provider/api_key/base_url/model，热生效。"""
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    from llm_runtime import save_config, load_config
    provider = payload.get("provider")
    api_key = payload.get("api_key")          # None=不修改 / ''=清除覆盖 Key
    base_url = payload.get("base_url")
    model = payload.get("model")
    if provider not in (None, "zhipu", "openai"):
        raise HTTPException(status_code=400, detail="provider 仅支持 zhipu / openai")
    if base_url is not None and not base_url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="base_url 需以 http(s):// 开头")
    saved = save_config(provider or "zhipu", api_key, base_url or "", model or "")
    # 热生效：分类层 + 对话主链立即使用新接入参数（无需重启）
    input_detector.llm_classifier.apply_runtime(saved)
    gov_agent.refresh_llm(saved)
    from llm_runtime import runtime_status
    return {"success": True, "config": runtime_status()}


@app.post("/api/model/config/test")
async def test_model_config(request: Request, payload: dict):
    """模型连通性测试（仅管理员：会向指定 base_url 发起请求，须防匿名 SSRF）。"""
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    from llm_runtime import test_connection
    provider = str(payload.get("provider", "zhipu"))
    api_key = str(payload.get("api_key", ""))
    base_url = str(payload.get("base_url", ""))
    model = str(payload.get("model", ""))
    ok, detail = test_connection(provider, api_key, base_url, model)
    if not ok:
        raise HTTPException(status_code=400, detail=detail)
    return {"success": True, "detail": detail}


# ==================== 站内通知 & 外部通知渠道（P1-4） ====================

@app.get("/api/notifications")
async def list_notifications(request: Request, limit: int = 50):
    """站内通知列表（需登录，顶栏铃铛对全员可见）。"""
    if not _login_guard(request):
        raise HTTPException(status_code=401, detail="未登录")
    from storage import get_storage
    storage = get_storage()
    limit = max(1, min(limit, 200))
    return {
        "list": storage.list_notifications(limit=limit),
        "unread": storage.count_unread_notifications(),
    }


@app.post("/api/notifications/read")
async def notifications_mark_read(request: Request, payload: dict):
    """标记通知已读（需登录）。"""
    if not _login_guard(request):
        raise HTTPException(status_code=401, detail="未登录")
    from storage import get_storage
    storage = get_storage()
    nid = payload.get("id")
    storage.mark_notifications_read(int(nid) if nid is not None else None)
    return {"success": True, "unread": storage.count_unread_notifications()}


@app.post("/api/notifications/clear")
async def notifications_clear(request: Request):
    """清空通知（需登录）。"""
    if not _login_guard(request):
        raise HTTPException(status_code=401, detail="未登录")
    from storage import get_storage
    get_storage().clear_notifications()
    return {"success": True}


@app.get("/api/notifications/webhook")
async def get_webhook_config(request: Request):
    """外部通知渠道配置查询（仅管理员）。"""
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    from notify_webhook import load_webhook
    return {"success": True, "config": load_webhook()}


@app.put("/api/notifications/webhook")
async def set_webhook_config(request: Request, payload: dict):
    """配置外部通知渠道（仅管理员）。"""
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    from notify_webhook import save_webhook
    url = str(payload.get("url", "")).strip()
    enabled = bool(payload.get("enabled", False))
    if enabled and not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Webhook 地址需以 http(s):// 开头")
    save_webhook(url, enabled)
    return {"success": True, "config": {"url": url, "enabled": enabled}}


@app.post("/api/notifications/webhook/test")
async def test_webhook_config(request: Request, payload: dict):
    """Webhook 连通性测试（仅管理员：会向指定地址发起请求，须防匿名 SSRF）。"""
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    from notify_webhook import test_webhook as _test
    url = str(payload.get("url", "")).strip()
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="请输入有效的 http(s) 地址")
    ok, detail = _test(url)
    if not ok:
        raise HTTPException(status_code=400, detail=detail)
    return {"success": True, "detail": detail}


# ==================== 系统自检与数据维护（运维视角） ====================

# 服务进程启动时刻（模块加载时记录，用于 uptime 统计）
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
    """知识库索引状态（用于前端展示语料规模与就绪度）"""
    from knowledge.rag_engine import get_kb
    try:
        return {"success": True, "kb": get_kb().stats()}
    except Exception as e:  # noqa: BLE001
        return {"success": False, "error": str(e), "kb": {"ready": False}}


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