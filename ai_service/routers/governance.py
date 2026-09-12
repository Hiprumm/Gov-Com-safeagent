# -*- coding: utf-8 -*-
"""合规报告 / 应急联动 / 开放生态 / PIPL / 开放问答 路由模块 —— P1-1 按业务域拆分（原 main.py 同域路由收敛）

- URL 与行为与原 main.py 完全一致，仅注册载体由 app 改为 router，由 main.py include_router 装配；
- 共享单例（input_detector / audit_logger / gov_agent …）来自 app_deps.py，与 main 共用同一实例；
- 跨域共享守卫（_admin_guard / _login_guard / _assert_session_owner / _pw_fields / _body / _ROLES）
  收敛于 routers.auth.py。
"""
import sys
import os
import time
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import List, Dict, Any, Optional
from datetime import datetime

from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse

from models.schemas import (
    DetectionResult, BatchDetectionRequest, BatchDetectionResponse,
    FileDetectionRequest, FileUploadRequest,
    ToolCallRequest, ToolRiskResult,
    PluginScanRequest, PluginScanResult,
    AuditLog, EvaluationMetrics,
    ApprovalRequest, ApprovalResponse,
    RiskLevel,
)

from config import settings
from auth import (
    DEMO_USERS, verify_password, authenticate, create_token, revoke_token,
    get_user_by_token, current_identity, list_demo_accounts,
    check_password_policy, mfa_config, mfa_status, begin_mfa_enroll,
    confirm_mfa_enroll, disable_mfa, create_mfa_ticket, verify_mfa_ticket,
    sso_enabled, sso_header_name, resolve_sso_identity,
    sso_signature_required, sso_ip_restricted,
)
from app_deps import (
    input_detector, tool_evaluator, approval_engine, kb_poisoning_detector,
    cross_source_correlator, bypass_tester, plugin_scanner, mcp_scanner,
    skill_analyzer, combination_detector, operation_guard, audit_logger,
    metrics_calculator, gov_agent, policy_manager, permission_engine,
    _apply_policy_hot,
)

from audit.audit_logger import AuditLogger
from routers.auth import _admin_guard, _login_guard, _assert_session_owner, _pw_fields, _body, _ROLES


router = APIRouter()


# ============================================================================
# T5 合规标准对接：合规报告 / 关键词库 / AIGC标识 / 哈希链校验
# ============================================================================

@router.get("/api/compliance/keywords/stats")
async def compliance_keywords_stats():
    """关键词库规模统计（GB/T 45654-2025）"""
    try:
        from security.compliance_lexicon import get_lexicon_stats
        return get_lexicon_stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/compliance/content_safety")
async def compliance_content_safety(request: dict):
    """生成内容安全合格率评测（要求 ≥90%）"""
    try:
        from security.compliance_lexicon import evaluate_content_safety_batch
        samples = request.get("samples") or []
        return evaluate_content_safety_batch(samples)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/compliance/refusal_rate")
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



def _operator(req: Request) -> str:
    return (current_identity(req.headers.get("X-Auth-Token")) or {}).get("username") or "system"


@router.get("/api/emergency/status")
def emergency_status():
    from governance import get_emergency_center
    return {"success": True, **get_emergency_center().status()}


@router.post("/api/emergency/engage")
async def emergency_engage(req: Request, payload: dict):
    from governance import get_emergency_center
    return get_emergency_center().engage(str(payload.get("reason", "")), _operator(req))


@router.post("/api/emergency/disengage")
async def emergency_disengage(req: Request):
    from governance import get_emergency_center
    return get_emergency_center().disengage(_operator(req))


@router.post("/api/emergency/block_user")
async def emergency_block_user(req: Request, payload: dict):
    from governance import get_emergency_center
    return get_emergency_center().block_user(str(payload.get("username", "")).strip(),
                                             str(payload.get("reason", "")), _operator(req))


@router.post("/api/emergency/unblock_user")
async def emergency_unblock_user(req: Request, payload: dict):
    from governance import get_emergency_center
    return get_emergency_center().unblock_user(str(payload.get("username", "")).strip(), _operator(req))


@router.post("/api/emergency/block_ip")
async def emergency_block_ip(req: Request, payload: dict):
    from governance import get_emergency_center
    return get_emergency_center().block_ip(str(payload.get("ip", "")).strip(),
                                           str(payload.get("reason", "")), _operator(req))


@router.post("/api/emergency/unblock_ip")
async def emergency_unblock_ip(req: Request, payload: dict):
    from governance import get_emergency_center
    return get_emergency_center().unblock_ip(str(payload.get("ip", "")).strip(), _operator(req))


# ---- 开放生态管理（管理端）----
@router.get("/api/ecosystem/clients")
def ecosystem_clients():
    from governance import get_openapi_manager
    m = get_openapi_manager()
    return {"success": True, "clients": m.list_clients(), **m.stats()}


@router.post("/api/ecosystem/create")
async def ecosystem_create(req: Request, payload: dict):
    from governance import get_openapi_manager
    return get_openapi_manager().create(
        str(payload.get("name", "")).strip(), int(payload.get("rate_limit", 60)),
        int(payload.get("quota", 0)), str(payload.get("description", "")), _operator(req))


@router.post("/api/ecosystem/toggle")
async def ecosystem_toggle(req: Request, payload: dict):
    from governance import get_openapi_manager
    return get_openapi_manager().toggle(str(payload.get("client_id", "")).strip(),
                                        bool(payload.get("enabled")))


@router.post("/api/ecosystem/delete")
async def ecosystem_delete(req: Request, payload: dict):
    from governance import get_openapi_manager
    return get_openapi_manager().delete(str(payload.get("client_id", "")).strip())


@router.get("/api/ecosystem/logs")
def ecosystem_logs(limit: int = 100):
    from governance import get_openapi_manager
    return {"success": True, "logs": get_openapi_manager().log_calls(limit)}


# ---- 开放生态：受保护示例接口（演示 Token 鉴权 + 限流配额 + 调用留痕）----
@router.post("/api/open/chat")
async def open_chat(req: Request, payload: dict):
    from governance import get_openapi_manager, get_emergency_center
    m = get_openapi_manager()
    token = req.headers.get("X-Client-Token", "")
    ip = req.client.host if req.client else ""
    client, status = m.authenticate(token, "/api/open/chat", ip)
    if status != 200:
        reason = {401: "未授权：无效或缺失 X-Client-Token",
                  403: "调用方已被停用", 402: "配额已用尽", 429: "超出限流（60s 窗口）"}.get(status, "拒绝")
        m.storage.record_api_call(client["client_id"] if client else "-", client["name"] if client else "-",
                                  "/api/open/chat", status, ip)
        return {"success": False, "code": status, "error": reason}
    # 应急联动：对外开放入口同样受全局熔断约束
    reason = get_emergency_center().reason_blocked(username=client["client_id"], ip=ip)
    if reason:
        return {"success": False, "code": 403, "error": reason}
    question = str(payload.get("question", "")).strip()
    if not question:
        return {"success": False, "error": "缺少 question 参数"}
    return {"success": True, "client": {"client_id": client["client_id"], "name": client["name"]},
            "echo": f"已收到调用方「{client['name']}」的提问：{question}"}


# ---- PIPL 合规台账 ----
@router.get("/api/pipl/records")
def pipl_records():
    from governance import get_pipl_ledger
    mgr = get_pipl_ledger()
    return {"success": True, "records": mgr.records(), **mgr.stats()}


@router.post("/api/pipl/update")
async def pipl_update(req: Request, payload: dict):
    from governance import get_pipl_ledger
    ok = get_pipl_ledger().update(
        int(payload.get("id", 0)), str(payload.get("legal_basis", "")),
        str(payload.get("assessment", "pending")), _operator(req))
    return ok if ok else {"success": False, "error": "更新失败"}


@router.post("/api/pipl/scan")
async def pipl_scan(req: Request, payload: dict):
    from governance import get_pipl_ledger
    return get_pipl_ledger().scan_and_register(
        str(payload.get("text", "")), str(payload.get("session_id", "")),
        _operator(req), source=str(payload.get("source", "manual")))


@router.get("/api/pipl/export")
async def pipl_export(req: Request, fmt: str = "csv"):
    """导出合规台账（CSV/JSON，仅含脱敏值），并审计留痕到真实操作人。"""
    if fmt not in ("csv", "json"):
        raise HTTPException(status_code=400, detail="fmt 仅支持 csv/json")
    actor = _operator(req)
    actor = actor or (current_identity(req.headers.get("X-Auth-Token")) or {}).get("username", "")
    from governance import get_pipl_ledger
    from audit.audit_logger import AuditLogger
    result = get_pipl_ledger().export(fmt=fmt)
    # 审计联动：台账导出属敏感操作，须记录谁在何时导出了多少条
    try:
        AuditLogger().create_log(
            user_id=actor or "unknown", user_role="admin", agent_id="pipl",
            action_type="pipl_export", action_details={"fmt": fmt, "count": result["count"]},
            risk_level="medium", is_blocked=False,
        )
    except Exception as e:  # noqa: BLE001
        pass
    return result



# ---- 合规对标报告 ----
@router.get("/api/compliance/report")
def compliance_report(fmt: str = "json"):
    from audit.compliance_report import ComplianceReportGenerator
    gen = ComplianceReportGenerator()
    report = gen.generate(fmt=fmt)
    if fmt in ("html", "markdown", "md"):
        return {"success": True, "fmt": fmt, "content": report}
    return {"success": True, "fmt": "json", "data": report}
