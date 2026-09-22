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



# ---- 开放生态：受保护示例接口（演示 Token 鉴权 + 限流配额 + 调用留痕）----
# ============================================================================
# Phase 6：应急联动(emergency)/开放生态(clients|create|toggle|delete|logs)/
# PIPL合规台账 管理端点已迁 Spring Boot biz（cn.safeagent.biz.governance），
# 本文件保留：合规评测、开放问答(open/chat)、合规对标报告。
# ============================================================================
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


# ---- 合规对标报告 ----
@router.get("/api/compliance/report")
def compliance_report(fmt: str = "json"):
    from audit.compliance_report import ComplianceReportGenerator
    gen = ComplianceReportGenerator()
    report = gen.generate(fmt=fmt)
    if fmt in ("html", "markdown", "md"):
        return {"success": True, "fmt": fmt, "content": report}
    return {"success": True, "fmt": "json", "data": report}
