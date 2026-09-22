# -*- coding: utf-8 -*-
"""认证 / MFA / SSO / 共享守卫 路由模块 —— P1-1 按业务域拆分（原 main.py 同域路由收敛）

- 跨域共享守卫（_admin_guard / _login_guard / _assert_session_owner / _pw_fields / _body / _ROLES）
  收敛于 routers.auth.py。
- Phase 6：认证 HTTP 端点（login / me / profile / password / MFA / SSO）已迁至 Spring Boot biz
  （cn.safeagent.biz.auth），本模块仅保留共享守卫与工具函数供其它保留 router 复用。
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import List, Dict, Any, Optional  # noqa: F401
from datetime import datetime  # noqa: F401

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse  # noqa: F401

from models.schemas import (  # noqa: F401
    DetectionResult, BatchDetectionRequest, BatchDetectionResponse,
    FileDetectionRequest, FileUploadRequest,
    ToolCallRequest, ToolRiskResult,
    PluginScanRequest, PluginScanResult,
    AuditLog, EvaluationMetrics,
    ApprovalRequest, ApprovalResponse,
    RiskLevel,
)

from config import settings  # noqa: F401
from auth import (  # noqa: F401
    DEMO_USERS, verify_password, authenticate, create_token, revoke_token,
    get_user_by_token, current_identity, list_demo_accounts,
    check_password_policy, mfa_config, mfa_status, begin_mfa_enroll,
    confirm_mfa_enroll, disable_mfa, create_mfa_ticket, verify_mfa_ticket,
    sso_enabled, sso_header_name, resolve_sso_identity,
    sso_signature_required, sso_ip_restricted,
)
from app_deps import (
    input_detector, tool_evaluator, approval_engine, kb_poisoning_detector,  # noqa: F401
    cross_source_correlator, bypass_tester, plugin_scanner, mcp_scanner,
    skill_analyzer, combination_detector, operation_guard, audit_logger,
    metrics_calculator, gov_agent, policy_manager, permission_engine,
    _apply_policy_hot,
)


router = APIRouter()


# ==================== 用户与组织管理 API（仅系统管理员 admin） ====================
_ROLES = ("admin", "operator", "auditor", "manager", "user")


def _admin_guard(request: Request):
    """返回当前具备后台管理权限的身份，无权限返回 None（走统一权限引擎）"""
    identity = current_identity(request.headers.get("X-Auth-Token"))
    if identity and permission_engine.has_permission(identity.get("role"), "admin.manage"):
        return identity
    return None


def _login_guard(request: Request):
    """返回当前登录身份（任意角色）；未登录返回 None。"""
    return current_identity(request.headers.get("X-Auth-Token")) or None


def _assert_session_owner(request: Request, session_id: str) -> str:
    """校验会话归属：仅会话所有者可操作，返回错误信息（空串表示通过）。"""
    identity = current_identity(request.headers.get("X-Auth-Token")) or {}
    username = identity.get("username")
    if not username:
        return "未登录"
    s = gov_agent.conversation_manager.storage.get_session(session_id)
    if not s:
        return "会话不存在"
    if s.get("user_id") != username:
        return "无权操作他人会话"
    return ""


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