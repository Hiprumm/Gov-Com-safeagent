# -*- coding: utf-8 -*-
"""认证 / MFA / SSO / 共享守卫 路由模块 —— P1-1 按业务域拆分（原 main.py 同域路由收敛）

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


router = APIRouter()


@router.post("/api/auth/login")
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


@router.post("/api/auth/logout")
async def auth_logout(request: Request):
    token = request.headers.get("X-Auth-Token")
    if token:
        revoke_token(token)
    return {"success": True}


@router.get("/api/auth/me")
async def auth_me(request: Request):
    """返回当前登录身份；未登录 user=null，同时附演示账号列表供登录界面展示"""
    token = request.headers.get("X-Auth-Token")
    user = get_user_by_token(token)
    return {"user": user, "demo_accounts": list_demo_accounts()}


@router.put("/api/auth/profile")
async def auth_profile_update(request: Request, body: dict):
    """个人中心：修改自己的显示名（昵称）。

    仅允许登录者修改自身 display_name；角色/部门/职位由组织架构管理，个人不可自改。
    更新成功后返回最新身份，前端据此同步 currentUser 与全局显示。
    """
    identity = current_identity(request.headers.get("X-Auth-Token"))
    if not identity or not identity.get("username"):
        raise HTTPException(status_code=401, detail="未登录或登录已过期")

    display_name = str((body or {}).get("display_name", "")).strip()
    if not display_name:
        raise HTTPException(status_code=422, detail="显示名不能为空")
    if len(display_name) > 20:
        raise HTTPException(status_code=422, detail="显示名长度不能超过 20 个字符")

    from storage import get_storage
    ok = get_storage().update_user_profile(identity["username"], display_name=display_name)
    if not ok:
        raise HTTPException(status_code=500, detail="资料保存失败，请稍后重试")

    # 审计到人：记录本人资料修改操作
    try:
        audit_logger.create_log(
            user_id=identity["username"], user_role=identity.get("role") or "user",
            agent_id="user_profile",
            action_type="profile_update",
            action_details={
                "display_name_old": identity.get("display_name") or "",
                "display_name_new": display_name,
                "department": identity.get("department") or "",
            },
            risk_level=RiskLevel.NONE,
        )
    except Exception:
        pass  # 审计失败不阻断资料保存

    return {"success": True, "user": get_user_by_token(request.headers.get("X-Auth-Token"))}


@router.get("/api/auth/permissions")
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

@router.post("/api/auth/mfa/verify")
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


@router.get("/api/auth/mfa/status")
async def auth_mfa_status(request: Request):
    """查询当前账号 MFA 状态与是否可启用。"""
    identity = current_identity(request.headers.get("X-Auth-Token"))
    if not identity:
        raise HTTPException(status_code=401, detail="未登录")
    return {"success": True, **mfa_status(identity["username"]), "config": mfa_config()}


@router.post("/api/auth/mfa/enroll")
async def auth_mfa_enroll(request: Request):
    """开始绑定 MFA：生成 TOTP 密钥与 otpauth URI（需扫描后 confirm）。"""
    identity = current_identity(request.headers.get("X-Auth-Token"))
    if not identity:
        raise HTTPException(status_code=401, detail="未登录")
    if not mfa_config().get("enabled"):
        return {"success": False, "message": "系统未启用 MFA"}
    return {"success": True, **begin_mfa_enroll(identity["username"])}


@router.post("/api/auth/mfa/confirm")
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


@router.post("/api/auth/mfa/disable")
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


@router.post("/api/auth/refresh")
async def auth_refresh(request: Request):
    """续期：当前访问令牌有效则签发新令牌（用于临近过期的平滑续签）。"""
    token = request.headers.get("X-Auth-Token")
    identity = current_identity(token)
    if not identity:
        raise HTTPException(status_code=401, detail="登录已失效，请重新登录")
    revoke_token(token)  # 旧令牌作废，避免长期可用
    return {"success": True, "token": create_token(identity["username"]), "user": identity}


@router.post("/api/auth/password")
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


@router.get("/api/auth/sso/config")
async def auth_sso_config():
    """SSO 是否启用及加要求（不泄露密钥本身）。"""
    return {
        "success": True,
        "sso_enabled": sso_enabled(),
        "header": sso_header_name(),
        "signature_required": sso_signature_required(),
        "ip_restricted": sso_ip_restricted(),
    }


@router.post("/api/auth/sso")
async def auth_sso_login(request: Request):
    """SSO 免密登录：由受信网关注入的头映射到本地账号并签发令牌。

    加固：启用共享密钥后必须携带 X-SSO-Signature；可配置来源 IP 白名单。
    """
    if not sso_enabled():
        raise HTTPException(status_code=404, detail="未启用 SSO")
    client_ip = request.client.host if request.client else ""
    identity = resolve_sso_identity(request.headers, client_ip=client_ip)
    if not identity:
        raise HTTPException(status_code=401, detail="SSO 身份无效（签名/IP 校验失败或账号不存在/已停用）")
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


def _assert_session_owner(request: Request, session_id: str) -> str:
    """校验会话归属：仅会话所有者可操作，返回错误信息（空串表示通过）。

    账户数据独立分离：智能问答会话属用户隐私数据，即使是系统管理员也仅能访问
    自己的会话，不得查看/操作他人会话。迁移前无主会话（user_id 为空）视为不可归属，拒绝操作。
    """
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


