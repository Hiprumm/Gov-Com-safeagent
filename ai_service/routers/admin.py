# -*- coding: utf-8 -*-
"""用户与组织管理 路由模块 —— P1-1 按业务域拆分（原 main.py 同域路由收敛）

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

from routers.auth import _admin_guard, _login_guard, _assert_session_owner, _pw_fields, _body, _ROLES


router = APIRouter()


@router.get("/api/admin/users")
async def admin_list_users(request: Request):
    """用户列表（仅 admin），支持分页：?page=1&page_size=10（默认每页 10，上限 200）"""
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份", "users": []}
    from storage import get_storage
    all_users = get_storage().list_users()
    total = len(all_users)
    try:
        page = max(1, int(request.query_params.get("page", 1)))
        page_size = min(200, max(1, int(request.query_params.get("page_size", 10))))
    except (TypeError, ValueError):
        page, page_size = 1, 10
    start = (page - 1) * page_size
    users = all_users[start:start + page_size]
    return {"success": True, "users": users, "total": total, "page": page, "page_size": page_size}


@router.post("/api/admin/users")
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


@router.put("/api/admin/users/{username}")
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


@router.post("/api/admin/users/{username}/reset_password")
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


@router.delete("/api/admin/users/{username}")
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


@router.get("/api/admin/stats")
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


@router.get("/api/admin/departments")
async def admin_list_departments(request: Request):
    """部门目录（仅 admin）"""
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份", "departments": []}
    from storage import get_storage
    return {"success": True, "departments": get_storage().list_departments()}


@router.post("/api/admin/departments")
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


@router.put("/api/admin/departments")
async def admin_rename_department(request: Request):
    """重命名部门（仅 admin）：{old_name, new_name}，同步更新该部门下用户归属"""
    from storage import get_storage
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    body = await _body(request)
    old_name = str(body.get("old_name", "")).strip()
    new_name = str(body.get("new_name", "")).strip()
    if not old_name or not new_name:
        return {"success": False, "error": "原部门名与新部门名均不能为空"}
    ok = get_storage().rename_department(old_name, new_name)
    return {"success": ok, "message": ("已重命名" if ok else "部门不存在或名称重复")}


@router.delete("/api/admin/departments")
async def admin_delete_department(request: Request, name: str):
    """删除部门（仅 admin）：该部门下用户的部门归属置空"""
    from storage import get_storage
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    name = (name or "").strip()
    if not name:
        return {"success": False, "error": "部门名称不能为空"}
    ok = get_storage().remove_department(name)
    return {"success": ok, "message": ("已删除部门" if ok else "部门不存在")}


# ==================== 审批管理 API ====================
