# -*- coding: utf-8 -*-
"""审计日志 / 审计保护 / 锚点 / TSA / 归档 / 链校验 路由模块 —— P1-1 按业务域拆分（原 main.py 同域路由收敛）

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


@router.get("/api/audit/config")
async def get_audit_config():
    """审计配置（日志留存天数等）"""
    from audit.audit_logger import AUDIT_RETENTION_DAYS
    return {
        "retention_days": AUDIT_RETENTION_DAYS,
        "retention_hint": f"审计日志默认留存 {AUDIT_RETENTION_DAYS} 天（可通过环境变量 AUDIT_RETENTION_DAYS 配置为 30=1个月 / 90=3个月 / 180=6个月）",
    }


# ==================== 审计不可篡改（WORM）与留存归档 ====================

@router.get("/api/audit/protection")
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


@router.post("/api/audit/protection/install")
async def install_audit_worm(request: Request):
    """安装/修复审计 WORM 保护触发器（仅管理员）。"""
    from audit.audit_protection import install_audit_protection
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    return {"success": True, "protection": install_audit_protection()}


@router.post("/api/audit/retention/run")
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



@router.get("/api/audit/anchor")
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


@router.post("/api/audit/anchor")
async def create_audit_anchor(request: Request):
    """创建审计锚点：对当前链头请求可信时间戳并留档（仅管理员）。"""
    from audit.tsa import create_anchor
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    try:
        return {"success": True, "anchor": create_anchor()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/audit/anchor/verify")
async def verify_audit_anchor(request: Request):
    """校验当前审计链相对最近锚点是否一致（未截断/回滚，仅管理员）。"""
    from audit.tsa import verify_anchor
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    result = verify_anchor()
    return {"success": bool(result.get("ok")), **result}


@router.get("/api/audit/tsa")
async def get_audit_tsa(request: Request):
    """查询可信时间戳（TSA）配置（仅管理员）。"""
    from audit.tsa import load_tsa_config
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    return {"success": True, "config": load_tsa_config(force=True)}


@router.put("/api/audit/tsa")
async def put_audit_tsa(request: Request):
    """配置可信时间戳服务（仅管理员）：{url, enabled}。"""
    from audit.tsa import save_tsa_config
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    body = await _body(request)
    return {"success": True, "config": save_tsa_config(str(body.get("url", "")), bool(body.get("enabled", False)))}


# ==================== 归档文件 / 外发投递历史（治理面板） ====================

@router.get("/api/audit/archives")
async def list_audit_archives(request: Request):
    """列出审计归档文件（仅管理员）。"""
    from audit.audit_protection import list_archives, ARCHIVE_DIR
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    return {"success": True, "archives": list_archives(), "archive_dir": ARCHIVE_DIR}


@router.get("/api/audit/archives/{name}")
async def download_audit_archive(request: Request, name: str):
    """下载指定归档文件（仅管理员，防目录穿越）。"""
    from audit.audit_protection import resolve_archive
    if not _admin_guard(request):
        raise HTTPException(status_code=403, detail="无权限：需要系统管理员身份")
    path = resolve_archive(name)
    if not path:
        raise HTTPException(status_code=404, detail="归档文件不存在")
    return FileResponse(path, media_type="application/x-ndjson", filename=name)




@router.get("/api/audit/logs/verify")
async def verify_audit_chain():
    """校验审计日志哈希链与签名完整性（防篡改）"""
    try:
        return audit_logger.verify_chain()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/audit/logs/verify-graded")
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
