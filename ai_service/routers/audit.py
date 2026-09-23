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


@router.get("/api/audit/verify")
async def verify_audit_public(log_id: Optional[str] = None):
    """第三方独立验签 API（阶段5 审计链生产化，**无需登录**）

    gateway-lite 已对 audit verify 前缀放行（/api/audit/verify 归入
    _AI_KEPT_AUDIT_PREFIXES 且不要求登录），第三方监管/审计方无需平台账号
    即可核验审计链真实性。入参：
    - log_id 可选：指定时做单条验证（重算哈希 + HMAC 验签）；
    - log_id 缺省：全链验证（哈希链 + 分级签名 + WORM 锚定链）。

    响应字段：
    - valid / checked_count / algorithm：验签结论与算法标识；
    - key_fingerprint：HMAC 密钥 sha256 前 16 位指纹（供第三方比对密钥一致性，
      仅指纹不泄露密钥本体；密钥取自 graded_signer 现有单例，与验签同源）；
    - worm_chain：WORM 锚定链（data/worm_anchor.jsonl）完整性校验结果。
    """
    import hashlib
    import hmac
    from audit.worm_store import get_worm_store
    from audit.audit_logger import _parse_extra, _canonical_content

    algorithm = "HMAC-SHA256 + SHA256 hash-chain + ZKP(HIGH)"

    # ---- HMAC 密钥指纹：从 graded_signer 现有单例（app_deps.audit_logger 内）取密钥计算 ----
    # 注意只输出 sha256 指纹前 16 位，绝不回传密钥本体
    key_fingerprint = ""
    try:
        key_bytes = None
        gs = getattr(audit_logger, "_graded_signer", None)
        if gs is not None and getattr(gs, "_hmac_key", None):
            key_bytes = gs._hmac_key
        elif getattr(audit_logger, "_signing_key", None):
            key_bytes = audit_logger._signing_key
        if key_bytes:
            key_fingerprint = hashlib.sha256(key_bytes).hexdigest()[:16]
    except Exception:
        key_fingerprint = ""

    # ---- WORM 锚定链完整性（与数据库内哈希链形成双重证据）----
    try:
        worm_chain = get_worm_store().verify_chain()
    except Exception as e:
        worm_chain = {"valid": False, "checked": 0, "first_bad_seq": None, "error": str(e)[:200]}

    try:
        if log_id:
            # ---- 单条验证：按存储记录重算哈希 + HMAC 验签 ----
            data = audit_logger.storage.get_audit_log_by_id(log_id)
            if not data:
                raise HTTPException(status_code=404, detail=f"审计记录不存在：{log_id}")
            extra = _parse_extra(data)
            stored_hash = extra.get("log_hash", "")
            stored_prev = extra.get("prev_hash", "")
            stored_sig = extra.get("signature", "")
            hash_ok = bool(stored_hash) and hashlib.sha256(
                _canonical_content(data, stored_prev).encode("utf-8")
            ).hexdigest() == stored_hash
            sig_ok = False
            if stored_sig and getattr(audit_logger, "_signing_key", None):
                expected = hmac.new(
                    audit_logger._signing_key, stored_hash.encode(), hashlib.sha256
                ).hexdigest()
                sig_ok = hmac.compare_digest(expected, stored_sig)
            return {
                "success": True,
                "mode": "single",
                "log_id": log_id,
                "valid": bool(hash_ok and sig_ok),
                "checks": {"hash_ok": hash_ok, "signature_ok": sig_ok},
                "checked_count": 1,
                "algorithm": algorithm,
                "key_fingerprint": key_fingerprint,
                "worm_chain": worm_chain,
            }

        # ---- 全链验证：基础哈希链 + 分级签名（HMAC/Agent签名/ZKP）----
        chain = audit_logger.verify_chain()
        graded = audit_logger.verify_graded_chain()
        checked_count = int(chain.get("checked", 0)) + int(graded.get("graded_checked", 0))
        valid = bool(chain.get("ok")) and bool(graded.get("ok", True)) and bool(worm_chain.get("valid", True))
        return {
            "success": True,
            "mode": "full",
            "valid": valid,
            "checked_count": checked_count,
            "algorithm": algorithm,
            "key_fingerprint": key_fingerprint,
            "chain": chain,
            "graded": graded,
            "worm_chain": worm_chain,
        }
    except HTTPException:
        raise
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
