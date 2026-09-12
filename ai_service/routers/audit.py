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


@router.get("/api/audit/logs/recent")
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


@router.get("/api/audit/logs/page")
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


@router.get("/api/audit/logs/{log_id}", response_model=AuditLog)
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


@router.post("/api/audit/logs/search")
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


@router.get("/api/audit/export")
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


@router.get("/api/audit/stats")
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
