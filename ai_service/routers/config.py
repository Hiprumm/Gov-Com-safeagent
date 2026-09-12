# -*- coding: utf-8 -*-
"""安全策略 / 模型接入 / 通知通道 / 审计外发 / AIGC 标识 路由模块 —— P1-1 按业务域拆分（原 main.py 同域路由收敛）

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


@router.get("/api/audit/forward")
async def get_audit_forward(request: Request):
    """查询审计外发配置（仅管理员）。"""
    from audit.audit_forwarder import load_config
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    return {"success": True, "config": load_config(force=True)}


@router.put("/api/audit/forward")
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


@router.post("/api/audit/forward/test")
async def test_audit_forward(request: Request):
    """测试审计外发连通性（仅管理员）。"""
    from audit.audit_forwarder import test_forward
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    result = test_forward()
    return {"success": bool(result.get("ok")), **result}


# ==================== 可信时间戳（TSA）与审计锚点（Checkpoint） ====================



@router.get("/api/audit/forward/history")
async def get_audit_forward_history(request: Request, limit: int = 30):
    """外发投递历史（最近若干条，仅管理员）。"""
    from audit.audit_forwarder import forward_history
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    return {"success": True, "history": forward_history(limit)}




# ============================================================================
# 安全管控台：安全策略中心（在线配置 · 热生效 · 版本化）
# ============================================================================

@router.get("/api/security/policy")
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


@router.put("/api/security/policy")
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





@router.get("/api/aigc/label")
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
# 收敛策略(P1-3)：12 个端点中仅 GET /api/optimization/attack_samples 被前端消费，
# 其余写端点默认关闭(501)，仅保留只读端点 + 只读汇总，降低攻击面与维护成本。
# ============================================================================


@router.get("/api/model/config")
async def get_model_config(request: Request):
    """模型接入配置查询（仅管理员：含接入端点与 Key 存在性，避免匿名探测）。"""
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    from llm_runtime import runtime_status
    return {"success": True, "config": runtime_status()}


@router.put("/api/model/config")
async def set_model_config(request: Request, payload: dict):
    """更新模型接入配置（仅管理员）：provider/api_key/base_url/model + 备用模型 backup_*，热生效。"""
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    from llm_runtime import save_config, load_config
    provider = payload.get("provider")
    api_key = payload.get("api_key")          # None=不修改 / ''=清除覆盖 Key
    base_url = payload.get("base_url")
    model = payload.get("model")
    backup_provider = payload.get("backup_provider")       # None=不修改
    backup_api_key = payload.get("backup_api_key")          # None=不修改 / ''=清除备用 Key
    backup_base_url = payload.get("backup_base_url")
    backup_model = payload.get("backup_model")
    if provider not in (None, "zhipu", "openai"):
        raise HTTPException(status_code=400, detail="provider 仅支持 zhipu / openai")
    if base_url is not None and not base_url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="base_url 需以 http(s):// 开头")
    if backup_provider not in (None, "zhipu", "openai"):
        raise HTTPException(status_code=400, detail="backup_provider 仅支持 zhipu / openai")
    if backup_base_url is not None and backup_base_url and not backup_base_url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="backup_base_url 需以 http(s):// 开头")
    try:
        saved = save_config(provider or "zhipu", api_key, base_url or "", model or "",
                            backup_provider=backup_provider, backup_api_key=backup_api_key,
                            backup_base_url=backup_base_url or "", backup_model=backup_model)
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"模型配置保存失败：{e}")
    # 热生效：分类层 + 对话主链立即使用新接入参数（无需重启）
    input_detector.llm_classifier.apply_runtime(saved)
    gov_agent.refresh_llm(saved)
    from llm_runtime import runtime_status
    return {"success": True, "config": runtime_status()}


@router.post("/api/model/config/test")
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


# ==================== 可观测性大盘（S1：运维指标只读端点） ====================



@router.get("/api/notifications")
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


@router.post("/api/notifications/read")
async def notifications_mark_read(request: Request, payload: dict):
    """标记通知已读（需登录）。"""
    if not _login_guard(request):
        raise HTTPException(status_code=401, detail="未登录")
    from storage import get_storage
    storage = get_storage()
    nid = payload.get("id")
    storage.mark_notifications_read(int(nid) if nid is not None else None)
    return {"success": True, "unread": storage.count_unread_notifications()}


@router.post("/api/notifications/clear")
async def notifications_clear(request: Request):
    """清空通知（需登录）。"""
    if not _login_guard(request):
        raise HTTPException(status_code=401, detail="未登录")
    from storage import get_storage
    get_storage().clear_notifications()
    return {"success": True}


@router.get("/api/notifications/webhook")
async def get_webhook_config(request: Request):
    """外部通知渠道配置查询（仅管理员）。"""
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    from notify_webhook import load_webhook
    return {"success": True, "config": load_webhook()}


@router.put("/api/notifications/webhook")
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


@router.post("/api/notifications/webhook/test")
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


# ==================== 应急通知通道（飞书机器人 / SMTP 邮件） ====================

@router.get("/api/notifications/channels")
async def get_notify_channels(request: Request):
    """查询全部通知通道配置（仅管理员；SMTP 密码脱敏返回）。"""
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    from notify_webhook import load_channels
    channels = load_channels()
    if channels["smtp"].get("smtp_password"):
        channels["smtp"]["smtp_password"] = "******"
    return {"success": True, "channels": channels}


@router.put("/api/notifications/channels/{name}")
async def set_notify_channel(name: str, request: Request, payload: dict):
    """配置某一通知通道（webhook | lark | smtp），仅管理员。"""
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    from notify_webhook import save_channel
    if name not in ("webhook", "lark", "smtp"):
        raise HTTPException(status_code=400, detail="通道仅支持 webhook/lark/smtp")
    if name in ("webhook", "lark"):
        url = str(payload.get("url", "")).strip()
        enabled = bool(payload.get("enabled", False))
        if enabled and not url.startswith(("http://", "https://")):
            raise HTTPException(status_code=400, detail="Webhook 地址需以 http(s):// 开头")
        save_channel(name, {"url": url, "enabled": enabled})
        return {"success": True, "channel": name, "config": {"url": url, "enabled": enabled}}
    save_channel("smtp", {
        "smtp_host": str(payload.get("smtp_host", "")).strip(),
        "smtp_port": int(payload.get("smtp_port", 465) or 465),
        "smtp_user": str(payload.get("smtp_user", "")).strip(),
        "smtp_password": str(payload.get("smtp_password", "")).strip(),
        "from_addr": str(payload.get("from_addr", "")).strip(),
        "to_addrs": list(payload.get("to_addrs", []) or []),
        "use_ssl": bool(payload.get("use_ssl", True)),
        "enabled": bool(payload.get("enabled", False)),
    })
    return {"success": True, "channel": "smtp"}


@router.post("/api/notifications/channels/{name}/test")
async def test_notify_channel(name: str, request: Request, payload: dict):
    """测试通知通道连通性（仅管理员）。webhook/lark 传 url；smtp 传邮件参数。"""
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    if name not in ("webhook", "lark", "smtp"):
        raise HTTPException(status_code=400, detail="通道仅支持 webhook/lark/smtp")
    try:
        if name in ("webhook", "lark"):
            from notify_webhook import test_webhook, test_lark
            url = str(payload.get("url", "")).strip()
            if not url.startswith(("http://", "https://")):
                raise HTTPException(status_code=400, detail="请输入有效的 http(s) 地址")
            fn = test_webhook if name == "webhook" else test_lark
            ok, detail = fn(url)
        else:
            from notify_webhook import test_smtp
            ok, detail = test_smtp({
                "smtp_host": str(payload.get("smtp_host", "")).strip(),
                "smtp_port": int(payload.get("smtp_port", 465) or 465),
                "smtp_user": str(payload.get("smtp_user", "")).strip(),
                "smtp_password": str(payload.get("smtp_password", "")).strip(),
                "from_addr": str(payload.get("from_addr", "")).strip(),
                "to_addrs": list(payload.get("to_addrs", []) or []),
                "use_ssl": bool(payload.get("use_ssl", True)),
            })
        if not ok:
            raise HTTPException(status_code=400, detail=detail or "发送失败")
        return {"success": True, "detail": detail}
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(e)[:180])


# ==================== 系统自检与数据维护（运维视角） ====================

# 服务进程启动时刻（模块加载时记录，用于 uptime 统计）
