# -*- coding: utf-8 -*-
"""安全检测 / 工具管控 / 审批 / 运行时 / 优化闭环 / 场景 / 回放 / 评测 路由模块 —— P1-1 按业务域拆分（原 main.py 同域路由收敛）

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

import asyncio
from security.session_risk_accumulator import session_risk_accumulator
from security.operation_guard import OperationIntent, ActionType as GuardActionType
from websocket.manager import push_approval_update, push_risk_alert
from routers.auth import _admin_guard, _login_guard, _assert_session_owner, _pw_fields, _body, _ROLES


router = APIRouter()


@router.post("/api/security/detect_input", response_model=BatchDetectionResponse)
async def detect_input(request: BatchDetectionRequest):
    try:
        result = input_detector.batch_detect(request)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/security/detect_single")
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
        # 可观测性：检测事件计数（风险级 + 攻击类型）
        try:
            from metrics_collector import get_metrics_collector
            risk_val = result.risk_level.value if hasattr(result.risk_level, "value") else str(result.risk_level)
            attack_val = result.attack_type.value if (hasattr(result, "attack_type") and result.attack_type and hasattr(result.attack_type, "value")) else (result.attack_type or None)
            get_metrics_collector().record_detect(risk_val, attack_val or "none")
        except Exception:  # noqa: BLE001
            pass
        return resp
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/security/detect_file")
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


@router.post("/api/security/tool_risk", response_model=ToolRiskResult)
async def evaluate_tool_risk(request: ToolCallRequest):
    try:
        result = tool_evaluator.evaluate(request)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 操作守卫层 API ====================

@router.post("/api/security/operation_guard/check")
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


@router.get("/api/security/operation_guard/session/{session_id}")
async def get_operation_guard_session(session_id: str):
    """获取会话操作守卫历史摘要"""
    try:
        summary = operation_guard.get_session_summary(session_id)
        return {"success": True, "summary": summary}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/security/operation_guard/clear/{session_id}")
async def clear_operation_guard_session(session_id: str):
    """清除会话操作守卫记录"""
    try:
        operation_guard.clear_session(session_id)
        return {"success": True, "message": f"Session {session_id} 操作守卫记录已清除"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== T4: 运行时工具调用控制 API ====================

@router.get("/api/security/runtime/trace/{session_id}")
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


@router.get("/api/security/runtime/anomalies/{session_id}")
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


@router.post("/api/security/runtime/terminate/{session_id}")
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


@router.get("/api/security/runtime/summary/{session_id}")
async def get_runtime_summary(session_id: str):
    """获取会话运行时摘要（步数/异常/级联/终止状态）"""
    try:
        summary = gov_agent.security_layer.runtime_monitor.get_session_summary(session_id)
        return {"session_id": session_id, "summary": summary}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/security/runtime/task_chain/{session_id}")
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


@router.post("/api/security/permission/check")
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


@router.post("/api/security/browser/check_url")
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


@router.get("/api/security/approval/pending")
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


@router.get("/api/security/approval/history")
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


@router.get("/api/security/approval/{request_id}", response_model=ApprovalRequest)
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


@router.post("/api/security/plugin_scan")
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


@router.get("/api/security/tool_management/status")
async def get_tool_management_status():
    return {"enabled": tool_management_enabled}


@router.post("/api/security/tool_management/toggle")
async def toggle_tool_management(request: Request):
    global tool_management_enabled
    body = await request.json() if request.headers.get("content-type", "").startswith("application/json") else {}
    tool_management_enabled = body.get("enabled", not tool_management_enabled)
    return {"enabled": tool_management_enabled}


@router.post("/api/security/mcp_scan")
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


@router.post("/api/security/skill_scan")
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


@router.post("/api/security/tool_combination_scan")
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





def _optimization_write_guard():
    """写端点开关：默认关闭，ENABLE_OPTIMIZATION_WRITE=true 时开启"""
    if not settings.ENABLE_OPTIMIZATION_WRITE:
        raise HTTPException(
            status_code=501,
            detail="优化闭环写端点默认关闭(只读收敛)。如需启用请设置 ENABLE_OPTIMIZATION_WRITE=true",
        )


@router.post("/api/optimization/feedback")
async def optimization_feedback(request: dict):
    """检测结果人工标注（确认/驳回）[写端点，默认关闭]"""
    _optimization_write_guard()
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


@router.get("/api/optimization/feedback")
async def optimization_feedback_list(limit: int = 100):
    try:
        from security.optimization_loop import get_optimization_loop
        return {"items": get_optimization_loop().list_feedback(limit)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/optimization/feedback/stats")
async def optimization_feedback_stats():
    """误报/漏报统计"""
    try:
        from security.optimization_loop import get_optimization_loop
        return get_optimization_loop().feedback_stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/optimization/tune")
async def optimization_tune(request: dict):
    """基于标注数据的规则自动调优 [写端点，默认关闭]"""
    _optimization_write_guard()
    try:
        from security.optimization_loop import get_optimization_loop
        return get_optimization_loop().auto_tune_from_feedback(
            auto_apply=request.get("auto_apply", True),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/optimization/versions")
async def optimization_versions(limit: int = 100):
    """关键词/模式库版本列表"""
    try:
        from security.optimization_loop import get_optimization_loop
        return {"versions": get_optimization_loop().list_versions(limit)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/optimization/versions/{version_id}/apply")
async def optimization_version_apply(version_id: str):
    """应用版本（写入动态检测库）[写端点，默认关闭]"""
    _optimization_write_guard()
    try:
        from security.optimization_loop import get_optimization_loop
        return get_optimization_loop().apply_version(version_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/optimization/attack_samples")
async def optimization_attack_samples_add(request: dict):
    """攻击样例库动态扩充 [写端点，默认关闭]"""
    _optimization_write_guard()
    try:
        from security.optimization_loop import get_optimization_loop
        return get_optimization_loop().record_attack_sample(
            content=request.get("content", ""),
            attack_type=request.get("attack_type", "unknown"),
            source=request.get("source", "manual"),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/optimization/attack_samples")
async def optimization_attack_samples_list(limit: int = 200):
    try:
        from security.optimization_loop import get_optimization_loop
        return {"items": get_optimization_loop().list_attack_samples(limit)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/optimization/cluster")
async def optimization_cluster(request: dict):
    """新型攻击模式自动聚类 [写端点，默认关闭]"""
    _optimization_write_guard()
    try:
        from security.optimization_loop import get_optimization_loop
        return get_optimization_loop().cluster_attack_patterns(
            min_cluster=request.get("min_cluster", 2),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/optimization/threat_intel")
async def optimization_threat_intel(request: dict):
    """威胁情报订阅接口（外部IOC导入）[写端点，默认关闭]"""
    _optimization_write_guard()
    try:
        from security.optimization_loop import get_optimization_loop
        iocs = request.get("iocs") or []
        return get_optimization_loop().import_threat_iocs(
            iocs=iocs, source=request.get("source", "external"),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/optimization/threat_intel")
async def optimization_threat_intel_list(limit: int = 200):
    try:
        from security.optimization_loop import get_optimization_loop
        return {"items": get_optimization_loop().list_threat_iocs(limit)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/optimization/regression")
async def optimization_regression(request: dict):
    """规则更新后自动回归测试 [写端点，默认关闭]"""
    _optimization_write_guard()
    try:
        from security.optimization_loop import get_optimization_loop
        samples = request.get("samples")
        return get_optimization_loop().run_regression(
            samples=samples, note=request.get("note", "api"),
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/optimization/trend")
async def optimization_trend(limit: int = 30):
    """检测效果趋势可视化数据"""
    try:
        from security.optimization_loop import get_optimization_loop
        return get_optimization_loop().get_trend(limit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/optimization/summary")
async def optimization_summary():
    """优化闭环只读汇总：反馈统计 / 版本数 / 样例库 / 威胁情报 / 最近趋势"""
    try:
        from security.optimization_loop import get_optimization_loop
        loop = get_optimization_loop()
        stats = loop.feedback_stats()
        counts = loop.get_counts()
        trend = loop.get_trend(limit=30)
        summary = {
            "write_enabled": settings.ENABLE_OPTIMIZATION_WRITE,
            "feedback": stats,
            "version_count": counts["versions"],
            "attack_sample_count": counts["attack_samples"],
            "threat_ioc_count": counts["threat_iocs"],
            "trend": trend,
        }
        return summary
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/security/eval_calc", response_model=EvaluationMetrics)
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





@router.post("/api/security/approval/approve/{request_id}")
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


@router.post("/api/security/approval/reject/{request_id}")
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


@router.get("/api/security/approval/status/{request_id}")
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



@router.post("/api/security/kb_poisoning/detect_pdf")
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


@router.post("/api/security/kb_poisoning/detect_text")
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

@router.get("/api/security/session_risk/{session_id}")
async def get_session_risk(session_id: str):
    """获取指定 session 的风险累积画像"""
    try:
        profile = session_risk_accumulator.get_session_summary(session_id)
        return {"success": True, "profile": profile}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/security/session_risk")
async def list_all_session_risks():
    """获取所有活跃 session 的风险摘要"""
    try:
        sessions = session_risk_accumulator.get_all_active_sessions()
        return {"success": True, "sessions": sessions, "count": len(sessions)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/security/session_risk/clear/{session_id}")
async def clear_session_risk(session_id: str):
    """清除 session 风险数据"""
    try:
        session_risk_accumulator.clear_session(session_id)
        return {"success": True, "message": f"Session {session_id} 风险数据已清除"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 跨来源关联分析 API ====================

@router.get("/api/security/cross_source/summary/{session_id}")
async def get_cross_source_summary(session_id: str):
    """获取某个 Session 的跨来源关联分析摘要"""
    try:
        summary = cross_source_correlator.get_session_summary(session_id)
        return {"success": True, "data": summary}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/security/cross_source/clear/{session_id}")
async def clear_cross_source(session_id: str):
    """清除某个 Session 的跨来源关联数据"""
    try:
        cross_source_correlator.clear_session(session_id)
        return {"success": True, "message": f"Session {session_id} 关联数据已清除"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 对抗样本 Bypass 测试 API ====================

@router.post("/api/security/bypass_test")
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

@router.post("/api/security/pssu/assess")
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


@router.post("/api/security/bypass_batch_test")
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




@router.get("/api/scenarios")
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


@router.get("/api/scenarios/{scenario_id}")
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


@router.post("/api/scenarios/{scenario_id}/run")
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


@router.post("/api/scenarios/run_all")
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




@router.post("/api/replay/record")
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


@router.post("/api/replay/{record_id}")
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


@router.post("/api/replay/all")
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


@router.get("/api/replay/records")
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



@router.get("/api/evaluation/report")
async def get_evaluation_report():
    """获取评测报告数据"""
    import json
    report_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "audit", "evaluation_report.json")
    if os.path.exists(report_path):
        with open(report_path, "r", encoding="utf-8") as f:
            return json.load(f)
    raise HTTPException(status_code=404, detail="评测报告未生成，请先运行评测")


# 评测生成状态（进程内存；仅演示场景，避免并发重跑）
_eval_gen_state = {"running": False, "started_at": None}


@router.post("/api/evaluation/generate")
async def generate_evaluation_report(request: Request):
    """触发评测报告（重新）生成（仅管理员，后台异步运行）。"""
    if not _admin_guard(request):
        return {"success": False, "error": "无权限：需要系统管理员身份"}
    if _eval_gen_state["running"]:
        return {"success": False, "error": "评测正在生成中，请稍后刷新"}
    import threading

    def _run():
        try:
            _eval_gen_state["running"] = True
            _eval_gen_state["started_at"] = datetime.now().isoformat()
            from audit.run_evaluation import (
                load_samples, run_detection, compute_metrics, classify_results, save_report,
            )
            from security.input_detector import InputDetectionService
            samples_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "audit", "attack_samples.json")
            report_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "audit", "evaluation_report.json")
            samples = load_samples(samples_path)
            detector = InputDetectionService()
            results = run_detection(samples, detector)
            metrics = compute_metrics(results)
            classification = classify_results(results)
            save_report(metrics, classification, results, report_path)
        except Exception as e:
            print(f"[EVAL] 评测生成失败: {e}")
        finally:
            _eval_gen_state["running"] = False

    threading.Thread(target=_run, daemon=True).start()
    return {"success": True, "message": "评测已在后台开始生成，完成后刷新页面即可查看最新报告"}


@router.get("/api/evaluation/status")
async def evaluation_generate_status():
    """评测生成状态查询（前端轮询用）。"""
    return {"running": _eval_gen_state["running"], "started_at": _eval_gen_state["started_at"]}


# ==================== 模型接入配置（P2-6：内网/离线 OpenAI 兼容端点） ====================

