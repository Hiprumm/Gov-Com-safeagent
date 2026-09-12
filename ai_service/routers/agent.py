# -*- coding: utf-8 -*-
"""智能体问答 / 文件 / 会话管理 路由模块 —— P1-1 按业务域拆分（原 main.py 同域路由收敛）

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


@router.post("/api/agent/run")
async def run_agent(req: Request, user_input: str, input_source: str = "user_input"):
    try:
        # 审计到人：将发起调用的登录账号+部门透传给 agent，贯穿到其审计/审批
        identity = current_identity(req.headers.get("X-Auth-Token")) if req else {}
        result = gov_agent.run(user_input, input_source, user=identity or None)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/agent/chat")
async def chat_with_history(req: Request, user_input: str, session_id: Optional[str] = None, input_source: str = "user_input"):
    # 应急联动：全局熔断 / 账号封锁 在聊天入口拦截
    try:
        from governance import get_emergency_center, get_pipl_ledger
        identity_block = current_identity(req.headers.get("X-Auth-Token")) if req else {}
        block_reason = get_emergency_center().reason_blocked(
            username=(identity_block or {}).get("username"),
            ip=req.client.host if req.client else "",
        )
        if block_reason:
            raise HTTPException(status_code=403, detail=block_reason)
        # PIPL 输入侧识别登记（含 PII 时写入台账留痕）
        if user_input:
            get_pipl_ledger().scan_and_register(
                user_input,
                session_id=session_id or "",
                username=(identity_block or {}).get("username") or "",
                source="chat",
            )
    except HTTPException:
        raise
    except Exception:
        pass
    try:
        # 审计到人：将发起调用的登录账号+部门透传给 agent，贯穿到其审计/审批
        identity = current_identity(req.headers.get("X-Auth-Token")) if req else {}
        result = gov_agent.run(user_input, input_source, session_id, user=identity or None)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/agent/chat/stream")
async def chat_stream(req: Request, user_input: str, session_id: Optional[str] = None, input_source: str = "user_input"):
    """AI 问答"思考中"流式接口：SSE 逐节点实时推送推理步骤，完成后推送最终回复。

    - event: thinking  → {"step", "phase", "phase_label", "title", "detail", "node"}
    - event: done      → {"final_response", "risk_level", "session_id", "thinking_steps", ...}
    - event: error     → {"message": ...}
    思考步骤全部来自 LangGraph 真实节点产出，无模拟、不额外消耗 LLM。
    """
    identity = current_identity(req.headers.get("X-Auth-Token")) if req else {}
    user_id = (identity or {}).get("username") or None

    # 应急联动：全局熔断 / 账号封锁 在流式入口拦截
    try:
        from governance import get_emergency_center, get_pipl_ledger
        block_reason = get_emergency_center().reason_blocked(
            username=user_id, ip=req.client.host if req.client else "")
        if block_reason:
            raise HTTPException(status_code=403, detail=block_reason)
        if user_input:
            get_pipl_ledger().scan_and_register(
                user_input, session_id=session_id or "", username=user_id or "", source="chat")
    except HTTPException:
        raise
    except Exception:
        pass

    def _sse(event_type: str, payload: Any) -> str:
        return f"event: {event_type}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"

    def event_stream():
        try:
            # 与同步 run 一致：确保会话存在并归属当前用户
            if not session_id:
                gen_session = gov_agent.conversation_manager.create_session(user_id)
            else:
                gen_session = gov_agent.conversation_manager.ensure_session(session_id, user_id)
        except Exception as e:
            yield _sse("error", {"message": f"会话初始化失败：{e}"})
            return
        try:
            for event_type, payload in gov_agent.run_stream(gen_session, user_input, input_source, user=identity or None):
                yield _sse(event_type, payload)
        except Exception as e:
            yield _sse("error", {"message": str(e)})

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/api/agent/file/stream")
async def file_stream(http_req: Request, request: FileUploadRequest):
    """附件问答流式接口：识别阶段推送"思考"步骤，之后逐 token 流式输出回答。

    - event: thinking → {"step", "phase", "phase_label", "title", "detail", "node"}
    - event: content  → {"delta": ...}
    - event: done     → {"final_response", "risk_level", "session_id", "thinking_steps", ...}
    - event: error    → {"message": ...}
    与 /api/agent/chat/stream 同协议，前端复用同一套 SSE 解析。
    """
    identity = current_identity(http_req.headers.get("X-Auth-Token")) if http_req else {}
    user_id = (identity or {}).get("username") or None
    session_id = request.session_id

    # 应急联动：全局熔断 / 账号封锁 在流式入口拦截
    try:
        from governance import get_emergency_center, get_pipl_ledger
        block_reason = get_emergency_center().reason_blocked(
            username=user_id, ip=http_req.client.host if http_req.client else "")
        if block_reason:
            raise HTTPException(status_code=403, detail=block_reason)
        if request.user_text:
            get_pipl_ledger().scan_and_register(
                request.user_text, session_id=session_id or "", username=user_id or "", source="chat")
    except HTTPException:
        raise
    except Exception:
        pass

    def _sse(event_type: str, payload: Any) -> str:
        return f"event: {event_type}\ndata: {json.dumps(payload, ensure_ascii=False)}\n\n"

    def event_stream():
        try:
            if not session_id:
                gen_session = gov_agent.conversation_manager.create_session(user_id)
            else:
                gen_session = gov_agent.conversation_manager.ensure_session(session_id, user_id)
        except Exception as e:
            yield _sse("error", {"message": f"会话初始化失败：{e}"})
            return
        try:
            for event_type, payload in gov_agent.process_file_message_stream(
                    gen_session, request.file_data, request.file_type, request.filename,
                    user_text=request.user_text, user=identity or None):
                yield _sse(event_type, payload)
        except Exception as e:
            yield _sse("error", {"message": str(e)})

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.post("/api/agent/file_upload")
async def upload_file(http_req: Request, request: FileUploadRequest):
    try:
        # 审计到人：解析登录账号透传给 agent 处理
        identity = current_identity(http_req.headers.get("X-Auth-Token")) if http_req else {}
        user_id = (identity or {}).get("username") or None
        session_id = request.session_id
        if not session_id:
            session_id = gov_agent.conversation_manager.create_session(user_id)
        result = gov_agent.process_file_message(session_id, request.file_data, request.file_type,
                                                request.filename, user_text=request.user_text,
                                                user=identity or None)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/agent/history")
async def get_conversation_history(request: Request, session_id: str):
    err = _assert_session_owner(request, session_id)
    if err:
        raise HTTPException(status_code=404 if err == "会话不存在" else 403, detail=err)
    try:
        result = gov_agent.get_conversation_history(session_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/agent/new_session")
async def create_new_session(request: Request):
    identity = current_identity(request.headers.get("X-Auth-Token")) or {}
    user_id = identity.get("username") or None
    try:
        result = gov_agent.create_new_session(user_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/agent/clear_session")
async def clear_conversation(request: Request, session_id: str):
    err = _assert_session_owner(request, session_id)
    if err:
        raise HTTPException(status_code=404 if err == "会话不存在" else 403, detail=err)
    try:
        result = gov_agent.clear_conversation(session_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/agent/delete_session")
async def delete_conversation(request: Request, session_id: str):
    """删除整个历史会话（会话记录及全部消息）"""
    err = _assert_session_owner(request, session_id)
    if err:
        raise HTTPException(status_code=404 if err == "会话不存在" else 403, detail=err)
    try:
        result = gov_agent.delete_session(session_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/agent/rename_session")
async def rename_session(request: Request, session_id: str, title: str):
    """重命名历史会话（title 传空字符串恢复为未命名）"""
    err = _assert_session_owner(request, session_id)
    if err:
        raise HTTPException(status_code=404 if err == "会话不存在" else 403, detail=err)
    try:
        if len(title) > 100:
            raise HTTPException(status_code=400, detail="会话标题过长（上限 100 字符）")
        ok = gov_agent.conversation_manager.rename_session(session_id, title)
        if not ok:
            raise HTTPException(status_code=404, detail="会话不存在")
        return {"success": True, "session_id": session_id, "title": title.strip() or None}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/agent/recall_preview")
async def recall_preview(request: Request, session_id: str, message_id: int):
    """撤回确认预览：返回撤回该消息时会删除哪些内容（含连带消息与涉及的文件/图片附件）。

    撤回语义为「删除 message_id 及之后所有消息」，此接口据实列出影响面，
    供前端弹确认框展示（仿 agent 的"执行前告知影响面"体验）。
    """
    err = _assert_session_owner(request, session_id)
    if err:
        raise HTTPException(status_code=404 if err == "会话不存在" else 403, detail=err)
    try:
        from storage import get_storage
        storage = get_storage()
        all_msgs = storage.get_history(session_id)
        doomed = [m for m in all_msgs if int(m.get("id")) >= int(message_id)]
        # 目标消息：语义上取待删除集合的第一条（即被点名的那条）
        target_msg = doomed[0] if doomed else None

        affected_files = []
        file_count = 0
        image_count = 0
        previews = []
        for m in doomed:
            mtype = m.get("type") or "text"
            previews.append({
                "id": m.get("id"),
                "role": m.get("role"),
                "type": mtype,
                "content": (m.get("content") or ""),
            })
            if mtype in ("file", "image"):
                # 文件名内嵌于 content（"[文件/图片上传] name"），一并作为"涉及文件"列出
                affected_files.append({
                    "type": mtype,
                    "name": (m.get("content") or "").strip(),
                })
                if mtype == "file":
                    file_count += 1
                else:
                    image_count += 1

        return {
            "success": True,
            "target_message": target_msg,
            "deleted_count": len(doomed),
            "deleted_messages": previews,
            "affected_files": affected_files,
            "file_count": file_count,
            "image_count": image_count,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/agent/recall_messages")
async def recall_messages(request: Request, session_id: str, message_id: int):
    """撤回/编辑消息：删除指定消息及之后的所有消息"""
    err = _assert_session_owner(request, session_id)
    if err:
        raise HTTPException(status_code=404 if err == "会话不存在" else 403, detail=err)
    try:
        from storage import get_storage
        storage = get_storage()
        deleted = storage.truncate_messages_from(session_id, message_id)
        history = storage.get_history(session_id)
        return {
            "success": True,
            "deleted_count": deleted,
            "remaining_messages": len(history),
            "messages": history
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/agent/delete_message")
async def delete_message(request: Request, session_id: str, message_id: int):
    """仅删除单条消息（不影响该条之前/之后的其它消息），与撤回（删该条及之后）区分"""
    err = _assert_session_owner(request, session_id)
    if err:
        raise HTTPException(status_code=404 if err == "会话不存在" else 403, detail=err)
    try:
        from storage import get_storage
        storage = get_storage()
        deleted = storage.delete_message(session_id, message_id)
        history = storage.get_history(session_id)
        return {
            "success": True,
            "deleted_count": deleted,
            "remaining_messages": len(history),
            "messages": history
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/agent/sessions")
async def list_sessions(request: Request):
    # 账户会话隔离：仅返回当前登录用户自己的会话
    identity = current_identity(request.headers.get("X-Auth-Token")) or {}
    user_id = identity.get("username") or None
    try:
        result = gov_agent.list_sessions(user_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


