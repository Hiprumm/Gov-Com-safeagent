import sys
import os
import time
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from typing import List, Dict, Any, Optional
from datetime import datetime

from models.schemas import (
    DetectionResult, BatchDetectionRequest, BatchDetectionResponse,
    FileDetectionRequest, FileUploadRequest,
    ToolCallRequest, ToolRiskResult,
    PluginScanRequest, PluginScanResult,
    AuditLog, EvaluationMetrics,
    ApprovalRequest, ApprovalResponse,
    RiskLevel
)

from security.input_detector import InputDetectionService
from security.tool_risk_evaluator import ToolRiskEvaluator
from security.approval_engine import ApprovalEngine
from security.kb_poisoning_detector import KBPoisoningDetector
from security.session_risk_accumulator import SessionRiskAccumulator
from security.adversarial_mutator import BypassTester
from security.cross_source_correlator import CrossSourceCorrelator, get_cross_source_correlator
from plugins.plugin_scanner import PluginScanner
from audit.audit_logger import AuditLogger
from audit.evaluation_metrics import EvaluationMetricsCalculator
from gov_agent_graph.gov_agent import GovAgent
from websocket.manager import ws_manager, handle_ws_events, push_approval_update, push_risk_alert
from config import settings

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="面向政企场景的大模型智能体安全关键技术研究 - FastAPI AI安全核心服务"
)

# ======== CORS ========
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in settings.ALLOWED_ORIGINS.split(",") if o.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ======== 基本 API Key 鉴权 (公网预览用) ========
_SKIP_AUTH_PATHS = {"/", "/api/health", "/docs", "/openapi.json", "/redoc"}

if settings.AUTH_ENABLED and settings.AUTH_API_KEY:
    @app.middleware("http")
    async def api_key_auth_middleware(request: Request, call_next):
        if request.url.path in _SKIP_AUTH_PATHS or request.url.path.startswith("/docs"):
            return await call_next(request)
        if request.headers.get("X-API-Key") != settings.AUTH_API_KEY:
            return JSONResponse(
                status_code=401,
                content={"detail": "Unauthorized: Missing or invalid X-API-Key header"}
            )
        return await call_next(request)

# ======== 简单限流 (滑动窗口) ========
_rate_limit_store: Dict[str, list] = defaultdict(list)

if settings.RATE_LIMIT_ENABLED:
    @app.middleware("http")
    async def rate_limit_middleware(request: Request, call_next):
        client_ip = request.client.host if request.client else "unknown"
        now = time.time()
        window = settings.RATE_LIMIT_WINDOW
        max_req = settings.RATE_LIMIT_REQUESTS
        _rate_limit_store[client_ip] = [t for t in _rate_limit_store[client_ip] if now - t < window]
        if len(_rate_limit_store[client_ip]) >= max_req:
            return JSONResponse(status_code=429, content={"detail": "Too Many Requests"})
        _rate_limit_store[client_ip].append(now)
        return await call_next(request)

# ======== 请求体大小限制 ========
_MAX_BODY = settings.MAX_REQUEST_SIZE_MB * 1024 * 1024

@app.middleware("http")
async def request_size_limit_middleware(request: Request, call_next):
    if request.headers.get("content-length"):
        content_length = int(request.headers["content-length"])
        if content_length > _MAX_BODY:
            return JSONResponse(
                status_code=413,
                content={"detail": f"Request body too large. Max {settings.MAX_REQUEST_SIZE_MB}MB"}
            )
    return await call_next(request)

input_detector = InputDetectionService()
tool_evaluator = ToolRiskEvaluator()
approval_engine = ApprovalEngine()
kb_poisoning_detector = KBPoisoningDetector()
session_risk_accumulator = SessionRiskAccumulator()
cross_source_correlator = get_cross_source_correlator()
# BypassTester 用 input_detector 的 detect_single_input 作为检测函数
bypass_tester = BypassTester(
    detector_func=lambda text, src: input_detector.detect_single_input(text, src)
)
plugin_scanner = PluginScanner()
audit_logger = AuditLogger()
metrics_calculator = EvaluationMetricsCalculator()
gov_agent = GovAgent()


# ======== 启动清理空会话 ========
@app.on_event("startup")
async def startup_cleanup():
    try:
        from storage import get_storage
        storage = get_storage()
        cleaned = storage.cleanup_empty_sessions()
        if cleaned > 0:
            print(f"[STARTUP] 已清理 {cleaned} 个空会话")
    except Exception as e:
        print(f"[STARTUP] 清理空会话时出错: {e}")


@app.get("/")
async def root():
    return {"message": settings.APP_NAME, "version": settings.APP_VERSION}


@app.post("/api/security/detect_input", response_model=BatchDetectionResponse)
async def detect_input(request: BatchDetectionRequest):
    try:
        result = input_detector.batch_detect(request)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/security/detect_single")
async def detect_single(text: str, source: str = "user_input", session_id: Optional[str] = None):
    try:
        result = input_detector.detect_single_input(text, source)

        # 记录到 session 风险累积
        if session_id:
            session_risk_accumulator.record_event(
                session_id=session_id,
                source=source,
                risk_level=result.risk_level if hasattr(result, 'risk_level') else RiskLevel.NONE,
                attack_type=result.attack_type.value if result.attack_type else None,
                confidence=result.confidence,
                details={"text_preview": text[:100]},
            )

        # 记录审计日志
        audit_logger.create_log(
            user_id="anonymous", user_role="user", agent_id="security_panel",
            action_type="input_detection",
            action_details={"source": source, "text_preview": text[:100], "session_id": session_id},
            risk_level=result.risk_level if hasattr(result, 'risk_level') else RiskLevel.NONE,
            detection_result=result,
            is_blocked=result.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL] if hasattr(result, 'risk_level') else False,
        )

        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/security/detect_file")
async def detect_file(request: FileDetectionRequest):
    try:
        from gov_agent_graph.gov_agent import FileProcessor
        
        file_processor = FileProcessor()
        processed = file_processor.process_file(request.file_data, request.file_type, request.filename)
        
        if processed["success"] and processed["content"]:
            result = input_detector.detect_single_input(
                processed["content"],
                source="uploaded_doc"
            )

            # 记录审计日志
            audit_logger.create_log(
                user_id="anonymous", user_role="user", agent_id="security_panel",
                action_type="file_detection",
                action_details={"filename": request.filename, "file_type": request.file_type},
                risk_level=result.risk_level,
                detection_result=result,
                is_blocked=result.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL],
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


@app.post("/api/security/tool_risk", response_model=ToolRiskResult)
async def evaluate_tool_risk(request: ToolCallRequest):
    try:
        result = tool_evaluator.evaluate(request)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/security/approval/create", response_model=ApprovalRequest)
async def create_approval(request: dict):
    try:
        approval_request = approval_engine.create_request(
            user_id=request.get("user_id", "user"),
            user_role=request.get("user_role", "user"),
            agent_id=request.get("agent_id", "gov_agent"),
            action_type=request.get("action_type", ""),
            action_details=request.get("action_details", {}),
            risk_level=RiskLevel(request.get("risk_level", "none"))
        )
        # WebSocket 推送：新审批创建
        import asyncio
        asyncio.create_task(push_approval_update(
            request_id=approval_request.request_id if hasattr(approval_request, 'request_id') else "unknown",
            action="created",
            risk_level=request.get("risk_level", "none"),
            detail={"action_type": request.get("action_type", "")}
        ))
        return approval_request
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/security/approval/approve", response_model=ApprovalResponse)
async def approve_approval(request_id: str, approver_id: str, approver_role: str, comments: Optional[str] = None):
    try:
        result = approval_engine.approve_request(request_id, approver_id, approver_role, comments)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/security/approval/reject", response_model=ApprovalResponse)
async def reject_approval(request_id: str, approver_id: str, comments: Optional[str] = None):
    try:
        result = approval_engine.reject_request(request_id, approver_id, comments)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/security/approval/{request_id}", response_model=ApprovalRequest)
async def get_approval(request_id: str):
    try:
        result = approval_engine.get_request(request_id)
        if not result:
            raise HTTPException(status_code=404, detail="审批请求不存在")
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/security/plugin_scan")
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


@app.get("/api/audit/logs/recent")
async def get_recent_logs(limit: int = 100):
    try:
        logs = audit_logger.get_recent_logs(limit)
        return {"logs": [log.dict() for log in logs]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/audit/logs/{log_id}", response_model=AuditLog)
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


@app.post("/api/audit/logs/search")
async def search_logs(
    user_id: Optional[str] = None,
    agent_id: Optional[str] = None,
    risk_level: Optional[str] = None,
    action_type: Optional[str] = None,
    is_blocked: Optional[bool] = None
):
    try:
        risk_level_enum = RiskLevel(risk_level) if risk_level else None
        logs = audit_logger.search_logs(
            user_id=user_id,
            agent_id=agent_id,
            risk_level=risk_level_enum,
            action_type=action_type,
            is_blocked=is_blocked
        )
        return {"logs": [log.dict() for log in logs]}
    except ValueError:
        raise HTTPException(status_code=400, detail="无效的风险等级")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/audit/export")
async def export_audit_logs(
    format: str = "json",
    risk_level: Optional[str] = None,
    user_id: Optional[str] = None,
    action_type: Optional[str] = None,
    limit: int = 1000,
):
    """
    审计日志导出

    支持 JSON 和 CSV 两种格式。
    可按风险等级、用户、操作类型筛选。

    Query params:
        format: json | csv (default: json)
        risk_level: none | low | medium | high | critical
        user_id: 用户ID过滤
        action_type: 操作类型过滤
        limit: 最大导出数量 (default: 1000)
    """
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


@app.get("/api/audit/stats")
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


@app.post("/api/security/eval_calc", response_model=EvaluationMetrics)
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


@app.post("/api/agent/run")
async def run_agent(user_input: str, input_source: str = "user_input"):
    try:
        result = gov_agent.run(user_input, input_source)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/agent/chat")
async def chat_with_history(user_input: str, session_id: Optional[str] = None, input_source: str = "user_input"):
    try:
        result = gov_agent.run(user_input, input_source, session_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/agent/file_upload")
async def upload_file(request: FileUploadRequest):
    try:
        session_id = request.session_id
        if not session_id:
            session_id = gov_agent.conversation_manager.create_session()
        
        result = gov_agent.process_file_message(session_id, request.file_data, request.file_type, request.filename)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/agent/history")
async def get_conversation_history(session_id: str):
    try:
        result = gov_agent.get_conversation_history(session_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/agent/new_session")
async def create_new_session():
    try:
        result = gov_agent.create_new_session()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/agent/clear_session")
async def clear_conversation(session_id: str):
    try:
        result = gov_agent.clear_conversation(session_id)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/agent/sessions")
async def list_sessions():
    try:
        result = gov_agent.list_sessions()
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION
    }


# ==================== 审批管理 API ====================

@app.get("/api/security/approval/pending")
async def get_pending_approvals():
    """获取所有待审批的请求"""
    try:
        pending = approval_engine.list_pending()
        pending_dicts = [r.dict() for r in pending]
        return {
            "pending": pending_dicts,
            "count": len(pending_dicts),
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/security/approval/approve/{request_id}")
async def approve_request(request_id: str, approver_comment: str = ""):
    """审批通过指定的请求"""
    try:
        approved = approval_engine.approve_request(request_id, "admin", approver_comment)
        if not approved:
            return {
                "success": False,
                "message": f"审批请求 {request_id} 不存在或已处理"
            }
        audit_logger.create_log(
            user_id="admin", user_role="admin", agent_id="security_panel",
            action_type="approval_approved",
            action_details={"request_id": request_id, "comment": approver_comment},
            risk_level=RiskLevel.NONE,
            is_blocked=False,
        )
        # WebSocket 推送：审批通过
        import asyncio
        asyncio.create_task(push_approval_update(
            request_id=request_id, action="approved",
            detail={"comment": approver_comment}
        ))
        return {"success": True, "message": f"请求 {request_id} 已审批通过"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/security/approval/reject/{request_id}")
async def reject_request(request_id: str, reason: str = ""):
    """驳回指定的请求"""
    try:
        rejected = approval_engine.reject_request(request_id, "admin", reason)
        if not rejected:
            return {
                "success": False,
                "message": f"审批请求 {request_id} 不存在或已处理"
            }
        audit_logger.create_log(
            user_id="admin", user_role="admin", agent_id="security_panel",
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


@app.get("/api/security/approval/status/{request_id}")
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

@app.post("/api/security/kb_poisoning/detect_pdf")
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
            is_blocked=result.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL],
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


@app.post("/api/security/kb_poisoning/detect_text")
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

@app.get("/api/security/session_risk/{session_id}")
async def get_session_risk(session_id: str):
    """获取指定 session 的风险累积画像"""
    try:
        profile = session_risk_accumulator.get_session_summary(session_id)
        return {"success": True, "profile": profile}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/security/session_risk")
async def list_all_session_risks():
    """获取所有活跃 session 的风险摘要"""
    try:
        sessions = session_risk_accumulator.get_all_active_sessions()
        return {"success": True, "sessions": sessions, "count": len(sessions)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/security/session_risk/clear/{session_id}")
async def clear_session_risk(session_id: str):
    """清除 session 风险数据"""
    try:
        session_risk_accumulator.clear_session(session_id)
        return {"success": True, "message": f"Session {session_id} 风险数据已清除"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 跨来源关联分析 API ====================

@app.get("/api/security/cross_source/summary/{session_id}")
async def get_cross_source_summary(session_id: str):
    """获取某个 Session 的跨来源关联分析摘要"""
    try:
        summary = cross_source_correlator.get_session_summary(session_id)
        return {"success": True, "data": summary}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/security/cross_source/clear/{session_id}")
async def clear_cross_source(session_id: str):
    """清除某个 Session 的跨来源关联数据"""
    try:
        cross_source_correlator.clear_session(session_id)
        return {"success": True, "message": f"Session {session_id} 关联数据已清除"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ==================== 对抗样本 Bypass 测试 API ====================

@app.post("/api/security/bypass_test")
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


@app.post("/api/security/bypass_batch_test")
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


@app.get("/api/scenarios")
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


@app.get("/api/scenarios/{scenario_id}")
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


@app.post("/api/scenarios/{scenario_id}/run")
async def run_scenario(scenario_id: str):
    """运行指定场景的完整演示流程（含安全检测）"""
    try:
        if not _has_scenario_engine:
            raise HTTPException(status_code=503, detail="场景演示引擎未就绪")
        results = scenario_engine.run_scenario_with_builtin_detector(scenario_id)
        report = scenario_engine.generate_demo_report(scenario_id, results)

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
                "attacks_detected": report.attacks_detected,
                "false_positives": report.false_positives,
                "detection_rate": report.detection_rate,
                "false_positive_rate": report.false_positive_rate,
                "summary": report.summary,
            },
            "results": [{
                "step_id": r.step_id,
                "role": r.role,
                "message": r.message[:100],
                "is_attack": r.is_attack,
                "passed": r.passed,
                "risk_level": r.risk_level,
                "confidence": r.confidence,
                "expected_action": r.expected_action,
            } for r in results],
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scenarios/run_all")
async def run_all_scenarios():
    """运行全部4个场景并返回汇总报告"""
    try:
        if not _has_scenario_engine:
            raise HTTPException(status_code=503, detail="场景演示引擎未就绪")
        all_results = scenario_engine.run_all_scenarios()

        return {
            "success": True,
            "overall": all_results["overall"],
            "scenarios": all_results["scenarios"],
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


@app.post("/api/replay/record")
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


@app.post("/api/replay/{record_id}")
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


@app.post("/api/replay/all")
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


@app.get("/api/replay/records")
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

@app.get("/api/evaluation/report")
async def get_evaluation_report():
    """获取评测报告数据"""
    import json
    report_path = os.path.join(os.path.dirname(__file__), "audit", "evaluation_report.json")
    if os.path.exists(report_path):
        with open(report_path, "r", encoding="utf-8") as f:
            return json.load(f)
    raise HTTPException(status_code=404, detail="评测报告未生成，请先运行评测")


# ==================== WebSocket 实时通信 ====================

@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    """WebSocket 事件通道 — 审批/风险/检测实时推送"""
    await handle_ws_events(websocket)


@app.get("/api/ws/status")
async def ws_status():
    """WebSocket 服务状态"""
    return {
        "active_connections": ws_manager.active_connections,
        "channels": ws_manager.channel_count,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)