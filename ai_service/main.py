import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
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
from plugins.plugin_scanner import PluginScanner
from audit.audit_logger import AuditLogger
from audit.evaluation_metrics import EvaluationMetricsCalculator
from gov_agent_graph.gov_agent import GovAgent
from config import settings

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="面向政企场景的大模型智能体安全关键技术研究 - FastAPI AI安全核心服务"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

input_detector = InputDetectionService()
tool_evaluator = ToolRiskEvaluator()
approval_engine = ApprovalEngine()
plugin_scanner = PluginScanner()
audit_logger = AuditLogger()
metrics_calculator = EvaluationMetricsCalculator()
gov_agent = GovAgent()


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


@app.post("/api/security/detect_single", response_model=DetectionResult)
async def detect_single(text: str, source: str = "user_input"):
    try:
        result = input_detector.detect_single_input(text, source)
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


@app.post("/api/security/plugin_scan", response_model=PluginScanResult)
async def scan_plugin(request: PluginScanRequest):
    try:
        result = plugin_scanner.scan(request)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)