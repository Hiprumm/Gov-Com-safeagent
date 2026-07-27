import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import Dict, Any, List
from models.state import AgentState
from models.schemas import RiskLevel, DetectionResult, ToolRiskResult
from security.input_detector import InputDetectionService
from security.tool_risk_evaluator import ToolRiskEvaluator
from security.approval_engine import ApprovalEngine
from audit.audit_logger import AuditLogger


class SecurityLayer:
    def __init__(self):
        self.input_detector = InputDetectionService()
        self.tool_evaluator = ToolRiskEvaluator()
        self.approval_engine = ApprovalEngine()
        self.audit_logger = AuditLogger()

    def detect_input(self, state: AgentState) -> AgentState:
        user_input = state["user_input"]
        input_source = state["input_source"]
        
        detection_result = self.input_detector.detect_single_input(user_input, input_source)
        
        self.audit_logger.create_log(
            user_id="user",
            user_role="user",
            agent_id="gov_agent",
            action_type="input_detection",
            action_details={"input": user_input[:100], "source": input_source},
            risk_level=detection_result.risk_level,
            detection_result=detection_result,
            is_blocked=detection_result.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL],
            blocking_reason=f"检测到{detection_result.risk_level.value}风险" if detection_result.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL] else None
        )
        
        return {
            **state,
            "detection_results": [detection_result],
            "risk_level": detection_result.risk_level,
            "can_proceed": detection_result.risk_level not in [RiskLevel.HIGH, RiskLevel.CRITICAL],
            "current_step": "input_detection_completed",
        }

    def evaluate_tool_call(self, state: AgentState) -> AgentState:
        tool_calls = state["tool_calls"]
        risk_results = []
        approval_requests = []
        
        for tool_call in tool_calls:
            tool_name = tool_call.get("name", "")
            tool_args = tool_call.get("args", {})
            
            from models.schemas import ToolCallRequest
            request = ToolCallRequest(
                tool_name=tool_name,
                tool_args=tool_args,
                user_role="user",
                agent_id="gov_agent",
                context=state.get("user_input", "")
            )
            
            risk_result = self.tool_evaluator.evaluate(request)
            risk_results.append(risk_result)
            
            self.audit_logger.create_log(
                user_id="user",
                user_role="user",
                agent_id="gov_agent",
                action_type="tool_risk_evaluation",
                action_details={"tool_name": tool_name, "tool_args": tool_args},
                risk_level=risk_result.risk_level,
                tool_call_result=risk_result,
                approval_status="pending" if risk_result.requires_approval else "auto_approved",
                is_blocked=risk_result.risk_level == RiskLevel.CRITICAL,
            )
            
            if risk_result.requires_approval:
                approval_request = self.approval_engine.create_request(
                    user_id="user",
                    user_role="user",
                    agent_id="gov_agent",
                    action_type=f"tool_call_{tool_name}",
                    action_details=tool_args,
                    risk_level=risk_result.risk_level
                )
                approval_requests.append(approval_request.dict())
        
        max_risk = max(risk_results, key=lambda r: r.risk_level.value).risk_level if risk_results else RiskLevel.NONE
        
        return {
            **state,
            "tool_risk_results": risk_results,
            "approval_requests": approval_requests,
            "risk_level": max_risk,
            "can_proceed": max_risk not in [RiskLevel.HIGH, RiskLevel.CRITICAL],
            "current_step": "tool_evaluation_completed",
        }

    def check_approval(self, state: AgentState) -> AgentState:
        approval_requests = state["approval_requests"]
        approval_status = {}
        
        for request in approval_requests:
            request_id = request.get("request_id", "")
            request_data = self.approval_engine.get_request(request_id)
            
            if request_data and request_data.status == "approved":
                approval_status[request_id] = "approved"
            elif request_data and request_data.status == "auto_approved":
                approval_status[request_id] = "auto_approved"
            else:
                approval_status[request_id] = "pending"
        
        all_approved = all(status in ["approved", "auto_approved"] for status in approval_status.values())
        
        return {
            **state,
            "approval_status": approval_status,
            "can_proceed": all_approved,
            "current_step": "approval_check_completed",
        }