import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import Dict, Any, List
from models.state import AgentState
from models.schemas import RiskLevel, DetectionResult, ToolRiskResult
from security.input_detector import InputDetectionService
from security.tool_risk_evaluator import ToolRiskEvaluator
from security.approval_engine import ApprovalEngine
from security.chain_analyzer import ChainAnalyzer, ChainAlert
from security.cross_source_correlator import get_cross_source_correlator
from audit.audit_logger import AuditLogger


class SecurityLayer:
    def __init__(self):
        self.input_detector = InputDetectionService()
        self.tool_evaluator = ToolRiskEvaluator()
        self.approval_engine = ApprovalEngine()
        self.audit_logger = AuditLogger()
        self.chain_analyzer = ChainAnalyzer()
        self.cross_source_correlator = get_cross_source_correlator()

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

        # 跨来源关联分析：记录事件并检测复合攻击模式
        session_id = state.get("session_id", "unknown")
        if detection_result.risk_level != RiskLevel.NONE:
            correlated_threats = self.cross_source_correlator.record_event(
                session_id=session_id,
                source=input_source,
                risk_level=detection_result.risk_level.value,
                attack_type=detection_result.attack_type.value if detection_result.attack_type else None,
                confidence=detection_result.confidence,
                content_preview=user_input[:200],
                evidence=detection_result.evidence[:5] if detection_result.evidence else [],
            )
            if correlated_threats:
                for threat in correlated_threats:
                    self.audit_logger.create_log(
                        user_id="user",
                        user_role="user",
                        agent_id="gov_agent",
                        action_type="cross_source_correlation",
                        action_details={
                            "pattern": threat.pattern.value,
                            "severity": threat.severity,
                            "sources": threat.involved_sources,
                            "attack_chain": threat.attack_chain,
                        },
                        risk_level=threat.severity,
                        is_blocked=threat.severity == "critical",
                        blocking_reason=f"检测到跨来源复合攻击: {threat.pattern.value}",
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
        
        # 链路检测: 记录每次工具调用并检查异常行为链
        session_id = state.get("session_id", "default")
        chain_alerts = []
        for tool_call in tool_calls:
            tool_name = tool_call.get("name", "")
            chain_alert = self.chain_analyzer.record_call(
                session_id=session_id,
                tool_name=tool_name,
                params=tool_call.get("args", {}),
                risk_level=next(
                    (r.risk_level for r in risk_results
                     if f"tool_call_{r.tool_name}" == f"tool_call_{tool_name}"
                     or r.tool_name == tool_name),
                    RiskLevel.NONE
                )
            )
            if chain_alert:
                chain_alerts.append(chain_alert)

        # 链路告警升级风险等级
        chain_risk = RiskLevel.NONE
        if chain_alerts:
            # 取最高风险等级的告警
            highest_chain_alert = max(chain_alerts, key=lambda a: a.risk_level.value)
            chain_risk = highest_chain_alert.risk_level

            # 记录链路告警到审计日志
            self.audit_logger.create_log(
                user_id="user",
                user_role="user",
                agent_id="gov_agent",
                action_type="chain_detection",
                action_details={
                    "pattern": highest_chain_alert.pattern.value,
                    "description": highest_chain_alert.description,
                    "matched_tools": [r.tool_name for r in highest_chain_alert.matched_steps],
                },
                risk_level=chain_risk,
                is_blocked=chain_risk == RiskLevel.CRITICAL,
                blocking_reason=highest_chain_alert.description if chain_risk == RiskLevel.CRITICAL else None,
            )

        # 最终风险: 单次评估 vs 链路检测 取最高
        final_risk = max_risk if max_risk.value >= chain_risk.value else chain_risk

        return {
            **state,
            "tool_risk_results": risk_results,
            "approval_requests": approval_requests,
            "risk_level": final_risk,
            "chain_alerts": [a.__dict__ for a in chain_alerts] if chain_alerts else [],
            "can_proceed": final_risk not in [RiskLevel.HIGH, RiskLevel.CRITICAL],
            "current_step": "tool_evaluation_completed",
        }

    def check_approval(self, state: AgentState) -> AgentState:
        """审批检查: 轮询等待最多30秒,超时则拒绝"""
        import time
        approval_requests = state["approval_requests"]
        approval_status = {}
        
        max_wait = 30  # 最大等待秒数
        poll_interval = 2  # 轮询间隔
        waited = 0

        for request in approval_requests:
            request_id = request.get("request_id", "")
            # 从数据库实时查状态
            while waited < max_wait:
                request_data = self.approval_engine.get_request(request_id)
                if request_data and request_data.status == "approved":
                    approval_status[request_id] = "approved"
                    break
                elif request_data and request_data.status == "rejected":
                    approval_status[request_id] = "rejected"
                    break
                elif request_data and request_data.status == "auto_approved":
                    approval_status[request_id] = "auto_approved"
                    break
                # 如果风险低,自动审批通过(无需等待人工)
                risk = request.get("risk_level", "none")
                if risk in ["none", "low"]:
                    self.approval_engine.approve_request(request_id, "system", "auto: low risk")
                    approval_status[request_id] = "auto_approved"
                    break
                # 轮询等待
                time.sleep(poll_interval)
                waited += poll_interval
            else:
                # 超时: 拒绝
                approval_status[request_id] = "timeout"
                self.approval_engine.reject_request(request_id, "system", "审批超时自动拒绝")

        all_approved = all(status in ["approved", "auto_approved"] for status in approval_status.values())

        return {
            **state,
            "approval_status": approval_status,
            "can_proceed": all_approved,
            "current_step": "approval_check_completed",
        }