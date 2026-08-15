import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import TypedDict, List, Optional, Dict, Any
from models.schemas import DetectionResult, ToolRiskResult, RiskLevel


class AgentState(TypedDict):
    user_input: str
    input_source: str
    session_id: Optional[str]
    detection_results: List[DetectionResult]
    risk_level: RiskLevel
    risk_summary: Optional[Dict[str, Any]]
    can_proceed: bool
    tool_calls: List[Dict[str, Any]]
    tool_risk_results: List[ToolRiskResult]
    tool_execution_results: List[Dict[str, Any]]
    approval_requests: List[Dict[str, Any]]
    approval_status: Dict[str, str]
    plugin_scan_results: List[Dict[str, Any]]
    conversation_history: List[Dict[str, str]]
    current_step: str
    final_response: Optional[str]
    audit_logs: List[Dict[str, Any]]
    llm_response: Optional[str]
    guard_results: List[Dict[str, Any]]
    runtime_trace: List[Dict[str, Any]]
    anomaly_alerts: List[Dict[str, Any]]
    # T4: ReAct 循环控制
    react_iteration: int
    react_max_iterations: int
    should_continue_react: bool
    # T5 合规：AIGC 内容标识元数据
    aigc_metadata: Optional[Dict[str, Any]]
