import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import uuid
from datetime import datetime
from typing import Dict, Any, Optional, List
from models.schemas import AuditLog, RiskLevel, DetectionResult, ToolRiskResult, PluginScanResult


class AuditLogger:
    def __init__(self):
        self.logs: Dict[str, AuditLog] = {}
        self.logs_by_user: Dict[str, List[AuditLog]] = {}
        self.logs_by_agent: Dict[str, List[AuditLog]] = {}
        self.logs_by_time: List[AuditLog] = []

    def create_log(self, user_id: str, user_role: str, agent_id: str,
                   action_type: str, action_details: Dict[str, Any] = {},
                   risk_level: RiskLevel = RiskLevel.NONE,
                   detection_result: Optional[DetectionResult] = None,
                   tool_call_result: Optional[ToolRiskResult] = None,
                   plugin_scan_result: Optional[PluginScanResult] = None,
                   approval_status: Optional[str] = None,
                   is_blocked: bool = False,
                   blocking_reason: Optional[str] = None) -> AuditLog:
        
        log_id = str(uuid.uuid4())
        
        log = AuditLog(
            log_id=log_id,
            timestamp=datetime.now(),
            user_id=user_id,
            user_role=user_role,
            agent_id=agent_id,
            action_type=action_type,
            action_details=action_details,
            risk_level=risk_level,
            detection_result=detection_result,
            tool_call_result=tool_call_result,
            plugin_scan_result=plugin_scan_result,
            approval_status=approval_status,
            is_blocked=is_blocked,
            blocking_reason=blocking_reason
        )
        
        self.logs[log_id] = log
        
        if user_id not in self.logs_by_user:
            self.logs_by_user[user_id] = []
        self.logs_by_user[user_id].append(log)
        
        if agent_id not in self.logs_by_agent:
            self.logs_by_agent[agent_id] = []
        self.logs_by_agent[agent_id].append(log)
        
        self.logs_by_time.append(log)
        self.logs_by_time.sort(key=lambda x: x.timestamp, reverse=True)
        
        return log

    def get_log(self, log_id: str) -> Optional[AuditLog]:
        return self.logs.get(log_id)

    def get_logs_by_user(self, user_id: str) -> List[AuditLog]:
        return self.logs_by_user.get(user_id, [])

    def get_logs_by_agent(self, agent_id: str) -> List[AuditLog]:
        return self.logs_by_agent.get(agent_id, [])

    def get_recent_logs(self, limit: int = 100) -> List[AuditLog]:
        return self.logs_by_time[:limit]

    def search_logs(self, user_id: Optional[str] = None,
                    agent_id: Optional[str] = None,
                    risk_level: Optional[RiskLevel] = None,
                    action_type: Optional[str] = None,
                    start_time: Optional[datetime] = None,
                    end_time: Optional[datetime] = None,
                    is_blocked: Optional[bool] = None) -> List[AuditLog]:
        
        results = []
        
        for log in self.logs.values():
            if user_id and log.user_id != user_id:
                continue
            if agent_id and log.agent_id != agent_id:
                continue
            if risk_level and log.risk_level != risk_level:
                continue
            if action_type and log.action_type != action_type:
                continue
            if start_time and log.timestamp < start_time:
                continue
            if end_time and log.timestamp > end_time:
                continue
            if is_blocked is not None and log.is_blocked != is_blocked:
                continue
            
            results.append(log)
        
        results.sort(key=lambda x: x.timestamp, reverse=True)
        return results

    def export_logs(self, logs: List[AuditLog]) -> str:
        export_lines = []
        export_lines.append("=" * 80)
        export_lines.append("政企大模型智能体安全审计报告")
        export_lines.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        export_lines.append(f"记录总数: {len(logs)}")
        export_lines.append("=" * 80)
        
        for i, log in enumerate(logs, 1):
            export_lines.append(f"\n--- 记录 #{i} ---")
            export_lines.append(f"日志ID: {log.log_id}")
            export_lines.append(f"时间: {log.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
            export_lines.append(f"用户ID: {log.user_id}")
            export_lines.append(f"用户角色: {log.user_role}")
            export_lines.append(f"智能体ID: {log.agent_id}")
            export_lines.append(f"操作类型: {log.action_type}")
            export_lines.append(f"风险等级: {log.risk_level.value}")
            export_lines.append(f"是否阻断: {'是' if log.is_blocked else '否'}")
            if log.blocking_reason:
                export_lines.append(f"阻断原因: {log.blocking_reason}")
            if log.approval_status:
                export_lines.append(f"审批状态: {log.approval_status}")
        
        export_lines.append("\n" + "=" * 80)
        export_lines.append("报告结束")
        
        return "\n".join(export_lines)