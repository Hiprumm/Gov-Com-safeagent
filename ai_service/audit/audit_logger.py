import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import uuid
from datetime import datetime
from typing import Dict, Any, Optional, List
from models.schemas import AuditLog, RiskLevel, DetectionResult, ToolRiskResult, PluginScanResult
from storage import get_storage


class AuditLogger:
    """审计日志记录器，后端使用 SQLite 持久化存储"""

    def __init__(self):
        self.storage = get_storage()

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

        self.storage.save_audit_log({
            "id": log_id,
            "timestamp": log.timestamp.isoformat(),
            "user_id": user_id,
            "user_role": user_role,
            "agent_id": agent_id,
            "action_type": action_type,
            "action_details": action_details,
            "risk_level": risk_level.value if isinstance(risk_level, RiskLevel) else str(risk_level),
            "detection_result": detection_result.model_dump() if detection_result else {},
            "tool_call_result": tool_call_result.model_dump() if tool_call_result else {},
            "approval_status": approval_status or "",
            "is_blocked": is_blocked,
            "blocking_reason": blocking_reason or "",
        })
        
        return log

    def get_log(self, log_id: str) -> Optional[AuditLog]:
        data = self.storage.get_audit_log_by_id(log_id)
        return self._dict_to_log(data) if data else None

    def get_logs_by_user(self, user_id: str) -> List[AuditLog]:
        results = self.storage.search_audit_logs({"user_id": user_id}, limit=1000)
        return [self._dict_to_log(d) for d in results]

    def get_logs_by_agent(self, agent_id: str) -> List[AuditLog]:
        results = self.storage.search_audit_logs({"agent_id": agent_id}, limit=1000)
        return [self._dict_to_log(d) for d in results]

    def get_recent_logs(self, limit: int = 100) -> List[AuditLog]:
        results = self.storage.get_audit_logs_recent(limit=limit)
        return [self._dict_to_log(d) for d in results]

    def search_logs(self, user_id: Optional[str] = None,
                    agent_id: Optional[str] = None,
                    risk_level: Optional[RiskLevel] = None,
                    action_type: Optional[str] = None,
                    start_time: Optional[datetime] = None,
                    end_time: Optional[datetime] = None,
                    is_blocked: Optional[bool] = None) -> List[AuditLog]:
        
        filters = {}
        if user_id:
            filters["user_id"] = user_id
        if agent_id:
            filters["agent_id"] = agent_id
        if risk_level:
            filters["risk_level"] = risk_level.value
        if action_type:
            filters["action_type"] = action_type
        if is_blocked is not None:
            filters["is_blocked"] = is_blocked

        results = self.storage.search_audit_logs(filters, limit=1000)

        # 时间过滤在 Python 中完成（start_time/end_time 暂不入库）
        logs = []
        for data in results:
            log = self._dict_to_log(data)
            if start_time and log.timestamp < start_time:
                continue
            if end_time and log.timestamp > end_time:
                continue
            logs.append(log)

        logs.sort(key=lambda x: x.timestamp, reverse=True)
        return logs

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
            if hasattr(log.risk_level, 'value'):
                export_lines.append(f"风险等级: {log.risk_level.value}")
            else:
                export_lines.append(f"风险等级: {log.risk_level}")
            export_lines.append(f"是否阻断: {'是' if log.is_blocked else '否'}")
            if log.blocking_reason:
                export_lines.append(f"阻断原因: {log.blocking_reason}")
            if log.approval_status:
                export_lines.append(f"审批状态: {log.approval_status}")
        
        export_lines.append("\n" + "=" * 80)
        export_lines.append("报告结束")
        
        return "\n".join(export_lines)

    @staticmethod
    def _dict_to_log(data: Dict[str, Any]) -> AuditLog:
        try:
            log = AuditLog(
                log_id=data.get("log_id", ""),
                timestamp=datetime.fromisoformat(data.get("timestamp", "")) if data.get("timestamp") else datetime.now(),
                user_id=data.get("user_id", ""),
                user_role=data.get("user_role", "user"),
                agent_id=data.get("agent_id", ""),
                action_type=data.get("action_type", ""),
                action_details=data.get("action_details", {}) or {},
                risk_level=RiskLevel(data.get("risk_level", "none")),
                approval_status=data.get("approval_status"),
                is_blocked=data.get("is_blocked", False),
                blocking_reason=data.get("blocking_reason"),
            )
            return log
        except Exception:
            return AuditLog(
                log_id=data.get("log_id", "") or str(uuid.uuid4()),
                timestamp=datetime.now(),
                user_id=data.get("user_id", ""),
                agent_id=data.get("agent_id", ""),
                action_type=data.get("action_type", ""),
            )
