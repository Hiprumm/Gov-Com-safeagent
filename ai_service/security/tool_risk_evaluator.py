import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import re
from typing import Dict, Any, List
from models.schemas import RiskLevel, ToolRiskResult, ToolCallRequest


class ToolRiskEvaluator:
    def __init__(self):
        self.high_risk_tools = {
            "system_command": ["exec", "run", "shell", "command", "terminal"],
            "file_write": ["write_file", "save_file", "create_file", "modify_file", "delete_file"],
            "database_write": ["insert", "update", "delete", "drop", "truncate"],
            "network_access": ["curl", "wget", "request", "http", "api_call"],
            "privileged_access": ["admin", "root", "sudo", "su", "superuser"],
        }
        
        self.medium_risk_tools = {
            "file_read": ["read_file", "open_file", "view_file", "list_dir"],
            "database_read": ["select", "query", "search", "lookup"],
            "data_export": ["export", "download", "backup", "extract"],
            "internal_api": ["intranet", "internal", "private_api"],
        }
        
        self.low_risk_tools = {
            "information": ["get_info", "query_status", "help", "search_knowledge"],
            "calculation": ["calculate", "compute", "sum", "analyze"],
            "formatting": ["format", "convert", "transform", "parse"],
            "utility": ["log", "trace", "debug", "monitor"],
        }
        
        self.sensitive_params = {
            "file_path": [r"\.\./", r"\.\.\\", r"/etc/", r"C:\\", r"/root/"],
            "url": [r"127\.0\.0\.1", r"localhost", r"192\.168\.", r"10\.", r"172\.(1[6-9]|2[0-9]|3[0-1])\."],
            "command": [r"rm -rf", r"del /s", r"format", r"shutdown"],
            "sql": [r"DROP", r"DELETE", r"INSERT", r"UPDATE", r"--", r";"],
            "credentials": ["password", "secret", "token", "key", "api_key", "secret_key"],
        }
        
        self.role_permissions = {
            "admin": {"high_risk": True, "medium_risk": True, "low_risk": True},
            "manager": {"high_risk": False, "medium_risk": True, "low_risk": True},
            "user": {"high_risk": False, "medium_risk": False, "low_risk": True},
            "guest": {"high_risk": False, "medium_risk": False, "low_risk": True},
        }

    def classify_tool(self, tool_name: str) -> str:
        tool_lower = tool_name.lower()
        
        if "search_knowledge" in tool_lower:
            return "low"
        
        for risk_level, tools in self.high_risk_tools.items():
            for keyword in tools:
                if keyword in tool_lower:
                    return "high"
        
        for risk_level, tools in self.medium_risk_tools.items():
            for keyword in tools:
                if keyword in tool_lower:
                    return "medium"
        
        for risk_level, tools in self.low_risk_tools.items():
            for keyword in tools:
                if keyword in tool_lower:
                    return "low"
        
        return "unknown"

    def evaluate_params(self, tool_args: Dict[str, Any]) -> List[str]:
        risk_details = []
        
        for param_name, patterns in self.sensitive_params.items():
            for key, value in tool_args.items():
                if param_name.lower() in key.lower():
                    value_str = str(value).lower()
                    for pattern in patterns:
                        if re.search(pattern, value_str, re.IGNORECASE):
                            risk_details.append(f"参数 [{key}] 包含敏感内容: {value_str[:50]}")
        
        return risk_details

    def check_role_permission(self, user_role: str, tool_risk_level: str) -> bool:
        permissions = self.role_permissions.get(user_role, self.role_permissions["guest"])
        return permissions.get(f"{tool_risk_level}_risk", False)

    def evaluate(self, request: ToolCallRequest) -> ToolRiskResult:
        tool_name = request.tool_name
        tool_args = request.tool_args
        user_role = request.user_role
        
        tool_risk_level = self.classify_tool(tool_name)
        param_risk_details = self.evaluate_params(tool_args)
        has_permission = self.check_role_permission(user_role, tool_risk_level)
        
        risk_score = 0.0
        risk_level = RiskLevel.NONE
        requires_approval = False
        approval_level = None
        risk_details = []
        
        if tool_risk_level == "high":
            risk_score = 0.8
            risk_level = RiskLevel.HIGH
            risk_details.append(f"工具 [{tool_name}] 属于高风险操作")
            requires_approval = not has_permission
            approval_level = "manager" if not has_permission else None
        elif tool_risk_level == "medium":
            risk_score = 0.5
            risk_level = RiskLevel.MEDIUM
            risk_details.append(f"工具 [{tool_name}] 属于中风险操作")
            requires_approval = not has_permission
            approval_level = "supervisor" if not has_permission else None
        elif tool_risk_level == "low":
            risk_score = 0.1
            risk_level = RiskLevel.LOW
        else:
            risk_score = 0.3
            risk_level = RiskLevel.MEDIUM
            risk_details.append(f"工具 [{tool_name}] 风险等级未知")
        
        if param_risk_details:
            risk_score = min(1.0, risk_score + 0.3)
            risk_level = RiskLevel.CRITICAL
            risk_details.extend(param_risk_details)
        
        if not has_permission:
            risk_score = min(1.0, risk_score + 0.2)
            risk_details.append(f"用户角色 [{user_role}] 无权限执行此操作")
        
        if risk_score >= 0.85:
            risk_level = RiskLevel.CRITICAL
        elif risk_score >= 0.6:
            risk_level = RiskLevel.HIGH
        elif risk_score >= 0.3:
            risk_level = RiskLevel.MEDIUM
        elif risk_score > 0:
            risk_level = RiskLevel.LOW
        
        if risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            requires_approval = True
            approval_level = "admin"
        
        return ToolRiskResult(
            risk_level=risk_level,
            risk_score=round(risk_score, 2),
            risk_details=risk_details,
            requires_approval=requires_approval,
            approval_level=approval_level
        )