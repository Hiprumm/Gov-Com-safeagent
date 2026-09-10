import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import uuid
from typing import Dict, Any, Optional
from datetime import datetime
from models.schemas import ApprovalRequest, ApprovalResponse, RiskLevel
from storage import get_storage


class ApprovalEngine:
    """审批引擎，后端使用 SQLite 持久化存储"""

    def __init__(self):
        self.storage = get_storage()
        
        # 风险 → 所需审批者角色。CRITICAL 由 admin 兜底：
        # 系统不存在 super_admin 账号（后台可创建角色仅 admin/operator/auditor/manager/user），
        # 若要求 super_admin，极危审批单将永远无人可批（审批死锁）。
        self.approval_matrix = {
            RiskLevel.LOW: {"auto_approve": True, "required_level": None},
            RiskLevel.MEDIUM: {"auto_approve": False, "required_level": "manager"},
            RiskLevel.HIGH: {"auto_approve": False, "required_level": "admin"},
            RiskLevel.CRITICAL: {"auto_approve": False, "required_level": "admin"},
        }

    def create_request(self, user_id: str, user_role: str, agent_id: str, 
                       action_type: str, action_details: Dict[str, Any], 
                       risk_level: RiskLevel) -> ApprovalRequest:
        request_id = f"APR_{uuid.uuid4().hex[:12]}"
        
        request = ApprovalRequest(
            request_id=request_id,
            user_id=user_id,
            user_role=user_role,
            agent_id=agent_id,
            action_type=action_type,
            action_details=action_details,
            risk_level=risk_level,
            status="pending"
        )

        if risk_level in self.approval_matrix and self.approval_matrix[risk_level]["auto_approve"]:
            request.status = "auto_approved"

        self.storage.create_approval({
            "request_id": request_id,
            "tool_name": action_type,
            "tool_args": action_details,
            "risk_level": risk_level.value,
            "requester_id": user_id,
            "requester_role": user_role,
            "required_role": self.approval_matrix.get(risk_level, {}).get("required_level", "admin"),
            "status": request.status,
            "reason": "",
            "created_at": datetime.now().isoformat(),
        })

        return request

    def approve_request(self, request_id: str, approver_id: str, 
                        approver_role: str, comments: Optional[str] = None) -> ApprovalResponse:
        data = self.storage.get_approval(request_id)
        
        if not data:
            return ApprovalResponse(request_id=request_id, status="not_found")
        
        status = data.get("status", "pending")
        if status != "pending":
            return ApprovalResponse(request_id=request_id, status=status)
        
        risk_level_str = data.get("risk_level", "low")
        try:
            risk_level = RiskLevel(risk_level_str)
        except ValueError:
            risk_level = RiskLevel.LOW

        required_level = self.approval_matrix.get(risk_level, {}).get("required_level", "admin")
        
        role_hierarchy = {
            "guest": 1,
            "user": 2,
            "manager": 3,
            "operator": 3,   # 安全运维与部门负责人同级（可批中低危）
            "admin": 4,
            "super_admin": 5,
        }
        
        approver_level = role_hierarchy.get(approver_role, 1)
        required_level_value = role_hierarchy.get(required_level, 1)
        
        if approver_level >= required_level_value:
            self.storage.update_approval(
                request_id, "approved",
                approver_id=approver_id,
                approver_role=approver_role,
                reason=comments or ""
            )
            return ApprovalResponse(
                request_id=request_id,
                status="approved",
                approved_by=approver_id,
                approved_at=datetime.now(),
                comments=comments
            )
        else:
            # 权限不足：**不修改审批单状态**（保持 pending），
            # 避免把"待审"误写成"已驳回"导致待办丢失（历史缺陷）
            return ApprovalResponse(
                request_id=request_id,
                status="insufficient_permission",
                comments=f"审批者角色 [{approver_role}] 权限不足，需要 [{required_level}]"
            )

    def reject_request(self, request_id: str, approver_id: str, 
                       comments: Optional[str] = None) -> ApprovalResponse:
        data = self.storage.get_approval(request_id)
        
        if not data:
            return ApprovalResponse(request_id=request_id, status="not_found")
        
        self.storage.update_approval(
            request_id, "rejected",
            approver_id=approver_id,
            reason=comments or ""
        )
        
        return ApprovalResponse(
            request_id=request_id,
            status="rejected",
            approved_by=approver_id,
            approved_at=datetime.now(),
            comments=comments
        )

    def get_request(self, request_id: str) -> Optional[ApprovalRequest]:
        data = self.storage.get_approval(request_id)
        if not data:
            return None
        
        risk_level_str = data.get("risk_level", "low")
        try:
            risk_level = RiskLevel(risk_level_str)
        except ValueError:
            risk_level = RiskLevel.LOW

        return ApprovalRequest(
            request_id=data.get("request_id", ""),
            user_id=data.get("requester_id", ""),
            user_role=data.get("requester_role", "user"),
            agent_id="",
            action_type=data.get("tool_name", ""),
            action_details=data.get("tool_args", {}),
            risk_level=risk_level,
            status=data.get("status", "pending"),
        )

    def list_pending(self) -> list:
        """获取所有待审批请求"""
        rows = self.storage.list_pending_approvals()
        results = []
        for data in rows:
            risk_level_str = data.get("risk_level", "low")
            try:
                risk_level = RiskLevel(risk_level_str)
            except ValueError:
                risk_level = RiskLevel.LOW
            results.append(ApprovalRequest(
                request_id=data.get("request_id", ""),
                user_id=data.get("requester_id", ""),
                user_role=data.get("requester_role", "user"),
                agent_id="",
                action_type=data.get("tool_name", ""),
                action_details=data.get("tool_args", {}),
                risk_level=risk_level,
                status=data.get("status", "pending"),
            ))
        return results
