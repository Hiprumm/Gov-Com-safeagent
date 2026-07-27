import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import Dict, Any, Optional
from datetime import datetime
from models.schemas import ApprovalRequest, ApprovalResponse, RiskLevel


class ApprovalEngine:
    def __init__(self):
        self.approval_requests: Dict[str, ApprovalRequest] = {}
        
        self.approval_matrix = {
            RiskLevel.LOW: {"auto_approve": True, "required_level": None},
            RiskLevel.MEDIUM: {"auto_approve": False, "required_level": "manager"},
            RiskLevel.HIGH: {"auto_approve": False, "required_level": "admin"},
            RiskLevel.CRITICAL: {"auto_approve": False, "required_level": "super_admin"},
        }

    def create_request(self, user_id: str, user_role: str, agent_id: str, 
                       action_type: str, action_details: Dict[str, Any], 
                       risk_level: RiskLevel) -> ApprovalRequest:
        request_id = f"APPROVE_{user_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
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
        
        self.approval_requests[request_id] = request
        
        if self.approval_matrix[risk_level]["auto_approve"]:
            request.status = "auto_approved"
        
        return request

    def approve_request(self, request_id: str, approver_id: str, 
                        approver_role: str, comments: Optional[str] = None) -> ApprovalResponse:
        request = self.approval_requests.get(request_id)
        
        if not request:
            return ApprovalResponse(request_id=request_id, status="not_found")
        
        if request.status != "pending":
            return ApprovalResponse(request_id=request_id, status=request.status)
        
        required_level = self.approval_matrix[request.risk_level]["required_level"]
        
        role_hierarchy = {
            "guest": 1,
            "user": 2,
            "manager": 3,
            "admin": 4,
            "super_admin": 5,
        }
        
        approver_level = role_hierarchy.get(approver_role, 1)
        required_level_value = role_hierarchy.get(required_level, 1)
        
        if approver_level >= required_level_value:
            request.status = "approved"
            request.approved_by = approver_id
            request.approved_at = datetime.now()
            
            return ApprovalResponse(
                request_id=request_id,
                status="approved",
                approved_by=approver_id,
                approved_at=datetime.now(),
                comments=comments
            )
        else:
            return ApprovalResponse(
                request_id=request_id,
                status="rejected",
                comments=f"审批者角色 [{approver_role}] 权限不足，需要 [{required_level}]"
            )

    def reject_request(self, request_id: str, approver_id: str, 
                       comments: Optional[str] = None) -> ApprovalResponse:
        request = self.approval_requests.get(request_id)
        
        if not request:
            return ApprovalResponse(request_id=request_id, status="not_found")
        
        request.status = "rejected"
        
        return ApprovalResponse(
            request_id=request_id,
            status="rejected",
            approved_by=approver_id,
            approved_at=datetime.now(),
            comments=comments
        )

    def get_request(self, request_id: str) -> Optional[ApprovalRequest]:
        return self.approval_requests.get(request_id)