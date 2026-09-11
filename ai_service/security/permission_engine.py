# -*- coding: utf-8 -*-
"""统一权限决策引擎（RBAC + ABAC 单一事实来源）

设计目标：把此前散落在各处的权限逻辑收敛到一处，避免"前端写死角色菜单 / 端点写死数据收敛 /
审批端点写死角色映射"的三处重复与漂移。所有"能做什么 / 能看哪些模块 / 能看多大范围数据 /
能否审批"的判定，统一由本引擎给出。

三个维度：
- RBAC（角色-权限点）：`has_permission(role, perm)` / `modules_for(role)`；
- ABAC（属性-数据范围）：`data_scope_for(subject)` 依据角色+部门+归属，得出 all / dept / self；
- 审批能力（角色层级）：`approver_role_for(role)` / `can_approve(role, risk)`。

职责分离：admin 管全部；operator 安全运营；auditor 合规审计；manager 部门负责人；user 业务用户。
"""
from typing import Dict, List, Optional, Set

# ------------------------------------------------------------------
# 角色层级（与审批引擎 role_hierarchy 对齐：operator 视为管理层级）
# guest/user < manager(=operator) < admin < super_admin
# ------------------------------------------------------------------
ROLE_LEVELS: Dict[str, int] = {
    "guest": 1,
    "user": 2,
    "manager": 3,
    "operator": 3,      # 安全运维可批中低危（等价 manager 层级）
    "admin": 4,
    "super_admin": 5,
}

# ------------------------------------------------------------------
# 模块（与前端导航 Tab 名称保持一致）
# ------------------------------------------------------------------
MODULES: List[str] = [
    "chat", "dashboard", "runtime", "security", "redteam",
    "tools", "approval", "audit", "policy", "system", "governance",
    "ops",
]

# 模块 → 进入该模块所需的最小权限点
MODULE_PERMISSION: Dict[str, str] = {
    "chat": "chat.use",
    "dashboard": "dashboard.view",
    "runtime": "runtime.view",
    "security": "security.detect",
    "redteam": "redteam.run",
    "tools": "tools.view",
    "approval": "approval.view",
    "audit": "audit.view",
    "policy": "policy.view",
    "system": "system.view",
    "governance": "system.maintain",
    "ops": "system.view",
}

# ------------------------------------------------------------------
# 权限点目录（按模块/动作细分，便于后续做细粒度授权与审计）
# ------------------------------------------------------------------
PERMISSIONS: Set[str] = {
    "chat.use",
    "dashboard.view",
    "runtime.view", "runtime.terminate",
    "security.detect", "security.scan",
    "redteam.run",
    "tools.view", "tools.manage",
    "approval.view", "approval.approve",
    "audit.view", "audit.export",
    "policy.view", "policy.manage",
    "system.view", "system.maintain",
    "admin.manage",              # 后台用户与组织管理
}

# ------------------------------------------------------------------
# 角色 → 权限点（RBAC 矩阵）
# ------------------------------------------------------------------
_DASHBOARD_ALL = {"dashboard.view", "chat.use"}
ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    "admin": set(PERMISSIONS),  # 全部
    "operator": {
        "chat.use", "dashboard.view",
        "runtime.view", "runtime.terminate",
        "security.detect", "security.scan",
        "tools.view", "tools.manage",
        "approval.view", "approval.approve",
        "audit.view",
    },
    "auditor": {
        "chat.use", "dashboard.view",
        "approval.view",
        "audit.view", "audit.export",
    },
    "manager": {
        "chat.use", "dashboard.view",
        "approval.view", "approval.approve",
        "audit.view",
    },
    "user": {
        "chat.use", "dashboard.view",
        "audit.view",
    },
}

# 数据可见范围（ABAC）：all=全平台 / dept=本部门 / self=本人
DATA_SCOPE_BY_ROLE: Dict[str, str] = {
    "admin": "all",
    "operator": "all",
    "auditor": "all",
    "manager": "dept",
    "user": "self",
}

# 角色 → 审批时可代理的审批角色（None 表示无审批权）
APPROVER_ROLE_BY_ROLE: Dict[str, Optional[str]] = {
    "admin": "admin",
    "operator": "manager",
    "manager": "manager",
}

# 风险 → 所需审批者角色（与 approval_engine.approval_matrix 保持一致）
# 说明：critical 由 admin 兜底——系统无可用的 super_admin 账号，要求它会导致极危审批死锁。
REQUIRED_ROLE_BY_RISK: Dict[str, str] = {
    "low": "user",            # 低危自动放行（引擎层 auto_approve）
    "medium": "manager",
    "high": "admin",
    "critical": "admin",
}


def _normalize(role: Optional[str]) -> str:
    return (role or "").strip().lower()


class PermissionEngine:
    """统一权限决策引擎（无状态，可全局单例复用）。"""

    # ---------------- RBAC ----------------
    def permissions_for(self, role: Optional[str]) -> Set[str]:
        return set(ROLE_PERMISSIONS.get(_normalize(role), set()))

    def has_permission(self, role: Optional[str], perm: str) -> bool:
        return perm in self.permissions_for(role)

    def modules_for(self, role: Optional[str]) -> List[str]:
        """该角色可见的模块（导航收敛），保持 MODULES 顺序。"""
        perms = self.permissions_for(role)
        return [m for m in MODULES if MODULE_PERMISSION[m] in perms]

    # ---------------- ABAC：数据范围 ----------------
    def data_scope_for(self, role: Optional[str], authenticated: bool = True) -> str:
        """返回 all / dept / self。

        未认证（内部轮询/访客）为避免误暴露，收敛为 self；已认证按角色矩阵。
        """
        if not authenticated:
            return "self"
        return DATA_SCOPE_BY_ROLE.get(_normalize(role), "self")

    def scope_meta(self, identity: Optional[Dict]) -> Dict:
        """由登录身份生成看板 scope 元信息（供前端标注视角）。"""
        identity = identity or {}
        username = identity.get("username", "")
        role = identity.get("role", "")
        dept = identity.get("department", "")
        display_name = identity.get("display_name", "")
        scope = self.data_scope_for(role, authenticated=bool(username))
        label = ("全平台" if scope == "all"
                 else "仅本人" if scope == "self"
                 else f"本部门 {dept or ''}".strip())
        return {
            "scope": scope,
            "username": username,
            "display_name": display_name,
            "role": role,
            "department": dept,
            "label": label,
            "hint": ("当前展示本账号可权限范围内的数据"
                     if scope in ("dept", "self") else "当前展示全平台数据"),
        }

    def row_visible(self, scope: str, subject: Dict, row: Dict, user_dept_map: Optional[Dict[str, str]] = None) -> bool:
        """ABAC 逐行判定：审计/操作记录对当前主体是否可见。

        subject: {username, department}
        row: 审计/记录原始行（含 user_id / action_details.department）
        user_dept_map: username -> department 反查表（可选，用于把记录归属到部门）
        """
        if scope == "all":
            return True
        row_user = row.get("user_id", "") or ""
        row_dept = (user_dept_map or {}).get(row_user, "")
        if not row_dept:
            ad = row.get("action_details") or {}
            row_dept = ad.get("department", "") if isinstance(ad, dict) else ""
        if scope == "self":
            return bool(row_user) and row_user == subject.get("username", "")
        if scope == "dept":
            d = subject.get("department", "")
            return bool(d) and row_dept == d
        return False

    # ---------------- 审批能力 ----------------
    def level_of(self, role: Optional[str]) -> int:
        return ROLE_LEVELS.get(_normalize(role), 0)

    def approver_role_for(self, role: Optional[str], authenticated: bool = True) -> Optional[str]:
        """当前登录角色发起审批时可使用的审批者角色；无权限返回 None。

        安全优先：未认证一律返回 None（不再回退为 admin）。
        """
        if not authenticated:
            return None
        return APPROVER_ROLE_BY_ROLE.get(_normalize(role))

    def required_role_for_risk(self, risk: Optional[str]) -> str:
        return REQUIRED_ROLE_BY_RISK.get(_normalize(risk), "admin")

    def can_approve(self, role: Optional[str], risk: Optional[str]) -> bool:
        """角色层级是否足以审批某风险等级（用于前置判断与前端展示）。"""
        required = self.required_role_for_risk(risk)
        return self.level_of(role) >= self.level_of(required)

    # ---------------- 汇总（供前端一次性拉取） ----------------
    def describe(self, identity: Optional[Dict]) -> Dict:
        identity = identity or {}
        role = identity.get("role", "")
        perms = sorted(self.permissions_for(role))
        return {
            "role": role,
            "permissions": perms,
            "modules": self.modules_for(role),
            "data_scope": self.data_scope_for(role, authenticated=bool(identity.get("username"))),
            "can_approve_approval": self.has_permission(role, "approval.approve"),
            "is_admin": _normalize(role) == "admin",
        }


_engine: Optional[PermissionEngine] = None


def get_permission_engine() -> PermissionEngine:
    global _engine
    if _engine is None:
        _engine = PermissionEngine()
    return _engine
