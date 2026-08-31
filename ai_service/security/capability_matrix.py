"""
能力清单矩阵（方向B-1）— 工具能力的唯一权威定义

捕鼠器思维的核心落地：Agent 的危险能力（文件写入/命令执行/数据外发）不再
"默认全给、调用前检测"，而是显式建模为能力集合（capability set）：

1. TOOL_CAPABILITIES：每个工具需要哪些能力（精确匹配）
2. CAPABILITY_METADATA：能力的风险级别 / 不可逆性 / 是否需要授权
3. ROLE_DEFAULT_GRANTS：角色默认最小权限（user=只读）
4. 未知工具：关键词回退推断（复用 Plan IR 的能力矩阵），推断不出视为高危

配套 B-2 capability_token.py：会话令牌默认只含只读能力，
危险能力必须经审批解锁后才授予（默认 deny）。
"""
from __future__ import annotations

from typing import Dict, FrozenSet, Set

# ==================== 能力元数据 ====================
# cap: (风险级别, 不可逆, 需授权才能获得, 说明)
CAPABILITY_METADATA: Dict[str, Dict] = {
    # ---- 只读能力（默认授予所有角色） ----
    "file_read":       {"risk": "low",      "irreversible": False, "grant_required": False, "desc": "读取文件"},
    "search":          {"risk": "low",      "irreversible": False, "grant_required": False, "desc": "搜索"},
    "knowledge_query": {"risk": "low",      "irreversible": False, "grant_required": False, "desc": "知识库检索"},
    "db_read":         {"risk": "low",      "irreversible": False, "grant_required": False, "desc": "数据库只读查询"},
    # ---- 危险能力（grant_required=True：默认不授予，审批解锁后才发） ----
    "file_write":      {"risk": "high",     "irreversible": True,  "grant_required": True,  "desc": "本地文件写入"},
    "file_delete":     {"risk": "critical", "irreversible": True,  "grant_required": True,  "desc": "文件删除"},
    "db_write":        {"risk": "high",     "irreversible": True,  "grant_required": True,  "desc": "数据库写入"},
    "command_exec":    {"risk": "critical", "irreversible": True,  "grant_required": True,  "desc": "系统命令执行"},
    "code_exec":       {"risk": "critical", "irreversible": True,  "grant_required": True,  "desc": "任意代码执行"},
    "data_transfer":   {"risk": "high",     "irreversible": True,  "grant_required": True,
                        "desc": "数据外发（不可逆：数据一旦外传无法撤回）"},
    "network_access":  {"risk": "high",     "irreversible": True,  "grant_required": True,  "desc": "网络访问/回连"},
    "communication":   {"risk": "medium",   "irreversible": True,  "grant_required": True,  "desc": "通讯外发（邮件/IM）"},
    # ---- 中性能力（跟随工具语义） ----
    "repo_access":     {"risk": "medium",   "irreversible": False, "grant_required": True,  "desc": "代码仓库访问"},
    "web_browse":      {"risk": "medium",   "irreversible": False, "grant_required": True,  "desc": "网页浏览"},
    "web_search":      {"risk": "low",      "irreversible": False, "grant_required": False, "desc": "网页搜索"},
    "api_call":        {"risk": "high",     "irreversible": True,  "grant_required": True,  "desc": "外部 API 调用"},
    "http_request":    {"risk": "high",     "irreversible": True,  "grant_required": True,  "desc": "HTTP 请求"},
    "pr_management":   {"risk": "medium",   "irreversible": True,  "grant_required": True,  "desc": "PR/合并管理"},
    "form_fill":       {"risk": "medium",   "irreversible": True,  "grant_required": True,  "desc": "表单提交"},
    "screenshot":      {"risk": "low",      "irreversible": False, "grant_required": False, "desc": "截屏"},
    "file_transfer":   {"risk": "high",     "irreversible": True,  "grant_required": True,  "desc": "文件传输"},
    "unknown_tool":    {"risk": "critical", "irreversible": True,  "grant_required": True,  "desc": "未登记工具（保守视为高危）"},
}

# ==================== 工具 → 能力集（精确匹配，系统注册工具的权威清单） ====================
TOOL_CAPABILITIES: Dict[str, FrozenSet[str]] = {
    "read_file":        frozenset({"file_read"}),
    "search_knowledge": frozenset({"search", "knowledge_query"}),
    "query_db":         frozenset({"db_read"}),
    "write_file":       frozenset({"file_write"}),
    "execute_command":  frozenset({"command_exec", "file_read", "file_write"}),
    "export_data":      frozenset({"data_transfer", "db_read"}),
    "send_email":       frozenset({"communication", "data_transfer", "network_access"}),
}

# ==================== 角色 → 默认能力集（最小权限） ====================
# admin 用 "*" 通配（全部能力）；user/guest 默认只读 —— 危险能力一律走审批解锁
ROLE_DEFAULT_GRANTS: Dict[str, FrozenSet[str]] = {
    "admin":   frozenset({"*"}),
    "manager": frozenset({"file_read", "search", "knowledge_query", "db_read", "web_search"}),
    "user":    frozenset({"file_read", "search", "knowledge_query", "db_read"}),
    "guest":   frozenset({"search", "knowledge_query"}),
}

# ==================== 未知工具关键词回退（与 Plan IR CAPABILITY_MATRIX 语义一致） ====================
KEYWORD_FALLBACK: Dict[str, FrozenSet[str]] = {
    "git":       frozenset({"file_read", "file_write", "repo_access"}),
    "github":    frozenset({"file_read", "file_write", "repo_access", "pr_management"}),
    "browser":   frozenset({"web_browse", "form_fill", "screenshot", "network_access"}),
    "web":       frozenset({"web_browse", "web_search", "network_access", "data_transfer"}),
    "http":      frozenset({"http_request", "data_transfer", "network_access"}),
    "api":       frozenset({"api_call", "data_transfer", "network_access"}),
    "database":  frozenset({"db_read", "db_write"}),
    "sql":       frozenset({"db_read", "db_write"}),
    "filesystem": frozenset({"file_read", "file_write", "file_delete"}),
    "file":      frozenset({"file_read", "file_write"}),
    "export":    frozenset({"data_transfer", "db_read"}),
    "terminal":  frozenset({"command_exec", "file_read", "file_write"}),
    "shell":     frozenset({"command_exec", "file_read", "file_write"}),
    "exec":      frozenset({"command_exec"}),
    "python":    frozenset({"code_exec", "file_read", "network_access"}),
    "email":     frozenset({"data_transfer", "communication", "network_access"}),
    "slack":     frozenset({"communication", "file_transfer", "network_access"}),
}


def get_tool_capabilities(tool_name: str) -> Set[str]:
    """工具 → 能力集。精确匹配优先；未知工具走关键词回退；仍推断不出 → unknown_tool（高危保守处理）"""
    if not tool_name:
        return {"unknown_tool"}
    name = tool_name.lower()
    exact = TOOL_CAPABILITIES.get(name) or TOOL_CAPABILITIES.get(tool_name)
    if exact:
        return set(exact)
    caps: Set[str] = set()
    for keyword, cs in KEYWORD_FALLBACK.items():
        if keyword in name:
            caps.update(cs)
    return caps if caps else {"unknown_tool"}


def get_grant_required_capabilities(tool_name: str) -> Set[str]:
    """工具所需能力中，必须经审批授予才拥有的部分（默认 deny 的能力）"""
    caps = get_tool_capabilities(tool_name)
    return {c for c in caps if CAPABILITY_METADATA.get(c, {}).get("grant_required", True)}


def get_default_grants(role: str = "user") -> Set[str]:
    """角色默认能力集（未登记角色按最小权限 user 处理）"""
    grants = ROLE_DEFAULT_GRANTS.get((role or "user").lower(), ROLE_DEFAULT_GRANTS["user"])
    return set(grants)


def capability_info(cap: str) -> Dict:
    """能力元数据（未登记能力保守视为需授权+不可逆）"""
    return CAPABILITY_METADATA.get(cap, {
        "risk": "medium", "irreversible": True, "grant_required": True, "desc": f"未登记能力:{cap}",
    })
