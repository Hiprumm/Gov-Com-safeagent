"""
操作守卫层 (Operation Guard)
============================

输入检测通过后，Agent 生成动作意图（tool_name + parameters），
操作守卫对动作意图做最后校验。即使输入检测判定安全，
操作守卫仍可拦截高危动作——这是防止"漏过检测后产生真实危害"的最后一道防线。

核心能力：
1. 工具黑名单：永远禁止调用的工具/命令（system/exec/eval/rm -rf 等）
2. 参数黑名单：参数值含恶意内容即使检测通过也拦
3. 审批前置：导出/权限/批量类动作强制走审批
4. 速率限制：同会话连续高危操作自动锁

设计原则：
- 输入检测负责"文本是否含攻击意图"
- 操作守卫负责"动作本身是否危险"——即使意图看似正常，
  执行 rm -rf / 或导出全部用户数据 也必须拦截/审批
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import re
import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from models.schemas import RiskLevel, AttackType


# ============================================================================
# 数据结构
# ============================================================================

class ActionType(str, Enum):
    """动作类型分类"""
    READ = "read"            # 只读查询
    WRITE = "write"          # 写入/修改
    EXECUTE = "execute"      # 执行命令/脚本
    EXPORT = "export"        # 导出/下载/外传数据
    ADMIN = "admin"          # 权限/配置/系统管理
    NETWORK = "network"      # 网络请求/外联
    DELETE = "delete"        # 删除数据/文件
    UNKNOWN = "unknown"


@dataclass
class OperationIntent:
    """Agent 生成的动作意图"""
    tool_name: str                          # 工具/MCP/Skill 名称
    parameters: Dict[str, Any] = field(default_factory=dict)  # 参数
    session_id: str = "default"
    user_input: str = ""                    # 触发此动作的用户原始输入
    action_type: ActionType = ActionType.UNKNOWN


@dataclass
class GuardResult:
    """操作守卫判定结果"""
    allowed: bool = True                    # 是否允许执行
    reason: str = ""                        # 判定原因
    requires_approval: bool = False         # 是否需要审批
    approval_reason: str = ""               # 审批原因
    risk_level: RiskLevel = RiskLevel.NONE  # 风险等级
    blocked_by: str = ""                    # 拦截规则名
    action_type: ActionType = ActionType.UNKNOWN
    rate_limited: bool = False              # 是否触发速率限制


# ============================================================================
# 规则定义
# ============================================================================

# 1. 工具黑名单（永远禁止调用，无论参数如何）
TOOL_BLACKLIST = {
    # 系统命令执行类
    "os.system", "os.popen", "subprocess.call", "subprocess.run",
    "subprocess.Popen", "subprocess.check_output", "subprocess.check_call",
    "exec", "eval", "compile", "__import__",
    "os.exec", "os.execv", "os.execl", "os.spawn",
    "pty.spawn", "commands.getoutput", "commands.getstatusoutput",
    # 危险文件操作
    "shutil.rmtree", "os.remove", "os.unlink",
    "shutil.copytree",  # 批量复制可能外泄
    # 危险系统操作
    "os.chmod", "os.chown", "os.setuid", "os.setgid",
    "signal.signal",   # 信号操控
    "sys.exit", "os._exit", "os.abort",
    # 网络后门类
    "socket.socket",   # 原始socket可能建后门
    "webbrowser.open", # 可能打开恶意URL
}

# 2. 工具名模糊匹配黑名单（子串匹配，防止改名绕过）
TOOL_NAME_BLACKLIST_PATTERNS = [
    r"(?:^|_)(?:exec|eval|system|shell|cmd|bash|powershell|terminal)(?:_|$)",
    r"(?:^|_)(?:rm_rf|del_tree|format_disk|mkfs|shutdown|reboot)(?:_|$)",
    r"(?:^|_)(?:reverse_shell|bind_shell|backdoor|payload)(?:_|$)",
    r"(?:^|_)(?:keylogger|screen_capture|clipboard_hijack)(?:_|$)",
]

# 3. 参数值黑名单（参数值含这些内容直接拦）
PARAM_VALUE_BLACKLIST_PATTERNS = [
    # 系统破坏命令
    r"rm\s+-rf\s+/",
    r"del\s+/[sS]\s+/[qQ]",
    r"format\s+[cC]:",
    r"mkfs\.\w+\s+/dev/",
    r"shutdown\s+-[hk]",
    r"dd\s+if=.*of=/dev/",
    # 数据库破坏
    r"(?:drop|truncate)\s+table\s+\w+",
    r"delete\s+from\s+\w+\s+where\s+1=1",
    r"(?:drop|delete)\s+database\s+",
    # 反弹shell
    r"(?:nc|netcat|bash|sh|python|perl)\s+-[ei]\s+.*\d+\.\d+\.\d+\.\d+",
    r"/dev/tcp/\d+\.\d+\.\d+\.\d+",
    r"socket\.socket\s*\(",
    # 数据外传
    r"(?:curl|wget)\s+.*\|\s*(?:bash|sh|python)",
    r"(?:curl|wget)\s+.*\$\{.*\}",
    # 提权
    r"sudo\s+su",
    r"sudo\s+-i",
    r"chmod\s+[4567]7[57]7",
    r"chown\s+root",
]

# 4. 审批前置动作（不拦，但强制走审批）
APPROVAL_REQUIRED_PATTERNS = [
    # 数据导出类
    {
        "pattern": r"(?:export|导出|下载|备份|迁移|打包|压缩|转出|外传|同步到外部)",
        "action_type": ActionType.EXPORT,
        "reason": "数据导出类操作需审批",
    },
    {
        "pattern": r"(?:download|backup|transfer|sync_to_external|send_to_remote)",
        "action_type": ActionType.EXPORT,
        "reason": "数据外传操作需审批",
    },
    # 权限/配置修改类
    {
        "pattern": r"(?:修改|调整|变更|设置|更新).{0,15}(?:权限|角色|级别|配置|策略|规则|密码|密钥)",
        "action_type": ActionType.ADMIN,
        "reason": "权限/配置修改需审批",
    },
    {
        "pattern": r"(?:grant|revoke|set_role|update_permission|change_config|modify_policy)",
        "action_type": ActionType.ADMIN,
        "reason": "权限管理操作需审批",
    },
    # 批量操作类（参数中数量>100）
    # 此项在参数检查中动态判定
    # 删除类
    {
        "pattern": r"(?:delete|删除|清除|清空|销毁|格式化|擦除)",
        "action_type": ActionType.DELETE,
        "reason": "数据删除操作需审批",
    },
    # 执行系统命令
    {
        "pattern": r"(?:execute|run|exec|invoke).{0,10}(?:command|script|shell|cmd|bash|program)",
        "action_type": ActionType.EXECUTE,
        "reason": "命令/脚本执行需审批",
    },
]

# 5. 可信域名白名单（参数值中的URL，白名单不告警）
TRUSTED_URL_SUFFIXES = (
    ".gov.cn", ".gov.org", ".gov", ".edu.cn", ".edu",
    ".ac.cn", ".mil.cn", ".org.cn",
    "localhost", "127.0.0.1", "::1",
)

# 6. 速率限制配置
RATE_LIMIT_CONFIG = {
    "high_risk_window": 60,      # 60秒窗口
    "high_risk_max": 3,          # 窗口内最多3次高危动作
    "export_max_per_hour": 10,   # 每小时最多10次导出
    "lock_duration": 300,        # 触发限制后锁定5分钟
}


# ============================================================================
# 操作守卫主类
# ============================================================================

class OperationGuard:
    """操作守卫层——动作执行前的最后一道防线

    使用方式：
        guard = get_operation_guard()
        result = guard.check_intent(intent)
        if not result.allowed:
            # 拦截，不执行
        elif result.requires_approval:
            # 转审批流程
        else:
            # 放行执行
    """

    def __init__(self):
        # 编译正则
        self._tool_name_blacklist = [re.compile(p, re.IGNORECASE) for p in TOOL_NAME_BLACKLIST_PATTERNS]
        self._param_blacklist = [re.compile(p, re.IGNORECASE) for p in PARAM_VALUE_BLACKLIST_PATTERNS]
        self._approval_patterns = []
        for cfg in APPROVAL_REQUIRED_PATTERNS:
            self._approval_patterns.append({
                "regex": re.compile(cfg["pattern"], re.IGNORECASE),
                "action_type": cfg["action_type"],
                "reason": cfg["reason"],
            })

        # 速率限制追踪：session_id -> List[(timestamp, action_type)]
        self._action_history: Dict[str, List[Tuple[float, ActionType]]] = {}
        # 锁定的session：session_id -> unlock_time
        self._locked_sessions: Dict[str, float] = {}

    def check_intent(self, intent: OperationIntent) -> GuardResult:
        """检查动作意图，返回守卫判定结果"""
        result = GuardResult(action_type=intent.action_type)

        # 0. 检查会话是否被锁定
        if self._is_session_locked(intent.session_id):
            remaining = self._locked_sessions[intent.session_id] - time.time()
            result.allowed = False
            result.risk_level = RiskLevel.HIGH
            result.blocked_by = "session_locked"
            result.rate_limited = True
            result.reason = f"会话因高频高危操作被锁定，剩余{int(remaining)}秒"
            return result

        # 推断动作类型
        if intent.action_type == ActionType.UNKNOWN:
            intent.action_type = self._infer_action_type(intent)
            result.action_type = intent.action_type

        # 1. 工具黑名单检查（精确匹配）
        if intent.tool_name in TOOL_BLACKLIST:
            result.allowed = False
            result.risk_level = RiskLevel.CRITICAL
            result.blocked_by = "tool_blacklist_exact"
            result.reason = f"工具 [{intent.tool_name}] 在永久黑名单中，禁止调用"
            self._record_action(intent.session_id, intent.action_type, is_high_risk=True)
            return result

        # 2. 工具名模糊匹配黑名单
        for pattern in self._tool_name_blacklist:
            if pattern.search(intent.tool_name):
                result.allowed = False
                result.risk_level = RiskLevel.CRITICAL
                result.blocked_by = "tool_blacklist_pattern"
                result.reason = f"工具名 [{intent.tool_name}] 匹配黑名单模式，禁止调用"
                self._record_action(intent.session_id, intent.action_type, is_high_risk=True)
                return result

        # 3. 参数值黑名单检查
        for param_name, param_value in intent.parameters.items():
            param_str = str(param_value)
            for pattern in self._param_blacklist:
                if pattern.search(param_str):
                    result.allowed = False
                    result.risk_level = RiskLevel.CRITICAL
                    result.blocked_by = "param_blacklist"
                    result.reason = f"参数 [{param_name}] 含恶意内容：匹配 {pattern.pattern[:50]}"
                    self._record_action(intent.session_id, intent.action_type, is_high_risk=True)
                    return result

        # 4. 审批前置检查（不拦，但标记需审批）
        combined_text = f"{intent.tool_name} {' '.join(str(v) for v in intent.parameters.values())} {intent.user_input}"
        for cfg in self._approval_patterns:
            if cfg["regex"].search(combined_text):
                result.requires_approval = True
                result.approval_reason = cfg["reason"]
                result.action_type = cfg["action_type"]
                result.risk_level = RiskLevel.MEDIUM
                result.reason = f"操作需审批：{cfg['reason']}"
                # 不在此处记录动作，统一在方法末尾记录（避免双重计数）
                break

        # 5. 批量操作检查（参数中数量>100）
        for param_name, param_value in intent.parameters.items():
            if self._is_bulk_operation(param_name, param_value):
                if not result.requires_approval:
                    result.requires_approval = True
                    result.approval_reason = "批量操作（数量超过阈值）需审批"
                    result.risk_level = RiskLevel.MEDIUM
                    result.reason = "批量操作需审批"
                break

        # 6. 外部URL检查（参数值含非白名单URL）
        external_urls = self._find_external_urls(intent.parameters)
        if external_urls:
            if not result.requires_approval:
                result.requires_approval = True
                result.approval_reason = f"参数含外部URL需审批：{external_urls[0]}"
                result.risk_level = RiskLevel.MEDIUM
                result.reason = "外部URL操作需审批"
            else:
                result.approval_reason += f"；含外部URL：{external_urls[0]}"

        # 7. 速率限制检查
        if self._check_rate_limit(intent.session_id):
            result.allowed = False
            result.risk_level = RiskLevel.HIGH
            result.blocked_by = "rate_limit"
            result.rate_limited = True
            result.reason = "触发速率限制：短时间内高频高危操作"
            self._lock_session(intent.session_id)
            return result

        # 记录动作
        self._record_action(intent.session_id, result.action_type, is_high_risk=result.requires_approval)

        # 放行（可能需审批）
        if not result.reason:
            result.reason = "操作通过守卫检查"
        return result

    def _infer_action_type(self, intent: OperationIntent) -> ActionType:
        """根据工具名和参数推断动作类型"""
        tool_lower = intent.tool_name.lower()
        param_text = " ".join(str(v) for v in intent.parameters.values()).lower()

        if any(kw in tool_lower or kw in param_text for kw in
               ["exec", "run", "execute", "shell", "cmd", "bash", "script"]):
            return ActionType.EXECUTE
        if any(kw in tool_lower or kw in param_text for kw in
               ["export", "download", "backup", "transfer", "导出", "下载", "备份", "迁移"]):
            return ActionType.EXPORT
        if any(kw in tool_lower or kw in param_text for kw in
               ["delete", "remove", "drop", "删除", "清除", "销毁"]):
            return ActionType.DELETE
        if any(kw in tool_lower or kw in param_text for kw in
               ["admin", "permission", "role", "config", "权限", "角色", "配置", "管理员"]):
            return ActionType.ADMIN
        if any(kw in tool_lower or kw in param_text for kw in
               ["curl", "wget", "request", "fetch", "http"]):
            return ActionType.NETWORK
        if any(kw in tool_lower or kw in param_text for kw in
               ["write", "update", "create", "modify", "写入", "修改", "创建"]):
            return ActionType.WRITE
        if any(kw in tool_lower or kw in param_text for kw in
               ["read", "query", "get", "list", "查询", "读取", "获取"]):
            return ActionType.READ
        return ActionType.UNKNOWN

    def _is_bulk_operation(self, param_name: str, param_value: Any) -> bool:
        """检查是否为批量操作（仅检查数量类参数，避免URL中的端口号误判）"""
        # 仅对数量类参数名检查字符串中的数字
        count_param_names = (
            "count", "limit", "size", "batch", "quantity", "num",
            "total", "amount", "max_count", "page_size", "bulk_size",
        )
        param_lower = param_name.lower()
        is_count_param = any(kw in param_lower for kw in count_param_names)

        # 数值型参数 > 100（任何参数名都检查）
        if isinstance(param_value, (int, float)):
            return param_value > 100
        # 列表/数组长度 > 100
        if isinstance(param_value, (list, tuple, set)):
            return len(param_value) > 100
        # 字符串中含数字 > 100（仅数量类参数，避免URL端口号误判）
        if is_count_param:
            val_str = str(param_value)
            nums = re.findall(r"\d+", val_str)
            for n in nums:
                if int(n) > 100:
                    return True
        return False

    def _find_external_urls(self, parameters: Dict[str, Any]) -> List[str]:
        """查找参数值中的非白名单外部URL"""
        urls = []
        url_pattern = re.compile(r"https?://([^\s/\"'<>]+)", re.IGNORECASE)
        for param_value in parameters.values():
            for match in url_pattern.finditer(str(param_value)):
                domain = match.group(1).lower()
                # 剥离端口号再匹配白名单（localhost:8000 → localhost）
                domain_no_port = domain.split(":")[0]
                if not any(domain_no_port.endswith(suffix) for suffix in TRUSTED_URL_SUFFIXES):
                    urls.append(match.group(0))
        return urls

    def _is_session_locked(self, session_id: str) -> bool:
        """检查会话是否被锁定"""
        if session_id in self._locked_sessions:
            if time.time() < self._locked_sessions[session_id]:
                return True
            else:
                del self._locked_sessions[session_id]
        return False

    def _lock_session(self, session_id: str):
        """锁定会话"""
        self._locked_sessions[session_id] = time.time() + RATE_LIMIT_CONFIG["lock_duration"]

    def _record_action(self, session_id: str, action_type: ActionType, is_high_risk: bool = False):
        """记录动作历史（仅记录高危动作用于速率限制）"""
        if not is_high_risk:
            return
        if session_id not in self._action_history:
            self._action_history[session_id] = []
        self._action_history[session_id].append((time.time(), action_type))
        # 清理过期记录
        cutoff = time.time() - 3600  # 保留1小时
        self._action_history[session_id] = [
            (ts, at) for ts, at in self._action_history[session_id] if ts > cutoff
        ]

    def _check_rate_limit(self, session_id: str) -> bool:
        """检查是否触发速率限制（仅统计高危动作）"""
        history = self._action_history.get(session_id, [])
        if not history:
            return False
        now = time.time()
        window = RATE_LIMIT_CONFIG["high_risk_window"]
        recent = [ts for ts, _ in history if now - ts < window]
        return len(recent) >= RATE_LIMIT_CONFIG["high_risk_max"]

    def clear_session(self, session_id: str):
        """清除会话记录"""
        self._action_history.pop(session_id, None)
        self._locked_sessions.pop(session_id, None)

    def get_session_summary(self, session_id: str) -> Dict:
        """获取会话操作历史摘要"""
        history = self._action_history.get(session_id, [])
        now = time.time()
        recent_1h = [(ts, at) for ts, at in history if now - ts < 3600]
        recent_1min = [(ts, at) for ts, at in history if now - ts < 60]

        return {
            "session_id": session_id,
            "total_actions_1h": len(recent_1h),
            "actions_1min": len(recent_1min),
            "is_locked": self._is_session_locked(session_id),
            "lock_remaining_seconds": max(0, int(self._locked_sessions.get(session_id, 0) - now)),
            "action_types_1h": list(set(at.value for _, at in recent_1h)),
        }


# ============================================================================
# 全局单例
# ============================================================================

_operation_guard: Optional[OperationGuard] = None


def get_operation_guard() -> OperationGuard:
    global _operation_guard
    if _operation_guard is None:
        _operation_guard = OperationGuard()
    return _operation_guard
