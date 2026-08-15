import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from models.schemas import RiskLevel, AttackType


class PermissionLevel(str, Enum):
    """权限级别"""
    READ = "read"           # 只读
    WRITE = "write"         # 写入
    EXECUTE = "execute"     # 执行
    NETWORK = "network"     # 网络
    ADMIN = "admin"         # 管理
    EXPORT = "export"       # 导出


# 风险等级排序（从低到高），用于等级间比较
_RISK_ORDER: List[RiskLevel] = [
    RiskLevel.NONE,
    RiskLevel.LOW,
    RiskLevel.MEDIUM,
    RiskLevel.HIGH,
    RiskLevel.CRITICAL,
]


def _risk_rank(level: RiskLevel) -> int:
    """获取风险等级的数值序号，数值越大风险越高"""
    return _RISK_ORDER.index(level)


@dataclass
class ToolPermission:
    """工具权限定义"""
    tool_name: str
    allowed_permissions: List[PermissionLevel]
    denied_permissions: List[PermissionLevel]
    max_calls_per_session: int  # 单会话最大调用次数
    requires_approval: bool
    base_risk: RiskLevel
    description: str = ""


@dataclass
class ParameterValidationResult:
    """参数校验结果"""
    is_valid: bool
    risk_level: RiskLevel
    violations: List[str]  # 违规描述
    sanitized_params: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ContextPermission:
    """上下文权限约束"""
    session_id: str
    allowed_permissions: List[PermissionLevel]
    denied_permissions: List[PermissionLevel]
    max_risk_allowed: RiskLevel
    reason: str = ""


# ---------------------------------------------------------------------------
# 工具权限注册表：定义常见工具的权限基线
# ---------------------------------------------------------------------------
TOOL_PERMISSIONS: Dict[str, ToolPermission] = {
    "read_file": ToolPermission(
        tool_name="read_file",
        allowed_permissions=[PermissionLevel.READ],
        denied_permissions=[PermissionLevel.WRITE, PermissionLevel.EXECUTE,
                            PermissionLevel.NETWORK, PermissionLevel.ADMIN],
        max_calls_per_session=20,
        requires_approval=False,
        base_risk=RiskLevel.LOW,
        description="读取文件内容",
    ),
    "write_file": ToolPermission(
        tool_name="write_file",
        allowed_permissions=[PermissionLevel.WRITE],
        denied_permissions=[PermissionLevel.EXECUTE, PermissionLevel.NETWORK,
                            PermissionLevel.ADMIN],
        max_calls_per_session=5,
        requires_approval=True,
        base_risk=RiskLevel.MEDIUM,
        description="写入文件",
    ),
    "execute_command": ToolPermission(
        tool_name="execute_command",
        allowed_permissions=[PermissionLevel.EXECUTE],
        denied_permissions=[PermissionLevel.NETWORK, PermissionLevel.ADMIN],
        max_calls_per_session=3,
        requires_approval=True,
        base_risk=RiskLevel.HIGH,
        description="执行系统命令",
    ),
    "export_data": ToolPermission(
        tool_name="export_data",
        allowed_permissions=[PermissionLevel.EXPORT],
        denied_permissions=[PermissionLevel.ADMIN],
        max_calls_per_session=2,
        requires_approval=True,
        base_risk=RiskLevel.HIGH,
        description="导出数据",
    ),
    "search_knowledge": ToolPermission(
        tool_name="search_knowledge",
        allowed_permissions=[PermissionLevel.READ],
        denied_permissions=[PermissionLevel.WRITE, PermissionLevel.EXECUTE,
                            PermissionLevel.NETWORK, PermissionLevel.ADMIN,
                            PermissionLevel.EXPORT],
        max_calls_per_session=50,
        requires_approval=False,
        base_risk=RiskLevel.NONE,
        description="搜索知识库",
    ),
    "send_request": ToolPermission(
        tool_name="send_request",
        allowed_permissions=[PermissionLevel.NETWORK],
        denied_permissions=[PermissionLevel.ADMIN],
        max_calls_per_session=5,
        requires_approval=True,
        base_risk=RiskLevel.HIGH,
        description="发送网络请求",
    ),
}


# ---------------------------------------------------------------------------
# 参数校验：危险模式正则定义
# ---------------------------------------------------------------------------

# 路径穿越模式：../ 、..\ 、URL编码的%2e%2e、双层编码、编码斜杠、以及绝对系统路径前缀
_PATH_TRAVERSAL_PATTERNS: List[str] = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e",
    r"%252e%252e",   # 双层编码 ..
    r"%2f",          # 编码斜杠（..%2f）
    r"%252f",        # 双层编码斜杠
    r"/etc/",
    r"C:\\Windows\\",
]

# 命令注入模式：shell元字符
_COMMAND_INJECTION_PATTERNS: List[str] = [
    r";",
    r"\|",
    r"&",
    r"\$\(",
    r"`",
    r"&&",
    r"\|\|",
]

# SQL注入模式：危险SQL关键字与经典注入载荷
_SQL_INJECTION_PATTERNS: List[str] = [
    r"\bDROP\b",
    r"\bDELETE\b",
    r"\bUNION\s+SELECT\b",
    r"\bOR\s+1\s*=\s*1\b",
]

# 危险系统文件路径
_DANGEROUS_SYSTEM_PATHS: List[str] = [
    "/etc/passwd",
    "/etc/shadow",
    "C:\\Windows\\System32",
]

# 受信任的URL域名/主机
_TRUSTED_URL_DOMAINS: List[str] = [
    ".gov.cn",
    ".edu.cn",
    "localhost",
    "127.0.0.1",
]

# Base64编码特征：长度>=40，由base64字符集组成（含URL-safe变体的-_）
_BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/_-]{40,}={0,2}$")
# 十六进制编码特征：长度>=32且为偶数，纯hex字符
_HEX_PATTERN = re.compile(r"^[0-9a-fA-F]{32,}$")

# 参数名到校验类型的映射关键字
_PATH_PARAM_KEYWORDS = ("file_path", "filepath", "path", "filename", "file")
_COMMAND_PARAM_KEYWORDS = ("command", "cmd", "shell", "exec")
_SQL_PARAM_KEYWORDS = ("query", "sql", "db_query", "statement")
_URL_PARAM_KEYWORDS = ("url", "uri", "endpoint", "link", "host")


def _match_any(patterns: List[str], value: str, flags: int = re.IGNORECASE) -> List[str]:
    """对给定值逐一匹配正则列表，返回所有命中的模式字符串"""
    matched: List[str] = []
    for pat in patterns:
        if re.search(pat, value, flags):
            matched.append(pat)
    return matched


def _detect_path_traversal(value: str) -> List[str]:
    """检测路径穿越攻击模式，返回违规描述列表（风险等级：CRITICAL）"""
    violations: List[str] = []
    matched = _match_any(_PATH_TRAVERSAL_PATTERNS, value)
    if matched:
        violations.append(
            f"[{AttackType.PATH_TRAVERSAL.value}] 参数包含路径穿越特征: "
            f"命中模式 {matched}"
        )
    return violations


def _detect_command_injection(value: str) -> List[str]:
    """检测命令注入攻击模式，返回违规描述列表（风险等级：CRITICAL）"""
    violations: List[str] = []
    matched = _match_any(_COMMAND_INJECTION_PATTERNS, value)
    if matched:
        violations.append(
            f"[{AttackType.COMMAND_EXECUTION.value}] 参数包含命令注入元字符: "
            f"命中模式 {matched}"
        )
    return violations


def _detect_sql_injection(value: str) -> List[str]:
    """检测SQL注入攻击模式，返回违规描述列表（风险等级：HIGH）"""
    violations: List[str] = []
    matched = _match_any(_SQL_INJECTION_PATTERNS, value)
    if matched:
        violations.append(
            f"[{AttackType.SQL_INJECTION.value}] 参数包含SQL注入关键字: "
            f"命中模式 {matched}"
        )
    return violations


def _detect_dangerous_system_paths(value: str) -> List[str]:
    """检测系统敏感文件路径，返回违规描述列表（风险等级：HIGH）"""
    violations: List[str] = []
    matched = _match_any(_DANGEROUS_SYSTEM_PATHS, value)
    if matched:
        violations.append(
            f"[{AttackType.UNAUTHORIZED_ACCESS.value}] 参数引用系统敏感路径: "
            f"命中 {matched}"
        )
    return violations


def _detect_external_url(value: str) -> List[str]:
    """检测非白名单的外部URL，返回违规描述列表（风险等级：MEDIUM）

    受信任域名：.gov.cn、.edu.cn、localhost、127.0.0.1
    """
    violations: List[str] = []
    value_lower = value.lower()
    is_trusted = any(domain in value_lower for domain in _TRUSTED_URL_DOMAINS)
    if not is_trusted:
        # 仅当值看起来像URL时才告警（包含http/https或含点号的域名）
        looks_like_url = (
            value_lower.startswith("http://")
            or value_lower.startswith("https://")
            or re.search(r"^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", value_lower) is not None
        )
        if looks_like_url:
            violations.append(
                f"[{AttackType.NETWORK_ATTACK.value}] 参数包含非白名单外部URL: {value[:80]}"
            )
    return violations


def _detect_encoded_payload(value: str) -> List[str]:
    """检测Base64/十六进制编码载荷，返回违规描述列表（风险等级：MEDIUM）"""
    violations: List[str] = []
    stripped = value.strip()

    # Base64编码检测
    if _BASE64_PATTERN.match(stripped):
        violations.append(
            f"[{AttackType.DATA_EXFILTRATION.value}] 参数疑似包含Base64编码载荷"
        )

    # 十六进制编码检测（要求偶数长度）
    if _HEX_PATTERN.match(stripped) and len(stripped) % 2 == 0:
        violations.append(
            f"[{AttackType.DATA_EXFILTRATION.value}] 参数疑似包含十六进制编码载荷"
        )

    return violations


# 每种校验类型对应的风险等级
_VALIDATOR_RISK_MAP: Dict[str, RiskLevel] = {
    "path_traversal": RiskLevel.CRITICAL,
    "command_injection": RiskLevel.CRITICAL,
    "sql_injection": RiskLevel.HIGH,
    "external_url": RiskLevel.MEDIUM,
    "dangerous_paths": RiskLevel.HIGH,
    "encoded_payload": RiskLevel.MEDIUM,
}


def _max_risk(levels: List[RiskLevel]) -> RiskLevel:
    """从风险等级列表中取最高等级，空列表返回NONE"""
    if not levels:
        return RiskLevel.NONE
    return max(levels, key=_risk_rank)


class PermissionMatrix:
    """工具权限矩阵

    负责工具级别的权限校验、调用次数限制、参数级安全校验，
    并支持基于会话上下文的动态权限调整。
    """

    def __init__(self):
        # 工具权限定义表（支持运行时扩展）
        self._tool_permissions: Dict[str, ToolPermission] = TOOL_PERMISSIONS.copy()
        # 调用计数：session_id -> {tool_name: count}
        self._call_counts: Dict[str, Dict[str, int]] = {}
        # 上下文权限覆盖：session_id -> ContextPermission
        self._context_overrides: Dict[str, ContextPermission] = {}

    # ------------------------------------------------------------------
    # 权限定义管理
    # ------------------------------------------------------------------

    def get_permission(self, tool_name: str) -> ToolPermission:
        """获取工具权限定义

        若工具未注册则抛出KeyError。
        """
        if tool_name not in self._tool_permissions:
            raise KeyError(f"工具 [{tool_name}] 未在权限矩阵中注册")
        return self._tool_permissions[tool_name]

    def register_permission(self, permission: ToolPermission) -> None:
        """注册或更新工具权限定义"""
        self._tool_permissions[permission.tool_name] = permission

    # ------------------------------------------------------------------
    # 权限校验
    # ------------------------------------------------------------------

    def check_permission(
        self,
        tool_name: str,
        required_permission: PermissionLevel,
        session_id: str = "default",
    ) -> bool:
        """检查工具在指定会话下是否拥有某项权限

        校验流程：
        1. 工具必须已注册
        2. 所需权限不在工具的denied_permissions中
        3. 所需权限在工具的allowed_permissions中
        4. 若存在上下文覆盖，进一步检查上下文的denied与allowed列表
        5. 工具基础风险不得超过上下文的max_risk_allowed
        """
        # 未知工具默认拒绝
        if tool_name not in self._tool_permissions:
            return False

        tool_perm = self._tool_permissions[tool_name]

        # 基础权限检查：先看拒绝列表，再看允许列表
        if required_permission in tool_perm.denied_permissions:
            return False
        if required_permission not in tool_perm.allowed_permissions:
            return False

        # 上下文覆盖检查
        context = self._context_overrides.get(session_id)
        if context is not None:
            # 上下文显式拒绝
            if required_permission in context.denied_permissions:
                return False
            # 上下文显式允许则放行
            if required_permission in context.allowed_permissions:
                return True
            # 上下文未显式允许时，检查工具风险是否在允许范围内
            if _risk_rank(tool_perm.base_risk) > _risk_rank(context.max_risk_allowed):
                return False

        return True

    # ------------------------------------------------------------------
    # 调用次数限制
    # ------------------------------------------------------------------

    def check_call_limit(self, tool_name: str, session_id: str) -> Tuple[bool, int]:
        """检查调用次数限制，返回(是否允许调用, 已调用次数)

        若工具未注册，返回(False, 0)。
        """
        if tool_name not in self._tool_permissions:
            return False, 0

        tool_perm = self._tool_permissions[tool_name]
        current_count = self._call_counts.get(session_id, {}).get(tool_name, 0)
        allowed = current_count < tool_perm.max_calls_per_session
        return allowed, current_count

    def record_call(self, tool_name: str, session_id: str) -> None:
        """记录一次工具调用，递增对应会话的计数"""
        if session_id not in self._call_counts:
            self._call_counts[session_id] = {}
        self._call_counts[session_id][tool_name] = (
            self._call_counts[session_id].get(tool_name, 0) + 1
        )

    # ------------------------------------------------------------------
    # 参数级校验
    # ------------------------------------------------------------------

    def validate_parameters(
        self, tool_name: str, parameters: Dict[str, Any]
    ) -> ParameterValidationResult:
        """参数级校验——检测危险参数

        根据参数名将其归类为路径/命令/SQL/URL等类型，分别应用对应的
        检测器；所有参数均会进行编码载荷检测。最终汇总违规信息，
        is_valid 为 True 当且仅当无任何违规。
        """
        violations: List[str] = []
        detected_risks: List[RiskLevel] = []

        for param_name, raw_value in parameters.items():
            # 仅对字符串类型参数做模式匹配
            if not isinstance(raw_value, str):
                continue

            value = raw_value
            name_lower = param_name.lower()

            # 路径类参数：路径穿越 + 系统敏感路径
            if any(kw in name_lower for kw in _PATH_PARAM_KEYWORDS):
                v = _detect_path_traversal(value)
                if v:
                    violations.extend(v)
                    detected_risks.append(_VALIDATOR_RISK_MAP["path_traversal"])
                v = _detect_dangerous_system_paths(value)
                if v:
                    violations.extend(v)
                    detected_risks.append(_VALIDATOR_RISK_MAP["dangerous_paths"])

            # 命令类参数：命令注入
            if any(kw in name_lower for kw in _COMMAND_PARAM_KEYWORDS):
                v = _detect_command_injection(value)
                if v:
                    violations.extend(v)
                    detected_risks.append(_VALIDATOR_RISK_MAP["command_injection"])

            # SQL类参数：SQL注入
            if any(kw in name_lower for kw in _SQL_PARAM_KEYWORDS):
                v = _detect_sql_injection(value)
                if v:
                    violations.extend(v)
                    detected_risks.append(_VALIDATOR_RISK_MAP["sql_injection"])

            # URL类参数：外部URL检测
            if any(kw in name_lower for kw in _URL_PARAM_KEYWORDS):
                v = _detect_external_url(value)
                if v:
                    violations.extend(v)
                    detected_risks.append(_VALIDATOR_RISK_MAP["external_url"])

            # 所有参数均检测编码载荷
            v = _detect_encoded_payload(value)
            if v:
                violations.extend(v)
                detected_risks.append(_VALIDATOR_RISK_MAP["encoded_payload"])

        overall_risk = _max_risk(detected_risks)
        is_valid = len(violations) == 0

        # sanitized_params：对通过校验的参数做基本清洗（去除首尾空白）
        # 若存在违规，仍返回原始参数供调用方参考，但is_valid为False
        sanitized: Dict[str, Any] = {}
        for param_name, raw_value in parameters.items():
            if isinstance(raw_value, str):
                sanitized[param_name] = raw_value.strip()
            else:
                sanitized[param_name] = raw_value

        return ParameterValidationResult(
            is_valid=is_valid,
            risk_level=overall_risk,
            violations=violations,
            sanitized_params=sanitized,
        )

    # ------------------------------------------------------------------
    # 上下文权限管理
    # ------------------------------------------------------------------

    def set_context_permission(
        self, session_id: str, context: ContextPermission
    ) -> None:
        """设置上下文权限约束，覆盖该会话的默认权限基线"""
        self._context_overrides[session_id] = context

    def get_context_permission(self, session_id: str) -> Optional[ContextPermission]:
        """获取上下文权限，不存在则返回None"""
        return self._context_overrides.get(session_id)

    def adjust_for_risk(self, session_id: str, current_risk: RiskLevel) -> None:
        """根据当前风险等级动态调整会话权限

        - NONE/LOW：清除上下文限制，全部正常
        - MEDIUM：禁止EXECUTE和ADMIN
        - HIGH：仅允许READ
        - CRITICAL：全部禁止
        """
        if current_risk in (RiskLevel.NONE, RiskLevel.LOW):
            # 风险较低，清除上下文覆盖，恢复正常权限
            self._context_overrides.pop(session_id, None)
            return

        if current_risk == RiskLevel.MEDIUM:
            context = ContextPermission(
                session_id=session_id,
                allowed_permissions=[
                    PermissionLevel.READ,
                    PermissionLevel.WRITE,
                    PermissionLevel.NETWORK,
                    PermissionLevel.EXPORT,
                ],
                denied_permissions=[PermissionLevel.EXECUTE, PermissionLevel.ADMIN],
                max_risk_allowed=RiskLevel.MEDIUM,
                reason=f"当前风险等级 {current_risk.value}，禁止执行与管理类操作",
            )
        elif current_risk == RiskLevel.HIGH:
            context = ContextPermission(
                session_id=session_id,
                allowed_permissions=[PermissionLevel.READ],
                denied_permissions=[
                    PermissionLevel.WRITE,
                    PermissionLevel.EXECUTE,
                    PermissionLevel.NETWORK,
                    PermissionLevel.ADMIN,
                    PermissionLevel.EXPORT,
                ],
                max_risk_allowed=RiskLevel.LOW,
                reason=f"当前风险等级 {current_risk.value}，仅允许只读操作",
            )
        else:  # CRITICAL
            context = ContextPermission(
                session_id=session_id,
                allowed_permissions=[],
                denied_permissions=[
                    PermissionLevel.READ,
                    PermissionLevel.WRITE,
                    PermissionLevel.EXECUTE,
                    PermissionLevel.NETWORK,
                    PermissionLevel.ADMIN,
                    PermissionLevel.EXPORT,
                ],
                max_risk_allowed=RiskLevel.NONE,
                reason=f"当前风险等级 {current_risk.value}，全部操作已禁止",
            )

        self._context_overrides[session_id] = context

    # ------------------------------------------------------------------
    # 会话管理
    # ------------------------------------------------------------------

    def clear_session(self, session_id: str) -> None:
        """清除指定会话的所有数据（调用计数与上下文权限）"""
        self._call_counts.pop(session_id, None)
        self._context_overrides.pop(session_id, None)

    def get_session_summary(self, session_id: str) -> Dict:
        """获取会话权限摘要

        返回包含调用计数、上下文权限及已注册工具信息的字典。
        """
        call_counts = self._call_counts.get(session_id, {})
        context = self._context_overrides.get(session_id)

        # 统计总调用次数
        total_calls = sum(call_counts.values())

        # 各工具的调用情况（已注册工具）
        tool_summaries: List[Dict[str, Any]] = []
        for tool_name, tool_perm in self._tool_permissions.items():
            called = call_counts.get(tool_name, 0)
            tool_summaries.append({
                "tool_name": tool_name,
                "called": called,
                "max_calls": tool_perm.max_calls_per_session,
                "remaining": max(0, tool_perm.max_calls_per_session - called),
                "requires_approval": tool_perm.requires_approval,
                "base_risk": tool_perm.base_risk.value,
            })

        return {
            "session_id": session_id,
            "total_calls": total_calls,
            "tool_calls": call_counts,
            "tool_summaries": tool_summaries,
            "context_permission": {
                "allowed_permissions": [p.value for p in context.allowed_permissions],
                "denied_permissions": [p.value for p in context.denied_permissions],
                "max_risk_allowed": context.max_risk_allowed.value,
                "reason": context.reason,
            } if context else None,
            "registered_tools": list(self._tool_permissions.keys()),
        }
