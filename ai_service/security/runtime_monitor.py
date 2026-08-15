"""
运行时监控器 (Runtime Monitor)
================================

监控 LLM Agent 的 ReAct (Think-Act-Observe) 循环，实时检测异常决策、
构建任务执行链路图、识别级联故障模式 (OWASP ASI08)，并提供一键终止能力。

核心能力：
1. ReAct 循环追踪：记录 Think / Act / Observe 三阶段的完整轨迹
2. 异常决策检测：8 类异常模式（突发删除、权限滥用、数据外泄、上下文漂移等）
3. 任务链路图构建：将工具调用归类为标准动作，构建可分析的任务链
4. 级联故障检测 (ASI08)：识别"读敏感数据→导出→外传"等危险链路组合
5. 一键终止：检测到 CRITICAL 风险时自动判定终止，或人工强制终止会话

设计原则：
- 与操作守卫(operation_guard)互补：操作守卫管"单次动作是否危险"，
  运行时监控管"整条决策链是否异常"——即使每一步单独看都合规，
  组合起来也可能构成攻击链
- 线程安全：所有会话数据访问加锁
- 自清理：超过 1 小时的空闲会话自动回收，避免内存泄漏
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import threading
import uuid
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field

from models.schemas import RiskLevel, AttackType


# ============================================================================
# 数据结构
# ============================================================================

@dataclass
class ReActStep:
    """ReAct 循环的一步"""
    step_id: int
    session_id: str
    step_type: str  # "think", "act", "observe"
    tool_name: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    reasoning: str = ""
    result: Optional[Dict[str, Any]] = None
    timestamp: float = field(default_factory=time.time)
    risk_level: RiskLevel = RiskLevel.NONE


@dataclass
class AnomalyAlert:
    """异常决策告警"""
    alert_type: str  # "sudden_delete", "admin_misuse", "privilege_escalation",
                     # "data_exfiltration", "context_drift", "tool_sequence_anomaly",
                     # "repeated_failure", "excessive_agency"
    severity: RiskLevel
    description: str
    step_id: int
    evidence: List[str] = field(default_factory=list)


@dataclass
class TaskChainNode:
    """任务链节点"""
    step_id: int
    tool_name: str
    action_category: str  # "read", "write", "execute", "export", "network", "admin", "delete"
    target: str
    risk_level: RiskLevel
    timestamp: float


@dataclass
class CascadeFailurePattern:
    """级联故障模式 (OWASP ASI08)"""
    name: str
    description: str
    node_sequence: List[str]  # 构成危险链路的动作类别序列
    severity: RiskLevel


# ============================================================================
# 动作分类规则
# ============================================================================

# 将工具名映射为标准动作类别的关键词规则
# 顺序敏感：先匹配更具体的（如 export 优先于 write）
ACTION_KEYWORD_RULES: List[Tuple[str, str]] = [
    # 删除类（优先匹配，避免被 write 覆盖）
    ("delete", "delete"),
    ("remove", "delete"),
    ("destroy", "delete"),
    ("clear", "delete"),
    ("drop", "delete"),
    ("truncate", "delete"),
    ("purge", "delete"),
    ("wipe", "delete"),
    # 管理类
    ("admin", "admin"),
    ("grant", "admin"),
    ("permission", "admin"),
    ("role", "admin"),
    ("privilege", "admin"),
    ("sudo", "admin"),
    ("chmod", "admin"),
    ("chown", "admin"),
    # 导出类
    ("export", "export"),
    ("download", "export"),
    ("backup", "export"),
    ("dump", "export"),
    ("archive", "export"),
    # 网络类
    ("send", "network"),
    ("network", "network"),
    ("http", "network"),
    ("url", "network"),
    ("request", "network"),
    ("email", "network"),
    ("upload", "network"),
    ("webhook", "network"),
    ("curl", "network"),
    ("wget", "network"),
    # 执行类
    ("execute", "execute"),
    ("command", "execute"),
    ("run", "execute"),
    ("exec", "execute"),
    ("shell", "execute"),
    ("script", "execute"),
    ("subprocess", "execute"),
    ("eval", "execute"),
    # 写入类
    ("write", "write"),
    ("create", "write"),
    ("save", "write"),
    ("modify", "write"),
    ("update", "write"),
    ("insert", "write"),
    ("patch", "write"),
    ("set", "write"),
    # 读取类（默认兜底）
    ("read", "read"),
    ("get", "read"),
    ("list", "read"),
    ("search", "read"),
    ("query", "read"),
    ("fetch", "read"),
    ("view", "read"),
    ("scan", "read"),
]

# 默认动作类别：无法匹配任何关键词时
DEFAULT_ACTION_CATEGORY = "read"


def classify_action_category(tool_name: str) -> str:
    """将工具名归类为标准动作类别

    参数:
        tool_name: 工具/MCP/Skill 名称

    返回:
        动作类别: read / write / execute / export / network / admin / delete
    """
    name_lower = tool_name.lower()
    for keyword, category in ACTION_KEYWORD_RULES:
        if keyword in name_lower:
            return category
    return DEFAULT_ACTION_CATEGORY


# ============================================================================
# 级联故障模式定义 (OWASP ASI08)
# ============================================================================

CASCADE_PATTERNS: List[CascadeFailurePattern] = [
    CascadeFailurePattern(
        name="data_exfil_chain",
        description="读取敏感数据→导出→外传",
        node_sequence=["read", "export", "network"],
        severity=RiskLevel.CRITICAL,
    ),
    CascadeFailurePattern(
        name="privilege_escalation_chain",
        description="正常操作→权限修改→管理员操作",
        node_sequence=["read", "admin", "execute"],
        severity=RiskLevel.CRITICAL,
    ),
    CascadeFailurePattern(
        name="reconnaissance_to_attack",
        description="信息收集→漏洞利用→持久化",
        node_sequence=["read", "execute", "write"],
        severity=RiskLevel.HIGH,
    ),
    CascadeFailurePattern(
        name="failure_to_bypass",
        description="操作失败→权限提升→重试",
        node_sequence=["execute", "admin", "execute"],
        severity=RiskLevel.HIGH,
    ),
]


# ============================================================================
# 危险工具关键词（用于上下文漂移等检测）
# ============================================================================

DANGEROUS_TOOL_KEYWORDS = [
    "delete", "remove", "destroy", "drop", "purge", "wipe",
    "execute", "command", "shell", "exec", "eval",
    "admin", "grant", "permission", "role", "sudo", "chmod",
    "export", "download", "dump", "backup",
    "send", "network", "http", "url", "email", "upload",
]

# 管理类关键词（用于 admin_misuse 检测）
ADMIN_KEYWORDS = [
    "admin", "grant", "permission", "role", "privilege", "sudo", "chmod", "chown",
    "权限", "角色", "管理员", "授权", "提权", "超级用户",
]

# 删除类关键词（用于 sudden_delete 检测）
DELETE_KEYWORDS = [
    "delete", "remove", "clear", "destroy", "drop", "truncate", "purge", "wipe",
    "删除", "清除", "销毁", "清空", "移除", "擦除",
]

# 敏感数据读取关键词（用于 data_exfiltration 检测）
SENSITIVE_READ_KEYWORDS = ["secret", "credential", "password", "token", "key", "config", "env", "private"]

# Think 推理中的高危意图关键词（用于 dangerous_reasoning 检测）
# 按严重程度分组：CRITICAL / HIGH / MEDIUM
DANGEROUS_REASONING_PATTERNS = {
    "critical": [
        # 删除/破坏意图
        r"(?:删除|清除|销毁|清空|擦除|移除|格式化).{0,20}(?:所有|全部|整个|一切|服务器|系统|日志|数据库|文件)",
        r"(?:delete|remove|destroy|purge|wipe|format).{0,20}(?:all|every|entire|server|system|log|database|file)",
        r"rm\s+-rf",
        # 提权意图
        r"(?:获取|得到|提升|升级|grant|escalate|obtain).{0,15}(?:管理员|root|admin|privilege|权限|超级用户)",
        r"(?:sudo|su\s+root|chmod\s+[4567]7[57]7)",
        # 反弹shell/后门
        r"(?:反弹|reverse|bind).{0,10}(?:shell|后门|backdoor)",
        r"(?:nc|netcat|bash|sh)\s+-[ei]",
        # 数据外传意图
        r"(?:外传|外泄|上传到|发送到|导出到|transfer|exfiltrate|upload\s+to|send\s+to).{0,20}(?:外部|外网|attacker|hacker|远程|remote|外部服务器)",
    ],
    "high": [
        # 执行系统命令意图
        r"(?:执行|运行|invoke|execute|run).{0,15}(?:系统命令|脚本|shell|bash|cmd|command|script)",
        r"(?:os\.system|subprocess|eval\s*\(|exec\s*\()",
        # 修改权限/配置意图
        r"(?:修改|变更|更改|modify|change|update).{0,15}(?:权限|角色|配置|策略|密码|密钥|permission|role|config|password|key)",
        # 导出/下载意图
        r"(?:导出|下载|备份|export|download|backup|dump).{0,15}(?:所有|全部|用户|数据|数据库|all|user|data|database)",
        # 网络请求到外部
        r"(?:请求|访问|连接|request|access|connect).{0,15}(?:外部|第三方|可疑|external|third.party|suspicious)",
    ],
    "medium": [
        # 读取敏感信息意图
        r"(?:读取|查看|获取|read|view|get|fetch).{0,15}(?:密码|密钥|凭据|token|secret|credential|password|key)",
        # 扫描/探测意图
        r"(?:扫描|探测|scan|probe|enumerate).{0,15}(?:端口|服务|漏洞|port|service|vulnerability)",
        # 绕过意图
        r"(?:绕过|bypass|规避|evade|escape).{0,15}(?:检测|防护|安全|限制|detection|protection|security|limit)",
    ],
}

# 渐进诱导关键词（用于 gradual_escalation 检测）
# 这些关键词按"诱导深度"分层，越靠后风险越高
ESCALATION_INDICATORS = [
    # 第1层：试探性提问
    (1, [r"(?:能|可以|是否|how\s+to|can\s+you|is\s+it\s+possible).{0,20}(?:执行|删除|修改|获取|execute|delete|modify|get)"]),
    # 第2层：明确请求操作
    (2, [r"(?:帮我|请|让|assist|please|help).{0,15}(?:执行|删除|修改|导出|execute|delete|modify|export)"]),
    # 第3层：给出具体方法/参数
    (3, [r"(?:使用|用|use|with).{0,15}(?:命令|脚本|参数|工具|command|script|parameter|tool)"]),
    # 第4层：催促/强调必要性
    (4, [r"(?:必须|立即|马上|现在|需要|necessary|must|immediately|now|need).{0,15}(?:执行|删除|操作|execute|delete|operate)"]),
]

# 会话最大步数阈值（超过则判定为可能死循环，触发终止）
MAX_STEPS_THRESHOLD = 50

# 会话自动清理间隔（秒）：超过此时间无活动的会话将被回收
SESSION_TTL_SECONDS = 3600  # 1 小时

# 连续失败阈值（用于 repeated_failure 检测）
REPEATED_FAILURE_THRESHOLD = 3

# 重复工具调用阈值（用于 tool_sequence_anomaly 检测）
REPEATED_TOOL_THRESHOLD = 5

# 过度代理的工具数量阈值（用于 excessive_agency 检测）
EXCESSIVE_AGENCY_TOOL_COUNT = 3

# 零宽字符集合（用于剥离 Think 推理中的不可见字符，防止绕过推理检测）
_ZERO_WIDTH_RE = re.compile(
    r"[\u200B\u200C\u200D\uFEFF\u2060\u200E\u200F\u2061\u2062\u2063\u2064]"
)


def _strip_zero_width(text: str) -> str:
    """剥离文本中的零宽字符（用于推理内容检测前处理）"""
    if not text:
        return text
    return _ZERO_WIDTH_RE.sub("", text)


# ============================================================================
# 主类：RuntimeMonitor
# ============================================================================

class RuntimeMonitor:
    """运行时监控器（单例）

    监控 Agent ReAct 循环，检测异常决策与级联故障，支持一键终止。
    所有方法线程安全。
    """

    _RISK_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    def __init__(self):
        # 会话 → ReAct 步骤列表
        self._sessions: Dict[str, List[ReActStep]] = {}
        # 会话 → 终止原因（非空表示已终止）
        self._terminated: Dict[str, str] = {}
        # 会话 → 用户原始输入（用于上下文漂移检测）
        self._user_inputs: Dict[str, str] = {}
        # 会话 → 可用工具列表（用于 excessive_agency 检测）
        self._available_tools: Dict[str, List[str]] = {}
        # 会话 → 缓存的异常告警（避免重复检测）
        self._cached_alerts: Dict[str, List[AnomalyAlert]] = {}
        # 会话 → 最后活动时间戳（用于自动清理）
        self._last_activity: Dict[str, float] = {}
        # 全局步数计数器（用于生成 step_id）
        self._step_counter: int = 0
        # 线程锁（使用可重入锁，因为部分检测方法会调用其他加锁方法）
        self._lock = threading.RLock()

    # ------------------------------------------------------------------
    # 内部辅助方法
    # ------------------------------------------------------------------

    def _next_step_id(self) -> int:
        """生成全局唯一 step_id"""
        self._step_counter += 1
        return self._step_counter

    def _touch_session(self, session_id: str) -> None:
        """更新会话最后活动时间"""
        self._last_activity[session_id] = time.time()

    def _ensure_session(self, session_id: str) -> None:
        """确保会话数据结构已初始化"""
        if session_id not in self._sessions:
            self._sessions[session_id] = []
        if session_id not in self._cached_alerts:
            self._cached_alerts[session_id] = []
        self._touch_session(session_id)

    def _cleanup_expired_sessions(self) -> None:
        """清理超过 TTL 的空闲会话（调用方需持有锁）"""
        now = time.time()
        expired = [
            sid for sid, ts in self._last_activity.items()
            if now - ts > SESSION_TTL_SECONDS
        ]
        for sid in expired:
            self._sessions.pop(sid, None)
            self._terminated.pop(sid, None)
            self._user_inputs.pop(sid, None)
            self._available_tools.pop(sid, None)
            self._cached_alerts.pop(sid, None)
            self._last_activity.pop(sid, None)

    def _get_act_steps(self, session_id: str) -> List[ReActStep]:
        """获取会话中所有 Act 阶段的步骤"""
        return [s for s in self._sessions.get(session_id, []) if s.step_type == "act"]

    @staticmethod
    def _extract_target(parameters: Dict[str, Any]) -> str:
        """从工具参数中提取操作目标描述"""
        # 按优先级尝试常见参数名
        for key in ("path", "file_path", "filepath", "filename", "target",
                    "url", "endpoint", "table", "collection", "command",
                    "query", "user_id", "role", "name"):
            if key in parameters:
                return str(parameters[key])
        return ""

    @staticmethod
    def _parameters_contain_url(parameters: Dict[str, Any]) -> bool:
        """检查参数中是否包含 URL"""
        url_keywords = ("http://", "https://", "ftp://", "ws://", "wss://")
        for value in parameters.values():
            value_str = str(value)
            if any(kw in value_str for kw in url_keywords):
                return True
        return False

    # ------------------------------------------------------------------
    # 1-3. ReAct 三阶段记录
    # ------------------------------------------------------------------

    def record_think(self, session_id: str, reasoning: str,
                     proposed_tool_calls: List[str]) -> int:
        """记录 Think 阶段

        参数:
            session_id: 会话 ID
            reasoning: Agent 的推理文本
            proposed_tool_calls: 本轮计划调用的工具列表

        返回:
            新建步骤的 step_id
        """
        with self._lock:
            self._cleanup_expired_sessions()
            self._ensure_session(session_id)

            # 首次 Think 时记录用户输入（若已设置）
            step = ReActStep(
                step_id=self._next_step_id(),
                session_id=session_id,
                step_type="think",
                reasoning=reasoning,
                parameters={"proposed_tool_calls": proposed_tool_calls},
            )
            self._sessions[session_id].append(step)
            return step.step_id

    def record_act(self, session_id: str, tool_name: str,
                   parameters: Dict[str, Any]) -> int:
        """记录 Act 阶段

        参数:
            session_id: 会话 ID
            tool_name: 实际调用的工具名
            parameters: 工具参数

        返回:
            新建步骤的 step_id
        """
        with self._lock:
            self._ensure_session(session_id)

            step = ReActStep(
                step_id=self._next_step_id(),
                session_id=session_id,
                step_type="act",
                tool_name=tool_name,
                parameters=parameters or {},
            )
            self._sessions[session_id].append(step)
            return step.step_id

    def record_observe(self, session_id: str, tool_name: str,
                       result: Dict[str, Any], success: bool) -> int:
        """记录 Observe 阶段

        参数:
            session_id: 会话 ID
            tool_name: 对应的工具名
            result: 工具执行结果
            success: 是否执行成功

        返回:
            新建步骤的 step_id
        """
        with self._lock:
            self._ensure_session(session_id)

            # 根据成功/失败标记结果
            enriched_result = dict(result or {})
            enriched_result["_success"] = success

            step = ReActStep(
                step_id=self._next_step_id(),
                session_id=session_id,
                step_type="observe",
                tool_name=tool_name,
                result=enriched_result,
                risk_level=RiskLevel.NONE,
            )
            self._sessions[session_id].append(step)
            return step.step_id

    # ------------------------------------------------------------------
    # 会话上下文设置
    # ------------------------------------------------------------------

    def set_user_input(self, session_id: str, user_input: str) -> None:
        """设置会话的用户原始输入（用于上下文漂移检测）"""
        with self._lock:
            self._ensure_session(session_id)
            self._user_inputs[session_id] = user_input

    def set_available_tools(self, session_id: str, tools: List[str]) -> None:
        """设置会话的可用工具列表（用于 excessive_agency 检测）"""
        with self._lock:
            self._ensure_session(session_id)
            self._available_tools[session_id] = list(tools)

    # ------------------------------------------------------------------
    # 4. 异常检测
    # ------------------------------------------------------------------

    def check_anomalies(self, session_id: str) -> List[AnomalyAlert]:
        """检测会话中的异常决策

        对当前会话执行全部 8 类异常检测，返回所有命中的告警。
        结果会缓存，避免对同一会话重复全量计算。
        """
        with self._lock:
            self._ensure_session(session_id)
            steps = self._sessions.get(session_id, [])
            if not steps:
                return []

            alerts: List[AnomalyAlert] = []
            act_steps = self._get_act_steps(session_id)
            user_input = self._user_inputs.get(session_id, "")
            available_tools = self._available_tools.get(session_id, [])

            # 依次执行各类检测
            alerts.extend(self._detect_sudden_delete(session_id, act_steps))
            alerts.extend(self._detect_admin_misuse(session_id, act_steps, user_input))
            alerts.extend(self._detect_privilege_escalation(session_id, act_steps))
            alerts.extend(self._detect_data_exfiltration(session_id, act_steps))
            alerts.extend(self._detect_context_drift(session_id, steps, user_input))
            alerts.extend(self._detect_tool_sequence_anomaly(session_id, act_steps))
            alerts.extend(self._detect_repeated_failure(session_id, steps))
            alerts.extend(self._detect_excessive_agency(session_id, act_steps,
                                                        user_input, available_tools))
            # T4 新增：Think 推理内容分析
            think_steps = [s for s in steps if s.step_type == "think"]
            alerts.extend(self._detect_dangerous_reasoning(session_id, think_steps))
            alerts.extend(self._detect_gradual_escalation(session_id, think_steps))

            # 缓存告警
            self._cached_alerts[session_id] = alerts
            return alerts

    def _detect_sudden_delete(self, session_id: str,
                              act_steps: List[ReActStep]) -> List[AnomalyAlert]:
        """检测突发删除：上下文为只读操作时突然调用删除工具"""
        alerts: List[AnomalyAlert] = []
        for i, step in enumerate(act_steps):
            tool_lower = step.tool_name.lower()
            if not any(kw in tool_lower for kw in DELETE_KEYWORDS):
                continue
            # 检查此删除之前的步骤是否都是只读
            prior = act_steps[:i]
            if not prior:
                continue
            prior_categories = [classify_action_category(s.tool_name) for s in prior]
            if all(c == "read" for c in prior_categories) and len(prior) >= 1:
                alerts.append(AnomalyAlert(
                    alert_type="sudden_delete",
                    severity=RiskLevel.HIGH,
                    description=f"步骤 {step.step_id} 在只读上下文中突然调用删除工具 '{step.tool_name}'，"
                                f"前 {len(prior)} 步均为只读操作",
                    step_id=step.step_id,
                    evidence=[
                        f"删除工具: {step.tool_name}",
                        f"前置操作均为只读: {prior_categories}",
                    ],
                ))
        return alerts

    def _detect_admin_misuse(self, session_id: str, act_steps: List[ReActStep],
                             user_input: str) -> List[AnomalyAlert]:
        """检测管理类工具滥用：用户输入未提及管理操作却调用了管理工具"""
        alerts: List[AnomalyAlert] = []
        user_lower = user_input.lower()
        user_mentions_admin = any(kw in user_lower for kw in ADMIN_KEYWORDS)

        for step in act_steps:
            tool_lower = step.tool_name.lower()
            if not any(kw in tool_lower for kw in ADMIN_KEYWORDS):
                continue
            if not user_mentions_admin:
                alerts.append(AnomalyAlert(
                    alert_type="admin_misuse",
                    severity=RiskLevel.HIGH,
                    description=f"步骤 {step.step_id} 调用管理类工具 '{step.tool_name}'，"
                                f"但用户输入未涉及管理操作",
                    step_id=step.step_id,
                    evidence=[
                        f"管理工具: {step.tool_name}",
                        f"用户输入: {user_input[:100]}",
                    ],
                ))
        return alerts

    def _detect_privilege_escalation(self, session_id: str,
                                     act_steps: List[ReActStep]) -> List[AnomalyAlert]:
        """检测权限提升链：read_user → modify_permission → set_admin 等序列"""
        alerts: List[AnomalyAlert] = []
        # 权限提升的特征序列：read → admin（先读取用户/配置，再修改权限）
        categories = [classify_action_category(s.tool_name) for s in act_steps]

        # 查找 read → admin 的序列
        for i in range(len(categories) - 1):
            if categories[i] == "read" and categories[i + 1] == "admin":
                step = act_steps[i + 1]
                alerts.append(AnomalyAlert(
                    alert_type="privilege_escalation",
                    severity=RiskLevel.CRITICAL,
                    description=f"步骤 {step.step_id} 疑似权限提升：先读取用户/配置后立即修改权限 "
                                f"('{act_steps[i].tool_name}' → '{step.tool_name}')",
                    step_id=step.step_id,
                    evidence=[
                        f"读取操作: {act_steps[i].tool_name}",
                        f"权限操作: {step.tool_name}",
                    ],
                ))
        return alerts

    def _detect_data_exfiltration(self, session_id: str,
                                  act_steps: List[ReActStep]) -> List[AnomalyAlert]:
        """检测数据外泄：read_sensitive → export → network 序列，或参数含 URL+导出"""
        alerts: List[AnomalyAlert] = []
        categories = [classify_action_category(s.tool_name) for s in act_steps]

        # 模式1: read → export → network 完整链路
        for i in range(len(categories) - 2):
            if (categories[i] == "read" and categories[i + 1] == "export"
                    and categories[i + 2] == "network"):
                step = act_steps[i + 2]
                alerts.append(AnomalyAlert(
                    alert_type="data_exfiltration",
                    severity=RiskLevel.CRITICAL,
                    description=f"步骤 {step.step_id} 检测到数据外泄链路："
                                f"'{act_steps[i].tool_name}' → '{act_steps[i + 1].tool_name}' → "
                                f"'{step.tool_name}'",
                    step_id=step.step_id,
                    evidence=[
                        f"读取: {act_steps[i].tool_name}",
                        f"导出: {act_steps[i + 1].tool_name}",
                        f"外传: {step.tool_name}",
                    ],
                ))

        # 模式2: 同一会话中参数含 URL 且存在导出操作
        has_export = any(c == "export" for c in categories)
        if has_export:
            for step in act_steps:
                if self._parameters_contain_url(step.parameters):
                    alerts.append(AnomalyAlert(
                        alert_type="data_exfiltration",
                        severity=RiskLevel.HIGH,
                        description=f"步骤 {step.step_id} 参数中包含 URL，且同会话存在导出操作，"
                                    f"疑似数据外传",
                        step_id=step.step_id,
                        evidence=[
                            f"工具: {step.tool_name}",
                            "参数包含 URL",
                            "同会话存在导出操作",
                        ],
                    ))
                    break  # 同一会话此模式只告警一次

        # 模式3: 读取敏感数据后立即网络操作
        for i in range(len(categories) - 1):
            if categories[i] == "read" and categories[i + 1] == "network":
                read_tool = act_steps[i].tool_name.lower()
                if any(kw in read_tool for kw in SENSITIVE_READ_KEYWORDS):
                    step = act_steps[i + 1]
                    alerts.append(AnomalyAlert(
                        alert_type="data_exfiltration",
                        severity=RiskLevel.CRITICAL,
                        description=f"步骤 {step.step_id} 读取敏感数据后立即网络外传: "
                                    f"'{act_steps[i].tool_name}' → '{step.tool_name}'",
                        step_id=step.step_id,
                        evidence=[
                            f"敏感读取: {act_steps[i].tool_name}",
                            f"网络操作: {step.tool_name}",
                        ],
                    ))
        return alerts

    def _detect_context_drift(self, session_id: str, steps: List[ReActStep],
                              user_input: str) -> List[AnomalyAlert]:
        """检测上下文漂移：推理文本偏离用户话题，却调用危险工具"""
        alerts: List[AnomalyAlert] = []
        if not user_input:
            return alerts

        # 从用户输入提取关键词（简单分词）
        user_keywords = set(self._extract_keywords(user_input))

        for step in steps:
            if step.step_type != "act":
                continue
            tool_lower = step.tool_name.lower()
            is_dangerous = any(kw in tool_lower for kw in DANGEROUS_TOOL_KEYWORDS)
            if not is_dangerous:
                continue

            # 找到该 Act 步骤前最近的 Think
            think_reasoning = ""
            for s in reversed(steps):
                if s.step_id < step.step_id and s.step_type == "think":
                    think_reasoning = s.reasoning
                    break

            if not think_reasoning:
                continue

            think_keywords = set(self._extract_keywords(think_reasoning))
            # 用户输入与推理的关键词重叠度
            overlap = len(user_keywords & think_keywords)
            # 若无重叠且工具危险，判定为上下文漂移
            if overlap == 0 and len(user_keywords) > 0:
                alerts.append(AnomalyAlert(
                    alert_type="context_drift",
                    severity=RiskLevel.MEDIUM,
                    description=f"步骤 {step.step_id} 推理内容与用户输入话题不符，"
                                f"却调用了危险工具 '{step.tool_name}'",
                    step_id=step.step_id,
                    evidence=[
                        f"用户输入关键词: {list(user_keywords)[:5]}",
                        f"推理关键词: {list(think_keywords)[:5]}",
                        f"危险工具: {step.tool_name}",
                    ],
                ))
        return alerts

    @staticmethod
    def _extract_keywords(text: str) -> List[str]:
        """从文本中提取关键词（简单实现：按空格/标点分词，过滤短词）"""
        import re
        # 按非字母数字汉字分割
        tokens = re.split(r'[\s,.;:!?()\[\]{}"\'`/\\|<>@#$%^&*+=~\-]+', text)
        # 过滤空字符串和过短的词
        return [t.lower() for t in tokens if len(t) >= 2]

    def _detect_tool_sequence_anomaly(self, session_id: str,
                                      act_steps: List[ReActStep]) -> List[AnomalyAlert]:
        """检测工具序列异常：write_file 紧跟 execute_command、同一工具连续调用过多"""
        alerts: List[AnomalyAlert] = []

        # 模式1: execute 后立即 write（可能写入恶意内容）
        # 模式2: read(敏感) 后立即 export
        for i in range(len(act_steps) - 1):
            curr_cat = classify_action_category(act_steps[i].tool_name)
            next_cat = classify_action_category(act_steps[i + 1].tool_name)

            if curr_cat == "execute" and next_cat == "write":
                alerts.append(AnomalyAlert(
                    alert_type="tool_sequence_anomaly",
                    severity=RiskLevel.MEDIUM,
                    description=f"步骤 {act_steps[i + 1].step_id} 执行命令后立即写入文件，"
                                f"疑似写入恶意内容",
                    step_id=act_steps[i + 1].step_id,
                    evidence=[
                        f"执行: {act_steps[i].tool_name}",
                        f"写入: {act_steps[i + 1].tool_name}",
                    ],
                ))

            if curr_cat == "read" and next_cat == "export":
                read_tool = act_steps[i].tool_name.lower()
                if any(kw in read_tool for kw in SENSITIVE_READ_KEYWORDS):
                    alerts.append(AnomalyAlert(
                        alert_type="tool_sequence_anomaly",
                        severity=RiskLevel.HIGH,
                        description=f"步骤 {act_steps[i + 1].step_id} 读取敏感数据后立即导出",
                        step_id=act_steps[i + 1].step_id,
                        evidence=[
                            f"敏感读取: {act_steps[i].tool_name}",
                            f"导出: {act_steps[i + 1].tool_name}",
                        ],
                    ))

        # 模式3: 同一工具连续调用超过阈值（疑似循环）
        if len(act_steps) >= REPEATED_TOOL_THRESHOLD:
            for i in range(len(act_steps) - REPEATED_TOOL_THRESHOLD + 1):
                window = act_steps[i:i + REPEATED_TOOL_THRESHOLD]
                tool_names = [s.tool_name for s in window]
                if len(set(tool_names)) == 1:
                    alerts.append(AnomalyAlert(
                        alert_type="tool_sequence_anomaly",
                        severity=RiskLevel.MEDIUM,
                        description=f"步骤 {window[-1].step_id} 工具 '{window[-1].tool_name}' "
                                    f"连续调用 {REPEATED_TOOL_THRESHOLD} 次，疑似循环",
                        step_id=window[-1].step_id,
                        evidence=[
                            f"重复工具: {window[-1].tool_name}",
                            f"连续次数: {REPEATED_TOOL_THRESHOLD}",
                        ],
                    ))
                    break  # 同一工具循环只告警一次
        return alerts

    def _detect_repeated_failure(self, session_id: str,
                                 steps: List[ReActStep]) -> List[AnomalyAlert]:
        """检测连续失败：同一工具连续失败超过阈值（疑似暴力破解）"""
        alerts: List[AnomalyAlert] = []
        # 提取所有 Observe 步骤并关联其失败状态
        observe_steps = [s for s in steps if s.step_type == "observe" and s.result]
        if len(observe_steps) < REPEATED_FAILURE_THRESHOLD:
            return alerts

        # 按工具名分组连续失败
        consecutive_failures: List[Tuple[str, int, int]] = []  # (tool_name, count, last_step_id)
        current_tool = ""
        current_count = 0
        current_last_step = 0

        for obs in observe_steps:
            success = obs.result.get("_success", True)
            if not success:
                if obs.tool_name == current_tool:
                    current_count += 1
                else:
                    if current_count >= REPEATED_FAILURE_THRESHOLD:
                        consecutive_failures.append((current_tool, current_count, current_last_step))
                    current_tool = obs.tool_name
                    current_count = 1
                current_last_step = obs.step_id
            else:
                if current_count >= REPEATED_FAILURE_THRESHOLD:
                    consecutive_failures.append((current_tool, current_count, current_last_step))
                current_tool = ""
                current_count = 0

        # 收尾检查
        if current_count >= REPEATED_FAILURE_THRESHOLD:
            consecutive_failures.append((current_tool, current_count, current_last_step))

        for tool_name, count, step_id in consecutive_failures:
            alerts.append(AnomalyAlert(
                alert_type="repeated_failure",
                severity=RiskLevel.HIGH,
                description=f"步骤 {step_id} 工具 '{tool_name}' 连续失败 {count} 次，疑似暴力破解或探测",
                step_id=step_id,
                evidence=[
                    f"失败工具: {tool_name}",
                    f"连续失败次数: {count}",
                ],
            ))
        return alerts

    def _detect_excessive_agency(self, session_id: str, act_steps: List[ReActStep],
                                 user_input: str,
                                 available_tools: List[str]) -> List[AnomalyAlert]:
        """检测过度代理 (ASI08)：简单问题调用过多工具、或调用了不在可用列表中的工具"""
        alerts: List[AnomalyAlert] = []

        # 模式1: 简单问题但调用工具过多
        # 判定"简单问题"：用户输入较短（<50字符）且不含"批量/所有/全部/列表"等批量词
        if user_input:
            is_simple = len(user_input) < 50
            batch_keywords = ["批量", "所有", "全部", "列表", "batch", "all", "list", "every"]
            is_simple = is_simple and not any(kw in user_input.lower() for kw in batch_keywords)
            if is_simple and len(act_steps) > EXCESSIVE_AGENCY_TOOL_COUNT:
                alerts.append(AnomalyAlert(
                    alert_type="excessive_agency",
                    severity=RiskLevel.MEDIUM,
                    description=f"用户提出简单问题，但 Agent 已调用 {len(act_steps)} 个工具，"
                                f"超出必要范围 (ASI08 过度代理)",
                    step_id=act_steps[-1].step_id,
                    evidence=[
                        f"用户输入长度: {len(user_input)}",
                        f"工具调用次数: {len(act_steps)}",
                        f"工具列表: {[s.tool_name for s in act_steps]}",
                    ],
                ))

        # 模式2: 调用了不在可用工具列表中的工具
        if available_tools:
            available_lower = {t.lower() for t in available_tools}
            for step in act_steps:
                if step.tool_name.lower() not in available_lower:
                    alerts.append(AnomalyAlert(
                        alert_type="excessive_agency",
                        severity=RiskLevel.HIGH,
                        description=f"步骤 {step.step_id} 调用了未声明的工具 '{step.tool_name}'，"
                                    f"超出可用工具范围 (ASI08)",
                        step_id=step.step_id,
                        evidence=[
                            f"未声明工具: {step.tool_name}",
                            f"可用工具数: {len(available_tools)}",
                        ],
                    ))
        return alerts

    def _detect_dangerous_reasoning(self, session_id: str,
                                     think_steps: List[ReActStep]) -> List[AnomalyAlert]:
        """检测 Think 推理中的高危意图

        解析推理文本，匹配删除/提权/外传/执行命令等危险意图关键词。
        这是 T4 的核心增强——很多攻击在 Think 阶段完成诱导，
        工具参数表面无害，但推理文本已暴露恶意意图。
        """
        import re
        alerts: List[AnomalyAlert] = []

        severity_map = {
            "critical": RiskLevel.CRITICAL,
            "high": RiskLevel.HIGH,
            "medium": RiskLevel.MEDIUM,
        }

        for step in think_steps:
            if not step.reasoning:
                continue
            # 剥离零宽字符后再匹配，防止通过不可见字符拆分高危指令绕过检测
            reasoning = _strip_zero_width(step.reasoning)
            reasoning_lower = reasoning.lower()

            # 按严重程度从高到低检测，同一 Think 步骤每个级别只告警一次
            detected_patterns: List[str] = []
            highest_severity = RiskLevel.NONE

            for level in ("critical", "high", "medium"):
                patterns = DANGEROUS_REASONING_PATTERNS.get(level, [])
                for pattern in patterns:
                    if re.search(pattern, reasoning, re.IGNORECASE):
                        detected_patterns.append(f"[{level}] {pattern}")
                        if self._RISK_ORDER.get(severity_map[level].value, 0) > \
                           self._RISK_ORDER.get(highest_severity.value, 0):
                            highest_severity = severity_map[level]

            if detected_patterns and highest_severity != RiskLevel.NONE:
                alerts.append(AnomalyAlert(
                    alert_type="dangerous_reasoning",
                    severity=highest_severity,
                    description=f"步骤 {step.step_id} Think 推理中检测到高危意图"
                                f"（{highest_severity.value}），疑似恶意诱导",
                    step_id=step.step_id,
                    evidence=[
                        f"匹配模式: {detected_patterns[0]}",
                        f"推理片段: {reasoning[:200]}",
                    ],
                ))
        return alerts

    def _detect_gradual_escalation(self, session_id: str,
                                    think_steps: List[ReActStep]) -> List[AnomalyAlert]:
        """检测渐进诱导：多轮 Think 中风险逐步升级

        攻击者通过多轮对话逐步诱导 Agent 执行高危操作，
        每一步单独看不危险，但累计后风险升高。
        检测逻辑：分析多轮 Think 的诱导深度是否逐步递增。
        """
        import re
        alerts: List[AnomalyAlert] = []

        if len(think_steps) < 2:
            return alerts

        # 为每个 Think 步骤计算诱导深度分数
        depth_scores: List[Tuple[int, int, str]] = []  # (step_id, depth, reasoning_preview)
        for step in think_steps:
            if not step.reasoning:
                depth_scores.append((step.step_id, 0, ""))
                continue
            # 剥离零宽字符后再计算诱导深度，防止拆分绕过
            cleaned = _strip_zero_width(step.reasoning)
            max_depth = 0
            for depth, patterns in ESCALATION_INDICATORS:
                for pattern in patterns:
                    if re.search(pattern, cleaned, re.IGNORECASE):
                        if depth > max_depth:
                            max_depth = depth
                        break
            depth_scores.append((step.step_id, max_depth, cleaned[:100]))

        # 检测深度递增序列：至少3步，深度从低到高
        if len(depth_scores) >= 3:
            for i in range(len(depth_scores) - 2):
                d1 = depth_scores[i][1]
                d2 = depth_scores[i + 1][1]
                d3 = depth_scores[i + 2][1]
                if d1 > 0 and d2 > d1 and d3 > d2:
                    alerts.append(AnomalyAlert(
                        alert_type="gradual_escalation",
                        severity=RiskLevel.HIGH,
                        description=f"检测到渐进诱导模式：Think 诱导深度 {d1}→{d2}→{d3} 逐步升级",
                        step_id=depth_scores[i+2][0],
                        evidence=[
                            f"步骤{depth_scores[i][0]} 深度{d1}: {depth_scores[i][2]}",
                            f"步骤{depth_scores[i+1][0]} 深度{d2}: {depth_scores[i+1][2]}",
                            f"步骤{depth_scores[i+2][0]} 深度{d3}: {depth_scores[i+2][2]}",
                        ],
                    ))
                    break

        # 检测累积危险推理：多个 Think 步骤都触发危险模式
        danger_count = sum(1 for _, depth, _ in depth_scores if depth > 0)
        if danger_count >= 3:
            alerts.append(AnomalyAlert(
                alert_type="gradual_escalation",
                severity=RiskLevel.MEDIUM,
                description=f"会话中 {danger_count} 个 Think 步骤包含危险诱导关键词，累计风险升高",
                step_id=depth_scores[-1][0],
                evidence=[
                    f"危险Think步骤数: {danger_count}/{len(think_steps)}",
                    f"深度分布: {[d for _, d, _ in depth_scores]}",
                ],
            ))

        return alerts

    # ------------------------------------------------------------------
    # 5. 任务链构建
    # ------------------------------------------------------------------

    def build_task_chain(self, session_id: str) -> List[TaskChainNode]:
        """构建任务执行链路图

        将会话中的 Act 步骤转换为标准化任务链节点，便于链路分析与可视化。
        """
        with self._lock:
            act_steps = self._get_act_steps(session_id)
            nodes: List[TaskChainNode] = []
            for step in act_steps:
                category = classify_action_category(step.tool_name)
                target = self._extract_target(step.parameters)
                nodes.append(TaskChainNode(
                    step_id=step.step_id,
                    tool_name=step.tool_name,
                    action_category=category,
                    target=target,
                    risk_level=step.risk_level,
                    timestamp=step.timestamp,
                ))
            return nodes

    # ------------------------------------------------------------------
    # 6. 级联故障检测 (ASI08)
    # ------------------------------------------------------------------

    def detect_cascade_failure(self, session_id: str) -> Optional[CascadeFailurePattern]:
        """检测级联故障模式 (OWASP ASI08)

        将会话的任务链动作序列与预定义的级联模式做子序列匹配，
        返回第一个命中的模式，无命中返回 None。
        """
        with self._lock:
            nodes = self.build_task_chain(session_id)
            if len(nodes) < 2:
                return None

            action_seq = [n.action_category for n in nodes]

            for pattern in CASCADE_PATTERNS:
                if self._match_subsequence(action_seq, pattern.node_sequence):
                    return pattern
            return None

    @staticmethod
    def _match_subsequence(actions: List[str], pattern: List[str]) -> bool:
        """判断 pattern 是否为 actions 的子序列（允许中间有无关步骤）

        例如 actions=["read","read","export","network"], pattern=["read","export","network"]
        按序匹配即可命中。
        """
        pi = 0
        for action in actions:
            if action == pattern[pi]:
                pi += 1
                if pi == len(pattern):
                    return True
        return False

    # ------------------------------------------------------------------
    # 7-8. 终止判定与执行
    # ------------------------------------------------------------------

    def should_terminate(self, session_id: str) -> Tuple[bool, str]:
        """判定会话是否应当终止

        终止条件（满足任一即返回 True）：
        1. 会话已被显式终止
        2. 检测到 CRITICAL 级别异常
        3. 命中级联故障模式
        4. 会话步数超过 50（疑似死循环）

        返回:
            (是否终止, 原因)
        """
        with self._lock:
            # 条件1: 已被显式终止
            if session_id in self._terminated:
                return True, self._terminated[session_id]

            steps = self._sessions.get(session_id, [])
            if not steps:
                return False, ""

            # 条件4: 步数超限（疑似死循环）
            if len(steps) > MAX_STEPS_THRESHOLD:
                reason = f"会话步数 {len(steps)} 超过阈值 {MAX_STEPS_THRESHOLD}，疑似死循环"
                return True, reason

        # 条件2: CRITICAL 异常（需在锁外调用 check_anomalies 避免死锁，但 check_anomalies 自身加锁）
        alerts = self.check_anomalies(session_id)
        for alert in alerts:
            if alert.severity == RiskLevel.CRITICAL:
                return True, f"检测到 CRITICAL 异常: {alert.alert_type} - {alert.description}"

        # 条件3: 级联故障
        cascade = self.detect_cascade_failure(session_id)
        if cascade is not None:
            return True, f"命中级联故障模式: {cascade.name} - {cascade.description}"

        return False, ""

    def terminate(self, session_id: str, reason: str) -> str:
        """一键终止会话

        参数:
            session_id: 会话 ID
            reason: 终止原因

        返回:
            终止凭证 ID（可用于审计追溯）
        """
        with self._lock:
            self._ensure_session(session_id)
            # 生成终止凭证
            termination_id = f"TERM-{session_id}-{int(time.time())}-{uuid.uuid4().hex[:8]}"
            full_reason = f"[{termination_id}] {reason}"
            self._terminated[session_id] = full_reason
            return termination_id

    def is_terminated(self, session_id: str) -> bool:
        """检查会话是否已被终止"""
        with self._lock:
            return session_id in self._terminated

    # ------------------------------------------------------------------
    # 9-11. 查询与清理
    # ------------------------------------------------------------------

    def get_session_trace(self, session_id: str) -> List[ReActStep]:
        """获取会话的完整执行轨迹"""
        with self._lock:
            return list(self._sessions.get(session_id, []))

    def get_session_summary(self, session_id: str) -> Dict[str, Any]:
        """获取会话摘要信息"""
        with self._lock:
            steps = self._sessions.get(session_id, [])
            act_steps = [s for s in steps if s.step_type == "act"]
            observe_steps = [s for s in steps if s.step_type == "observe"]
            think_steps = [s for s in steps if s.step_type == "think"]

            # 统计工具调用
            tool_counts: Dict[str, int] = {}
            for s in act_steps:
                tool_counts[s.tool_name] = tool_counts.get(s.tool_name, 0) + 1

            # 统计失败次数
            failure_count = sum(
                1 for s in observe_steps
                if s.result and not s.result.get("_success", True)
            )

            # 获取缓存的告警
            cached = self._cached_alerts.get(session_id, [])
            highest_alert = max(
                (a.severity for a in cached),
                default=RiskLevel.NONE,
                key=lambda r: list(RiskLevel).index(r),
            )

            terminated = session_id in self._terminated

            return {
                "session_id": session_id,
                "total_steps": len(steps),
                "think_count": len(think_steps),
                "act_count": len(act_steps),
                "observe_count": len(observe_steps),
                "tool_call_counts": tool_counts,
                "failure_count": failure_count,
                "alert_count": len(cached),
                "highest_alert_severity": highest_alert.value if highest_alert else "none",
                "terminated": terminated,
                "termination_reason": self._terminated.get(session_id, ""),
                "duration_seconds": (steps[-1].timestamp - steps[0].timestamp) if steps else 0.0,
            }

    def clear_session(self, session_id: str) -> None:
        """清除会话所有数据"""
        with self._lock:
            self._sessions.pop(session_id, None)
            self._terminated.pop(session_id, None)
            self._user_inputs.pop(session_id, None)
            self._available_tools.pop(session_id, None)
            self._cached_alerts.pop(session_id, None)
            self._last_activity.pop(session_id, None)


# ============================================================================
# 模块级单例
# ============================================================================

# 全局运行时监控器实例
_runtime_monitor: Optional[RuntimeMonitor] = None
_singleton_lock = threading.Lock()


def get_runtime_monitor() -> RuntimeMonitor:
    """获取全局 RuntimeMonitor 单例"""
    global _runtime_monitor
    if _runtime_monitor is None:
        with _singleton_lock:
            if _runtime_monitor is None:
                _runtime_monitor = RuntimeMonitor()
    return _runtime_monitor
