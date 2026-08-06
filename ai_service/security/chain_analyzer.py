"""
异常任务链路检测引擎 (Chain Analyzer)

分析智能体工具调用序列,检测复合型攻击行为链路:
- 数据外泄: 读敏感文件 → 编码 → 网络外发
- 权限提升: 读取配置 → 修改权限 → 管理员执行
- 数据销毁: 列举文件 → 批量删除
- 后门安装: 下载 → 写入 → 执行

与单次工具风险评估不同,链路检测关注多次调用的组合模式。
"""
from typing import List, Dict, Any, Optional, Tuple
from enum import Enum
from dataclasses import dataclass, field
from models.schemas import RiskLevel


class ChainPattern(Enum):
    DATA_EXFILTRATION = "data_exfiltration"       # 数据外泄
    PRIVILEGE_ESCALATION = "privilege_escalation"  # 权限提升
    DATA_DESTRUCTION = "data_destruction"          # 数据销毁
    BACKDOOR_INSTALL = "backdoor_install"          # 后门安装
    LATERAL_MOVEMENT = "lateral_movement"          # 横向移动


@dataclass
class ToolCallRecord:
    tool_name: str
    action: str               # 归类后的动作: read_file / write_file / execute / network / encode / delete
    parameters: Dict[str, Any] = field(default_factory=dict)
    risk_level: RiskLevel = RiskLevel.NONE
    timestamp: float = 0.0


@dataclass
class ChainAlert:
    pattern: ChainPattern
    description: str
    matched_steps: List[ToolCallRecord]
    risk_level: RiskLevel
    recommended_action: str


# 动作分类规则: 将工具名映射到标准动作类型
ACTION_RULES = {
    # 读操作
    "read_file": "read_file",
    "read_document": "read_file",
    "search_knowledge": "read_file",
    "list_files": "read_file",
    # 写操作
    "write_file": "write_file",
    "create_file": "write_file",
    "save_document": "write_file",
    # 执行
    "execute_command": "execute",
    "run_script": "execute",
    "system_call": "execute",
    # 网络
    "http_request": "network",
    "send_email": "network",
    "send_message": "network",
    "api_call": "network",
    # 编码
    "encode_base64": "encode",
    "compress_file": "encode",
    "encrypt_data": "encode",
    # 删除
    "delete_file": "delete",
    "truncate_table": "delete",
    "drop_table": "delete",
    # 权限
    "modify_permissions": "permission",
    "grant_access": "permission",
    "change_role": "permission",
}


# 异常链路模式定义: (步骤1, 步骤2, 步骤3) → (模式, 描述, 风险等级)
CHAIN_PATTERNS: List[Dict] = [
    {
        "steps": ["read_file", "encode", "network"],
        "pattern": ChainPattern.DATA_EXFILTRATION,
        "description": "数据外泄链路: 读取文件 → 编码处理 → 网络外发。检测到疑似敏感数据外传行为。",
        "risk_level": RiskLevel.CRITICAL,
        "recommendation": "立即阻断网络请求，审计读取的文件内容，确认是否有敏感数据泄露。"
    },
    {
        "steps": ["read_file", "network"],
        "pattern": ChainPattern.DATA_EXFILTRATION,
        "description": "数据外泄链路(简化): 读取文件 → 网络外发。检测到文件读取后直接网络传输。",
        "risk_level": RiskLevel.HIGH,
        "recommendation": "审查读取的文件是否为敏感数据，建议增加人工审批环节。"
    },
    {
        "steps": ["permission", "execute"],
        "pattern": ChainPattern.PRIVILEGE_ESCALATION,
        "description": "权限提升链路: 修改权限 → 执行命令。检测到权限变更后立即执行操作。",
        "risk_level": RiskLevel.CRITICAL,
        "recommendation": "阻断此操作链，审计权限变更记录，确认是否为授权操作。"
    },
    {
        "steps": ["delete", "network"],
        "pattern": ChainPattern.DATA_DESTRUCTION,
        "description": "数据销毁+外联: 删除数据 → 网络通信。检测到可能的证据销毁行为。",
        "risk_level": RiskLevel.CRITICAL,
        "recommendation": "立即阻断，恢复已删除数据（如有备份），审计删除原因。"
    },
    {
        "steps": ["network", "write_file", "execute"],
        "pattern": ChainPattern.BACKDOOR_INSTALL,
        "description": "后门安装链路: 下载文件 → 写入磁盘 → 执行。检测到疑似后门安装行为。",
        "risk_level": RiskLevel.CRITICAL,
        "recommendation": "立即阻断执行操作，删除已下载的文件，审计下载来源。"
    },
    {
        "steps": ["network", "execute"],
        "pattern": ChainPattern.BACKDOOR_INSTALL,
        "description": "后门安装(简化): 网络下载 → 直接执行。检测到远程内容执行。",
        "risk_level": RiskLevel.HIGH,
        "recommendation": "阻断远程执行，审查下载内容是否包含恶意代码。"
    },
]


def classify_action(tool_name: str) -> str:
    """将工具名映射为标准动作类型"""
    for key, action in ACTION_RULES.items():
        if key in tool_name.lower():
            return action
    return tool_name.lower()


class ChainAnalyzer:
    """任务链路异常检测器"""

    def __init__(self, max_history: int = 20):
        self.call_history: Dict[str, List[ToolCallRecord]] = {}
        self.max_history = max_history

    def record_call(self, session_id: str, tool_name: str, params: dict = None,
                    risk_level: RiskLevel = RiskLevel.NONE) -> Optional[ChainAlert]:
        """记录一次工具调用并检查链路异常"""
        from time import time

        action = classify_action(tool_name)
        record = ToolCallRecord(
            tool_name=tool_name,
            action=action,
            parameters=params or {},
            risk_level=risk_level,
            timestamp=time()
        )

        if session_id not in self.call_history:
            self.call_history[session_id] = []
        self.call_history[session_id].append(record)

        # 限制历史长度
        if len(self.call_history[session_id]) > self.max_history:
            self.call_history[session_id] = self.call_history[session_id][-self.max_history:]

        # 检查是否触发链路告警
        return self._check_chain(session_id)

    def _check_chain(self, session_id: str) -> Optional[ChainAlert]:
        """检查当前调用链是否匹配任何异常模式"""
        history = self.call_history.get(session_id, [])
        if len(history) < 2:
            return None

        # 取最近N次调用的动作序列
        recent_actions = [r.action for r in history[-5:]]

        for pattern_def in CHAIN_PATTERNS:
            steps = pattern_def["steps"]
            match = self._match_sequence(recent_actions, steps)
            if match is not None:
                # 匹配到模式，找到对应的原始记录
                matched_records = history[-len(recent_actions):][match:match + len(steps)]
                return ChainAlert(
                    pattern=pattern_def["pattern"],
                    description=pattern_def["description"],
                    matched_steps=matched_records,
                    risk_level=pattern_def["risk_level"],
                    recommended_action=pattern_def["recommendation"],
                )

        return None

    @staticmethod
    def _match_sequence(actions: List[str], pattern: List[str]) -> Optional[int]:
        """在动作序列中匹配模式,返回起始索引"""
        n, m = len(actions), len(pattern)
        if n < m:
            return None

        # 滑动窗口匹配: 允许中间有无关步骤,只要模式按序出现即可
        pi = 0  # pattern index
        start = -1
        for i, action in enumerate(actions):
            if action == pattern[pi]:
                if pi == 0:
                    start = i
                pi += 1
                if pi == m:
                    return start
        return None

    def get_session_history(self, session_id: str) -> List[Dict]:
        """获取会话的工具调用历史"""
        records = self.call_history.get(session_id, [])
        return [{
            "tool_name": r.tool_name,
            "action": r.action,
            "risk_level": r.risk_level.value,
            "timestamp": r.timestamp,
        } for r in records]

    def clear_session(self, session_id: str):
        """清除会话历史"""
        self.call_history.pop(session_id, None)


# 全局单例
chain_analyzer = ChainAnalyzer()
