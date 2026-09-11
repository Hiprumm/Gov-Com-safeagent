"""
跨来源关联分析引擎 (Cross-Source Correlation Engine)
=====================================================

比赛方案方向一要求：
"构建覆盖用户输入、网页内容、文档附件、知识库检索结果、历史记忆等多源输入的攻击识别机制，
实现对提示注入、间接指令污染、越狱诱导、数据投毒等风险的自动发现、关联分析和分级评估。"

本引擎实现：
1. 多源事件追踪——按 Session 聚合来自不同输入源的检测事件
2. 跨来源攻击链路检测——识别"上传文档→注入指令→数据窃取"等复合攻击模式
3. 时间序列关联——检测短时间窗口内的协同攻击行为
4. 攻击链证据链构建——为审计溯源提供完整的攻击路径证据
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple
from datetime import datetime, timedelta
from enum import Enum


class CorrelationPattern(Enum):
    """预定义的跨来源攻击模式"""
    # 知识投毒→提示注入 组合
    DOCUMENT_POISON_THEN_INJECTION = "document_poison_then_injection"
    # 记忆污染→数据窃取
    MEMORY_POISON_THEN_EXFILTRATION = "memory_poison_then_exfiltration"
    # 文件上传→命令执行
    FILE_UPLOAD_THEN_COMMAND = "file_upload_then_command"
    # 知识检索污染→越狱
    KB_POISON_THEN_JAILBREAK = "kb_poison_then_jailbreak"
    # 多源协同注入
    MULTI_SOURCE_COORDINATED_INJECTION = "multi_source_coordinated_injection"
    # 权限提升链
    PRIVILEGE_ESCALATION_CHAIN = "privilege_escalation_chain"


@dataclass
class SourceEvent:
    """单个输入源的检测事件"""
    session_id: str
    source: str           # user_input, file_upload, knowledge_retrieval, agent_memory, web_content
    risk_level: str       # none, low, medium, high, critical
    attack_type: Optional[str]
    confidence: float
    timestamp: datetime
    content_preview: str  # 输入内容摘要
    evidence: List[str] = field(default_factory=list)


@dataclass
class CorrelatedThreat:
    """跨来源关联威胁"""
    pattern: CorrelationPattern
    session_id: str
    severity: str         # low, medium, high, critical
    confidence: float
    involved_sources: List[str]
    involved_events: List[SourceEvent]
    attack_chain: List[str]  # 攻击步骤描述
    detected_at: datetime
    evidence: List[str]


class CrossSourceCorrelator:
    """跨来源关联分析引擎"""

    # 攻击模式定义：(源1, 源2, ...) → 关联阈值 → 模式
    PATTERN_DEFINITIONS = {
        CorrelationPattern.DOCUMENT_POISON_THEN_INJECTION: {
            "sources": {"file_upload", "user_input"},
            "source_sequence": ["file_upload", "user_input"],
            "max_time_window_seconds": 300,     # 5分钟内
            "min_combined_confidence": 0.6,
            "description": "先上传含恶意指令的文件，再通过对话触发注入",
        },
        CorrelationPattern.MEMORY_POISON_THEN_EXFILTRATION: {
            "sources": {"agent_memory", "user_input"},
            "source_sequence": ["agent_memory", "user_input"],
            "max_time_window_seconds": 600,
            "min_combined_confidence": 0.7,
            "description": "污染历史记忆后诱导数据导出",
        },
        CorrelationPattern.FILE_UPLOAD_THEN_COMMAND: {
            "sources": {"file_upload", "user_input"},
            "source_sequence": ["file_upload", "user_input"],
            "max_time_window_seconds": 300,
            "min_combined_confidence": 0.65,
            "description": "上传文件后尝试执行系统命令",
        },
        CorrelationPattern.KB_POISON_THEN_JAILBREAK: {
            "sources": {"knowledge_retrieval", "user_input"},
            "source_sequence": ["knowledge_retrieval", "user_input"],
            "max_time_window_seconds": 600,
            "min_combined_confidence": 0.6,
            "description": "污染知识库检索结果后尝试越狱",
        },
        CorrelationPattern.MULTI_SOURCE_COORDINATED_INJECTION: {
            "sources": {"user_input", "file_upload", "knowledge_retrieval"},
            "source_sequence": None,  # 不要求特定顺序，只要3个源都有事件
            "max_time_window_seconds": 900,   # 15分钟
            "min_combined_confidence": 0.5,
            "description": "多源协同攻击——从多个渠道注入恶意指令",
        },
        CorrelationPattern.PRIVILEGE_ESCALATION_CHAIN: {
            "sources": {"user_input", "user_input"},
            "source_sequence": ["user_input", "user_input"],
            "max_time_window_seconds": 300,
            "min_combined_confidence": 0.7,
            "description": "权限提升链——连续尝试提升权限",
        },
    }

    # 权限提升关键词
    PRIVILEGE_ESCALATION_KEYWORDS = [
        "提升权限", "管理员", "root", "sudo", "admin",
        "越权", "绕过权限", "获取权限", "修改角色",
    ]

    def __init__(self):
        # 按 session_id 存储事件
        self._events: Dict[str, List[SourceEvent]] = {}
        # 已报告的威胁（去重）
        self._reported_threats: Set[str] = set()
        # 按 session_id 存储已检测到的威胁对象（供 summary 查询使用）
        self._session_threats: Dict[str, List["CorrelatedThreat"]] = {}
        self._max_events_per_session = 200

    def record_event(
        self,
        session_id: str,
        source: str,
        risk_level: str,
        attack_type: Optional[str] = None,
        confidence: float = 0.0,
        content_preview: str = "",
        evidence: Optional[List[str]] = None,
    ) -> Optional[List[CorrelatedThreat]]:
        """
        记录一个检测事件，并执行跨来源关联分析。

        Returns:
            如果检测到新的关联威胁，返回威胁列表；否则返回 None
        """
        event = SourceEvent(
            session_id=session_id,
            source=source,
            risk_level=risk_level,
            attack_type=attack_type,
            confidence=confidence,
            timestamp=datetime.now(),
            content_preview=content_preview[:200],
            evidence=evidence or [],
        )

        # 存储事件
        if session_id not in self._events:
            self._events[session_id] = []
        self._events[session_id].append(event)

        # 限制存储量
        if len(self._events[session_id]) > self._max_events_per_session:
            self._events[session_id] = self._events[session_id][-self._max_events_per_session:]

        # 只对有风险的事件做关联分析
        if risk_level in ("none", "low"):
            return None

        return self._correlate(session_id, event)

    def _correlate(self, session_id: str, new_event: SourceEvent) -> Optional[List[CorrelatedThreat]]:
        """执行跨来源关联分析"""
        threats = []
        session_events = self._events.get(session_id, [])
        now = datetime.now()

        for pattern, config in self.PATTERN_DEFINITIONS.items():
            required_sources = config["sources"]
            time_window = timedelta(seconds=config["max_time_window_seconds"])
            min_confidence = config["min_combined_confidence"]

            # 收集时间窗口内来自不同源的风险事件
            window_events = [
                e for e in session_events
                if now - e.timestamp <= time_window
                and e.risk_level not in ("none",)
            ]

            # 检查源覆盖
            sources_in_window = {e.source for e in window_events}
            if not required_sources.issubset(sources_in_window):
                continue

            # 如果有顺序要求
            sequence = config.get("source_sequence")
            if sequence and len(window_events) >= len(sequence):
                if not self._check_sequence(window_events, sequence):
                    continue

            # 计算综合置信度
            combined_confidence = self._calc_combined_confidence(window_events)
            if combined_confidence < min_confidence:
                continue

            # 特殊模式检查
            if pattern == CorrelationPattern.PRIVILEGE_ESCALATION_CHAIN:
                if not self._check_privilege_escalation(window_events):
                    continue

            # 构建威胁
            involved_sources = list(required_sources)
            threat_id = f"{session_id}_{pattern.value}_{now.timestamp():.0f}"

            if threat_id in self._reported_threats:
                continue

            self._reported_threats.add(threat_id)

            attack_chain = self._build_attack_chain(pattern, window_events)
            severity = self._calc_severity(combined_confidence, len(window_events))

            threat = CorrelatedThreat(
                pattern=pattern,
                session_id=session_id,
                severity=severity,
                confidence=round(combined_confidence, 3),
                involved_sources=involved_sources,
                involved_events=window_events[-5:],  # 最近5个事件
                attack_chain=attack_chain,
                detected_at=now,
                evidence=[
                    f"跨来源关联: {config['description']}",
                    f"涉及来源: {', '.join(involved_sources)}",
                    f"窗口内事件数: {len(window_events)}",
                    f"综合置信度: {combined_confidence:.2f}",
                ],
            )

            threats.append(threat)

            # 同步存入 session 威胁列表，便于后续 summary 查询
            if session_id not in self._session_threats:
                self._session_threats[session_id] = []
            self._session_threats[session_id].append(threat)

        return threats if threats else None

    def _check_sequence(self, events: List[SourceEvent], sequence: List[str]) -> bool:
        """检查事件是否按指定源顺序发生"""
        source_order = [e.source for e in sorted(events, key=lambda e: e.timestamp)]
        seq_idx = 0
        for src in source_order:
            if seq_idx < len(sequence) and src == sequence[seq_idx]:
                seq_idx += 1
        return seq_idx >= len(sequence)

    def _check_privilege_escalation(self, events: List[SourceEvent]) -> bool:
        """检查是否存在权限提升模式"""
        escalation_count = 0
        for event in events:
            for keyword in self.PRIVILEGE_ESCALATION_KEYWORDS:
                if keyword in event.content_preview:
                    escalation_count += 1
                    break
        return escalation_count >= 2

    def _calc_combined_confidence(self, events: List[SourceEvent]) -> float:
        """计算多源事件的综合置信度"""
        if not events:
            return 0.0

        # 加权平均：越近的事件权重越高
        now = datetime.now()
        total_weight = 0.0
        weighted_sum = 0.0

        for i, event in enumerate(events):
            # 时间衰减权重（越近越高）
            age_seconds = (now - event.timestamp).total_seconds()
            time_weight = max(0.1, 1.0 - age_seconds / 3600)  # 1小时内衰减到0.1

            # 风险等级权重
            risk_weights = {"critical": 1.5, "high": 1.2, "medium": 0.8, "low": 0.4}
            risk_weight = risk_weights.get(event.risk_level, 0.2)

            # 源多样性加成
            source_bonus = 1.0 + min(0.3, i * 0.1)  # 后面的事件有更高权重

            weight = time_weight * risk_weight * source_bonus
            total_weight += weight
            weighted_sum += event.confidence * weight

        if total_weight == 0:
            return 0.0

        # 源多样性加成
        unique_sources = len({e.source for e in events})
        diversity_bonus = min(1.0, 0.8 + unique_sources * 0.15)

        return min(1.0, (weighted_sum / total_weight) * diversity_bonus)

    def _calc_severity(self, confidence: float, event_count: int) -> str:
        """计算关联威胁的严重程度"""
        # 综合置信度和事件数量
        if confidence >= 0.85 or event_count >= 5:
            return "critical"
        elif confidence >= 0.7 or event_count >= 3:
            return "high"
        elif confidence >= 0.5:
            return "medium"
        else:
            return "low"

    def _build_attack_chain(self, pattern: CorrelationPattern, events: List[SourceEvent]) -> List[str]:
        """构建攻击链描述"""
        chain = []
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        for i, event in enumerate(sorted_events):
            source_name = {
                "user_input": "用户输入",
                "file_upload": "文件上传",
                "knowledge_retrieval": "知识检索",
                "agent_memory": "历史记忆",
                "web_content": "网页内容",
            }.get(event.source, event.source)

            step = f"第{i+1}步 [{source_name}]"
            if event.attack_type:
                step += f" 触发{event.attack_type}"
            if event.risk_level in ("high", "critical"):
                step += f" (风险等级: {event.risk_level})"
            chain.append(step)

        return chain

    def get_session_summary(self, session_id: str) -> Dict:
        """获取某个 Session 的关联分析摘要"""
        events = self._events.get(session_id, [])
        if not events:
            return {"session_id": session_id, "total_events": 0, "sources": {}, "threats": []}

        sources = {}
        for e in events:
            if e.source not in sources:
                sources[e.source] = {"count": 0, "risk_events": 0}
            sources[e.source]["count"] += 1
            if e.risk_level not in ("none",):
                sources[e.source]["risk_events"] += 1

        # 收集与此 session 相关的威胁详情
        session_threats = self._session_threats.get(session_id, [])
        threats = []
        for t in session_threats:
            threats.append({
                "pattern": getattr(t.pattern, "value", str(t.pattern)),
                "severity": getattr(t, "severity", None),
                "confidence": getattr(t, "confidence", 0.0),
                "attack_chain": getattr(t, "attack_chain", []),
                "detected_at": getattr(t.detected_at, "isoformat", lambda: str(t.detected_at))(),
                "involved_sources": getattr(t, "involved_sources", []),
            })

        return {
            "session_id": session_id,
            "total_events": len(events),
            "sources": sources,
            "unique_sources": len(sources),
            "risk_events": sum(1 for e in events if e.risk_level not in ("none",)),
            "multi_source_events": len(sources) >= 2,
            "threat_count": len(threats),
            "threats": threats,
        }

    def clear_session(self, session_id: str):
        """清除某个 Session 的事件"""
        if session_id in self._events:
            del self._events[session_id]
        if session_id in self._session_threats:
            del self._session_threats[session_id]
        # 清除相关威胁记录
        to_remove = [tid for tid in self._reported_threats if tid.startswith(session_id)]
        for tid in to_remove:
            self._reported_threats.remove(tid)


# 全局单例
_cross_source_correlator: Optional[CrossSourceCorrelator] = None


def get_cross_source_correlator() -> CrossSourceCorrelator:
    global _cross_source_correlator
    if _cross_source_correlator is None:
        _cross_source_correlator = CrossSourceCorrelator()
    return _cross_source_correlator
