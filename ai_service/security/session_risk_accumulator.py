"""
Session级风险累积评分引擎 (Session Risk Accumulator)

多源关联分析：将来自不同输入源（用户输入、文件上传、知识库检索、工具调用等）
的低风险事件进行累积评分，当低风险事件叠加达到阈值时，自动升级风险等级。

核心能力：
1. 多源事件追踪：user_input / uploaded_doc / knowledge_retrieval / tool_call / chain_alert
2. 时间衰减加权：新事件权重高，旧事件权重低（指数衰减）
3. 同类型频次加成：同一攻击类型反复出现时额外加权
4. 风险升级机制：低风险累积到阈值自动升级
5. Session级风险画像：实时综合风险评估
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from models.schemas import RiskLevel, AttackType


# 源类型权重：不同来源的可信度/威胁程度不同
SOURCE_WEIGHTS = {
    "user_input": 1.0,           # 直接用户输入
    "uploaded_doc": 0.9,         # 上传文档
    "knowledge_retrieval": 0.8,  # 知识库检索结果（可能被投毒）
    "agent_memory": 0.7,         # Agent记忆（可能持久化投毒）
    "plugin_output": 0.85,       # 插件输出
    "tool_call": 1.2,            # 工具调用（实操风险更高）
    "chain_alert": 1.5,          # 链路告警（复合攻击）
    "web_scrape": 0.8,           # 网页抓取
}

# 风险等级基础分
RISK_LEVEL_SCORES = {
    RiskLevel.NONE: 0,
    RiskLevel.LOW: 25,
    RiskLevel.MEDIUM: 50,
    RiskLevel.HIGH: 75,
    RiskLevel.CRITICAL: 100,
}

# 累积升级阈值
UPGRADE_THRESHOLDS = [
    (150, RiskLevel.CRITICAL),  # 累计分 >= 150 → CRITICAL
    (100, RiskLevel.HIGH),       # 累计分 >= 100 → HIGH
    (60, RiskLevel.MEDIUM),      # 累计分 >= 60 → MEDIUM
    (30, RiskLevel.LOW),         # 累计分 >= 30 → LOW
]

# 时间衰减半衰期（秒）：每过 T 秒，权重衰减一半
TIME_DECAY_HALFLIFE = 300  # 5分钟

# 同类型频次阈值
FREQUENCY_THRESHOLDS = {
    "same_type_count": 3,     # 同一攻击类型出现N次
    "same_source_count": 5,   # 同一来源出现N次事件
    "burst_count": 3,         # 短时间内出现N次
    "burst_window": 30,       # 突发窗口（秒）
}


@dataclass
class RiskEvent:
    """单个风险事件"""
    event_id: str
    session_id: str
    source: str          # InputSource 的值
    attack_type: Optional[str] = None
    risk_level: RiskLevel = RiskLevel.NONE
    confidence: float = 0.0
    timestamp: float = field(default_factory=time.time)
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SessionRiskProfile:
    """Session 风险画像"""
    session_id: str
    overall_risk_level: RiskLevel = RiskLevel.NONE
    cumulative_score: float = 0.0
    event_count: int = 0
    unique_attack_types: int = 0
    unique_sources: int = 0
    top_attack_type: Optional[str] = None
    escalated_from: Optional[RiskLevel] = None  # 原基础最高级别
    escalated_to: Optional[RiskLevel] = None    # 升级到哪个级别
    escalation_reasons: List[str] = field(default_factory=list)
    active_since: float = 0.0
    last_event_time: float = 0.0
    recent_events: List[Dict] = field(default_factory=list)


class SessionRiskAccumulator:
    """Session 级风险累积评分引擎"""

    def __init__(self, max_events_per_session: int = 100):
        self.sessions: Dict[str, List[RiskEvent]] = {}
        self.max_events = max_events_per_session

    def record_event(
        self,
        session_id: str,
        source: str,
        risk_level: RiskLevel,
        attack_type: Optional[str] = None,
        confidence: float = 0.0,
        details: Optional[Dict] = None,
    ) -> SessionRiskProfile:
        """记录一个风险事件并返回更新后的 session 风险画像"""
        import uuid

        event = RiskEvent(
            event_id=str(uuid.uuid4())[:8],
            session_id=session_id,
            source=source,
            attack_type=attack_type,
            risk_level=risk_level,
            confidence=confidence,
            timestamp=time.time(),
            details=details or {},
        )

        if session_id not in self.sessions:
            self.sessions[session_id] = []

        self.sessions[session_id].append(event)

        # 限制事件数量
        if len(self.sessions[session_id]) > self.max_events:
            self.sessions[session_id] = self.sessions[session_id][-self.max_events:]

        # 计算风险画像
        return self._calculate_profile(session_id)

    def get_profile(self, session_id: str) -> SessionRiskProfile:
        """获取 session 风险画像（不新增事件）"""
        return self._calculate_profile(session_id)

    def _calculate_profile(self, session_id: str) -> SessionRiskProfile:
        """计算 session 的综合风险画像"""
        events = self.sessions.get(session_id, [])
        now = time.time()

        profile = SessionRiskProfile(
            session_id=session_id,
            event_count=len(events),
            active_since=events[0].timestamp if events else now,
            last_event_time=events[-1].timestamp if events else now,
        )

        if not events:
            return profile

        # 1. 计算各项统计
        attack_types = set()
        sources = set()
        type_count: Dict[str, int] = {}

        for ev in events:
            if ev.attack_type:
                attack_types.add(ev.attack_type)
                type_count[ev.attack_type] = type_count.get(ev.attack_type, 0) + 1
            sources.add(ev.source)

        profile.unique_attack_types = len(attack_types)
        profile.unique_sources = len(sources)

        if type_count:
            profile.top_attack_type = max(type_count, key=type_count.get)

        # 2. 时间衰减加权累积分
        cumulative = 0.0
        for ev in events:
            source_weight = SOURCE_WEIGHTS.get(ev.source, 1.0)
            base_score = RISK_LEVEL_SCORES.get(ev.risk_level, 0)
            # 时间衰减：e^(-ln2 * elapsed / halflife)
            elapsed = now - ev.timestamp
            decay = 2.0 ** (-elapsed / TIME_DECAY_HALFLIFE)
            weighted = base_score * source_weight * decay * ev.confidence
            cumulative += weighted

        # 衰减后最小分 = 基础分 * 0.5（考虑时间间隔）
        profile.cumulative_score = round(min(cumulative, 200), 1)

        # 3. 找基础最高风险（不考虑累积）
        base_max_level = RiskLevel.NONE
        for ev in events:
            lev_order = {RiskLevel.NONE: 0, RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2,
                         RiskLevel.HIGH: 3, RiskLevel.CRITICAL: 4}
            if lev_order[ev.risk_level] > lev_order[base_max_level]:
                base_max_level = ev.risk_level

        # 4. 频次加成
        freq_bonus = 0.0
        escalation_reasons: List[str] = []

        # 同攻击类型频次加成
        for atype, count in type_count.items():
            if count >= FREQUENCY_THRESHOLDS["same_type_count"]:
                boost = (count - 2) * 5  # 超过2次后每次+5分
                freq_bonus += boost
                escalation_reasons.append(
                    f"攻击类型 [{atype}] 出现 {count} 次 (+{boost}分)"
                )

        # 同来源频次加成
        source_counts: Dict[str, int] = {}
        for ev in events:
            source_counts[ev.source] = source_counts.get(ev.source, 0) + 1
        for src, count in source_counts.items():
            if count >= FREQUENCY_THRESHOLDS["same_source_count"]:
                boost = (count - 4) * 3
                freq_bonus += boost
                escalation_reasons.append(
                    f"来源 [{src}] 事件 {count} 次 (+{boost}分)"
                )

        # 突发检测：短时间内大量事件
        recent_30s = [e for e in events if now - e.timestamp <= FREQUENCY_THRESHOLDS["burst_window"]]
        if len(recent_30s) >= FREQUENCY_THRESHOLDS["burst_count"]:
            burst_boost = len(recent_30s) * 5
            freq_bonus += burst_boost
            escalation_reasons.append(
                f"突发检测: {len(recent_30s)} 个事件在 {FREQUENCY_THRESHOLDS['burst_window']}s 内 (+{burst_boost}分)"
            )

        total_score = profile.cumulative_score + freq_bonus

        # 5. 判定升级后的风险等级
        upgraded_level = base_max_level
        for threshold, level in UPGRADE_THRESHOLDS:
            if total_score >= threshold:
                upgraded_level = level
                break

        # 判断是否发生了升级
        lev_order = {RiskLevel.NONE: 0, RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2,
                     RiskLevel.HIGH: 3, RiskLevel.CRITICAL: 4}

        if lev_order[upgraded_level] > lev_order[base_max_level]:
            profile.escalated_from = base_max_level
            profile.escalated_to = upgraded_level
            profile.escalation_reasons = escalation_reasons
            profile.overall_risk_level = upgraded_level
        else:
            profile.overall_risk_level = base_max_level
            if escalation_reasons:
                profile.escalation_reasons = [
                    f"注意: {r}" for r in escalation_reasons
                ]

        # 6. 最近事件摘要
        profile.recent_events = []
        for ev in events[-10:]:
            profile.recent_events.append({
                "event_id": ev.event_id,
                "source": ev.source,
                "attack_type": ev.attack_type,
                "risk_level": ev.risk_level.value,
                "confidence": round(ev.confidence, 2),
                "timestamp": ev.timestamp,
                "elapsed_seconds": round(now - ev.timestamp, 1),
            })

        return profile

    def get_session_summary(self, session_id: str) -> Dict:
        """获取 session 风险摘要（适合 API 返回）"""
        profile = self._calculate_profile(session_id)
        return {
            "session_id": profile.session_id,
            "overall_risk_level": profile.overall_risk_level.value,
            "cumulative_score": profile.cumulative_score,
            "event_count": profile.event_count,
            "unique_attack_types": profile.unique_attack_types,
            "unique_sources": profile.unique_sources,
            "top_attack_type": profile.top_attack_type,
            "escalated": profile.escalated_to is not None,
            "escalated_from": profile.escalated_from.value if profile.escalated_from else None,
            "escalated_to": profile.escalated_to.value if profile.escalated_to else None,
            "escalation_reasons": profile.escalation_reasons,
            "active_since": profile.active_since,
            "last_event_time": profile.last_event_time,
            "recent_events": profile.recent_events,
        }

    def clear_session(self, session_id: str):
        """清除 session 数据"""
        self.sessions.pop(session_id, None)

    def get_all_active_sessions(self) -> List[Dict]:
        """获取所有活跃 session 摘要"""
        result = []
        for sid in self.sessions:
            result.append(self.get_session_summary(sid))
        # 按累积分降序
        result.sort(key=lambda x: x["cumulative_score"], reverse=True)
        return result


# 全局单例
session_risk_accumulator = SessionRiskAccumulator()
