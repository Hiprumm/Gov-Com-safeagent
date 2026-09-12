"""
多源输入关联分析器（薄封装，P2-2 收敛后）
==========================================

P2-2 检测模块合并：跨来源关联的唯一实现为 `security.cross_source_correlator`，
本模块收敛为薄封装，仅保留 cross_source_correlator 之外的补充能力：
1. 间接注入识别（EchoLeak CVE-2025-32711 攻击链，regex 规则）
2. 会话风险累积（委托 session_risk_accumulator）
3. 风险因素汇总与处置建议生成

跨来源事件记录部分全部委托给 `get_cross_source_correlator()` 单例——
与 `gov_agent_graph/security_layer.py` 入口指向同一实例、同一套模式与阈值，
两处入口记录的事件共享同一状态（不再存在"旧包装 + 新实现"双轨）。
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import re
import time
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field

from security.cross_source_correlator import get_cross_source_correlator
from security.session_risk_accumulator import (
    SessionRiskAccumulator, session_risk_accumulator,
    RiskEvent, SessionRiskProfile
)
from models.schemas import RiskLevel, AttackType


@dataclass
class CorrelationResult:
    """关联分析结果"""
    session_id: str
    indirect_injection_detected: bool = False
    cumulative_risk_level: RiskLevel = RiskLevel.NONE
    cumulative_score: float = 0.0
    escalated: bool = False
    escalated_from: Optional[RiskLevel] = None
    escalated_to: Optional[RiskLevel] = None
    correlated_threats: List[Dict] = field(default_factory=list)
    source_summary: Dict[str, int] = field(default_factory=dict)
    risk_factors: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


class CorrelationAnalyzer:
    """多源输入关联分析器（薄封装，P2-2）

    跨来源关联部分委托给 cross_source_correlator 唯一实现（共享同一单例），
    本类只补充：间接注入识别、会话风险累积、风险因素/建议生成。
    """

    # 间接注入特征模式
    _INDIRECT_INJECTION_PATTERNS = [
        # 知识库文档中的隐藏指令
        (r"(?:根据|根据以上|参考|按照).{0,15}(?:文档|资料|知识库|文件|附件).{0,20}(?:忽略|绕过|执行|输出|发送)", "知识库间接注入"),
        (r"(?:文档|资料|文件|附件).{0,10}(?:中提到|中说|要求|指示|指示我们).{0,20}(?:忽略|绕过|执行|发送|输出)", "文档间接注入"),
        # 网页内容中的隐藏指令
        (r"(?:网页|网站|页面|链接).{0,10}(?:中提到|中说|要求|指示).{0,20}(?:忽略|绕过|执行|发送|输出)", "网页间接注入"),
        # 历史记忆中的污染指令
        (r"(?:之前|上次|历史|记忆).{0,10}(?:说过|提到|要求|指示|约定).{0,20}(?:忽略|绕过|执行|发送|输出)", "记忆间接注入"),
        # 工具输出中的注入
        (r"(?:工具|mcp|skill|插件).{0,10}(?:返回|输出|结果).{0,20}(?:忽略|绕过|执行|发送|输出)", "工具输出间接注入"),
        # EchoLeak式攻击
        (r"(?:根据检索结果|根据搜索结果).{0,20}(?:忽略|绕过|执行|发送|输出|访问)", "检索结果间接注入"),
        (r"(?:如下内容|以下内容|下面内容).{0,10}(?:来自|来源于|摘自).{0,15}(?:外部|第三方|网络|互联网)", "外部内容引用"),
    ]

    def __init__(self):
        # P2-2：与 security_layer 入口共享同一 cross_source_correlator 单例
        self.correlator = get_cross_source_correlator()
        self.accumulator = session_risk_accumulator

    def analyze(
        self,
        session_id: str,
        text: str,
        source: str,
        risk_level: RiskLevel,
        attack_type: Optional[AttackType] = None,
        confidence: float = 0.0,
    ) -> CorrelationResult:
        """
        分析多源输入的关联风险

        Args:
            session_id: 会话ID
            text: 输入文本
            source: 输入源（user_input/uploaded_doc/web_scrape/knowledge_retrieval/agent_memory/plugin_output）
            risk_level: 当前输入的风险等级
            attack_type: 检测到的攻击类型
            confidence: 检测置信度
        """
        result = CorrelationResult(session_id=session_id)

        # 1. 记录到跨来源关联引擎
        threats = self.correlator.record_event(
            session_id=session_id,
            source=source,
            risk_level=risk_level.value if isinstance(risk_level, RiskLevel) else str(risk_level),
            attack_type=attack_type.value if attack_type else None,
            confidence=confidence,
            content_preview=text[:200],
        )

        # 2. 记录到会话风险累积引擎
        profile = self.accumulator.record_event(
            session_id=session_id,
            source=source,
            risk_level=risk_level,
            attack_type=attack_type.value if attack_type else None,
            confidence=confidence,
        )

        # 3. 检测间接注入（EchoLeak式攻击）
        indirect_detected = self._detect_indirect_injection(session_id, text, source, result)

        # 4. 填充结果
        result.cumulative_risk_level = profile.overall_risk_level
        result.cumulative_score = profile.cumulative_score
        result.escalated = profile.escalated_to is not None
        result.escalated_from = profile.escalated_from
        result.escalated_to = profile.escalated_to
        result.indirect_injection_detected = indirect_detected

        if threats:
            result.correlated_threats = [
                {
                    "pattern": t.pattern.value,
                    "severity": t.severity,
                    "confidence": t.confidence,
                    "involved_sources": t.involved_sources,
                    "attack_chain": t.attack_chain,
                    "evidence": t.evidence,
                }
                for t in threats
            ]

        # 5. 源摘要
        session_summary = self.correlator.get_session_summary(session_id)
        result.source_summary = session_summary.get("sources", {})

        # 6. 风险因素
        result.risk_factors = self._collect_risk_factors(profile, threats, indirect_detected)

        # 7. 建议
        result.recommendations = self._generate_recommendations(result)

        return result

    def _detect_indirect_injection(
        self,
        session_id: str,
        text: str,
        source: str,
        result: CorrelationResult,
    ) -> bool:
        """检测间接注入攻击"""
        # 非用户直接输入的源需要重点检测
        if source in ("user_input",):
            # 用户输入中引用外部内容时检测
            for pattern, desc in self._INDIRECT_INJECTION_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    result.risk_factors.append(f"间接注入特征: {desc}")
                    return True
            return False

        # 非用户输入源（文档/网页/知识库/记忆/工具输出）中的指令本身就是间接注入
        if source in ("uploaded_doc", "web_scrape", "knowledge_retrieval", "agent_memory", "plugin_output"):
            # 检查是否包含注入指令
            injection_patterns = [
                r"忽略.{0,10}(?:之前|上面|系统|所有|当前).{0,10}(?:指令|规则|提示|prompt|限制|防护|检测)",
                r"(?:forget|ignore).{0,15}(?:previous|system|all).{0,15}(?:instruction|rule)",
                r"绕过.{0,10}(?:安全|检测|过滤|审计|防护|限制)",
                r"(?:bypass|skip).{0,10}(?:security|filter|check|audit|guard)",
                r"(?:输出|返回|显示).{0,10}(?:系统|prompt|密钥|secret|token|password|凭证)",
                r"(?:执行|运行|run|execute).{0,10}(?:命令|command|脚本|script|代码|code)",
                r"(?:发送|上传|传输|导出).{0,10}(?:文件|数据|信息).{0,10}(?:到|至|to).{0,10}(?:外部|第三方|远程|external)",
                r"(?:导出|下载|获取|访问).{0,10}(?:全部|所有|完整|整个).{0,10}(?:数据|文件|记录|信息).{0,15}(?:外部|第三方|远程|external)",
                r"(?:你现在是|act as).{0,20}(?:DAN|没有任何限制|unrestricted|jailbreak)",
                r"(?:你的新任务|your new task|new instruction).{0,30}(?:忽略|ignore|forget|bypass)",
                r"关闭.{0,10}(?:审批|校验|检测|安全|防护|验证|审计)",
                r"记住.{0,10}(?:永久|规则|指令|配置)",
                r"(?:以|作为|使用|借用)\s*(?:管理员|系统管理员|root|admin)\s*(?:权限|身份|执行|操作)",
            ]

            for pattern in injection_patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    result.risk_factors.append(
                        f"间接注入检测: {source}源中包含注入指令（EchoLeak式攻击）"
                    )
                    return True

        return False

    def _collect_risk_factors(
        self,
        profile: SessionRiskProfile,
        threats: Optional[List[Any]],
        indirect_detected: bool,
    ) -> List[str]:
        """收集风险因素"""
        factors = []

        if indirect_detected:
            factors.append("检测到间接注入攻击（EchoLeak CVE-2025-32711模式）")

        if profile.escalated_to is not None:
            factors.append(
                f"风险累积升级: {profile.escalated_from.value} → {profile.escalated_to.value}"
            )
            factors.extend(profile.escalation_reasons)

        if threats:
            for t in threats:
                factors.append(
                    f"跨来源关联: {t.pattern.value} (置信度: {t.confidence:.2f})"
                )

        if profile.unique_sources >= 3:
            factors.append(f"多源输入: {profile.unique_sources}个不同来源")
        elif profile.unique_sources >= 2 and profile.event_count >= 2:
            factors.append(f"跨源关联: {profile.unique_sources}个来源存在风险事件")

        if profile.unique_attack_types >= 3:
            factors.append(f"多类型攻击: {profile.unique_attack_types}种不同攻击类型")
        elif profile.unique_attack_types >= 2:
            factors.append(f"多种攻击类型: {profile.unique_attack_types}种")

        return factors

    def _generate_recommendations(self, result: CorrelationResult) -> List[str]:
        """生成安全建议"""
        recs = []

        if result.indirect_injection_detected:
            recs.append("检测到间接注入攻击，建议审查最近的外部内容输入（文档/网页/知识库检索结果）")

        if result.escalated:
            recs.append(f"会话风险已升级至 {result.escalated_to.value}，建议加强审批管控")

        if result.correlated_threats:
            recs.append(f"检测到 {len(result.correlated_threats)} 个跨来源关联威胁，建议进行安全审计")

        if result.cumulative_score >= 100:
            recs.append("累积风险分过高，建议暂停当前会话并进行人工审查")

        if not recs and result.cumulative_risk_level == RiskLevel.NONE:
            recs.append("当前会话风险正常")

        return recs

    def get_session_report(self, session_id: str) -> Dict:
        """获取会话关联分析报告"""
        profile = self.accumulator.get_session_summary(session_id)
        correlator_summary = self.correlator.get_session_summary(session_id)

        return {
            "session_id": session_id,
            "cumulative_risk": profile,
            "correlation_summary": correlator_summary,
        }

    def clear_session(self, session_id: str):
        """清除会话数据"""
        self.correlator.clear_session(session_id)
        self.accumulator.clear_session(session_id)


# 全局单例
_correlation_analyzer: Optional[CorrelationAnalyzer] = None


def get_correlation_analyzer() -> CorrelationAnalyzer:
    global _correlation_analyzer
    if _correlation_analyzer is None:
        _correlation_analyzer = CorrelationAnalyzer()
    return _correlation_analyzer
