"""
SecurityGuard —— SDK 的统一安全门面（方向C-1/C-2）

一个对象聚合全部安全能力，客户 Agent 只需面对这一个 API：

    from gov_safeagent_sdk import SecurityGuard
    guard = SecurityGuard()                          # ① 嵌入
    v = guard.detect_sync("读取文件")                 # ② 输入检测
    if v.allowed: ...                                # ③ 按判定放行/阻断
    t = guard.check_tool("sess", "write_file", {...}) # ④ 工具级能力治理
    text = guard.filter_output(llm_answer)           # ⑤ 输出脱敏

覆盖纵深防御全部环节：
- detect / detect_sync / detect_async : 输入检测（11 层管线 + 会话关联）
- check_tool / grant_tool             : 能力令牌（B-2 默认 deny）+ operation_guard（A-3）
- assess_plan                         : Plan IR 序列风险 + 不可逆性建模（A-1/A-2/B-4）
- filter_output                       : PII/密钥脱敏（A-5）
所有调用走核心侧同一套实现 —— 与本仓库 Agent 主流程共享检测状态、
会话风险累积与审计链（分级签名自动记录）。
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from .core import load_core

# 默认阻断的风险级别（与主 Agent 流程一致：high/critical 阻断）
BLOCK_LEVELS = ("high", "critical")


@dataclass
class GuardVerdict:
    """SDK 统一判定结果"""
    allowed: bool
    risk_level: str = "none"            # none/low/medium/high/critical
    reason: str = ""
    evidence: List[str] = field(default_factory=list)
    blocked_by: str = ""                # input_detection / capability_token / operation_guard / ...
    sanitized: Optional[str] = None     # 仅 filter_output：脱敏后文本
    latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "allowed": self.allowed,
            "risk_level": self.risk_level,
            "reason": self.reason,
            "evidence": self.evidence,
            "blocked_by": self.blocked_by,
            "latency_ms": round(self.latency_ms, 3),
        }


class SecurityGuard:
    """政企大模型智能体安全防护门面（可嵌入任意 Agent 进程）"""

    def __init__(
        self,
        core_path: Optional[str] = None,
        role: str = "user",
        block_levels: tuple = BLOCK_LEVELS,
    ):
        load_core(core_path)
        self.role = role
        self.block_levels = tuple(block_levels)

        # 懒导入核心组件（load_core 后 security.* 可用）
        from security.input_detector import InputDetectionService
        from security.capability_token import get_capability_token_manager
        from security.operation_guard import get_operation_guard, OperationIntent
        from security.sequence_risk_evaluator import SequenceRiskEvaluator
        from security.plan_ir import PlanIRBuilder
        from security.output_filter import OutputFilter

        self._detector = InputDetectionService()
        self._tokens = get_capability_token_manager()      # 与主流程共享同一令牌池
        self._op_guard = get_operation_guard()
        self._seq_evaluator = SequenceRiskEvaluator()
        self._plan_builder = PlanIRBuilder()
        self._output_filter = OutputFilter(block_critical=False)
        self._OperationIntent = OperationIntent

    # ==================== 输入检测（C-1 detect / C-2 sync+async） ====================

    def detect(self, text: str, session_id: str = "default", source: str = "user_input") -> GuardVerdict:
        """检测一条输入（prompt/文档/网页内容/检索片段）。同步。"""
        start = time.perf_counter()
        result = self._detector.detect_single_input(text, source, session_id=session_id)
        risk = result.risk_level.value if hasattr(result.risk_level, "value") else str(result.risk_level)
        blocked = risk in self.block_levels
        latency = (time.perf_counter() - start) * 1000
        return GuardVerdict(
            allowed=not blocked,
            risk_level=risk,
            reason=(f"检测到{risk}风险: {result.attack_type.value if result.attack_type else '未知攻击'}"
                    if blocked else "输入检测通过"),
            evidence=list(result.evidence or [])[:10],
            blocked_by="input_detection" if blocked else "",
            latency_ms=latency,
        )

    # C-2：同步接口（detect 的显式别名）
    def detect_sync(self, text: str, session_id: str = "default", source: str = "user_input") -> GuardVerdict:
        return self.detect(text, session_id, source)

    # C-2：异步接口 —— 同步管线放线程池，不阻塞事件循环
    async def detect_async(self, text: str, session_id: str = "default", source: str = "user_input") -> GuardVerdict:
        return await asyncio.to_thread(self.detect, text, session_id, source)

    # ==================== 工具调用治理（B-2 能力令牌 + A-3 operation_guard） ====================

    def check_tool(
        self,
        session_id: str,
        tool_name: str,
        parameters: Optional[Dict[str, Any]] = None,
        user_input: str = "",
    ) -> GuardVerdict:
        """工具调用前校验：能力令牌（默认 deny）→ operation_guard（参数级）"""
        start = time.perf_counter()
        parameters = parameters or {}

        # 1) 能力令牌（B-2）—— 与主流程共享同一令牌池，审批解锁直接生效
        token_result = self._tokens.check(session_id, tool_name, role=self.role)
        if not token_result.allowed:
            return GuardVerdict(
                allowed=False,
                risk_level="high",
                reason=token_result.reason,
                evidence=[f"missing_capabilities={sorted(token_result.missing_capabilities)}"],
                blocked_by="capability_token",
                latency_ms=(time.perf_counter() - start) * 1000,
            )

        # 2) operation_guard（A-3）—— 参数级拦截（路径遍历/黑名单/速率限制）
        intent = self._OperationIntent(
            tool_name=tool_name,
            parameters=parameters,
            session_id=session_id,
            user_input=user_input,
        )
        guard_result = self._op_guard.check_intent(intent)
        latency = (time.perf_counter() - start) * 1000
        if not guard_result.allowed:
            return GuardVerdict(
                allowed=False,
                risk_level=guard_result.risk_level.value if hasattr(guard_result.risk_level, "value") else "medium",
                reason=guard_result.reason,
                evidence=[f"blocked_by_rule={guard_result.blocked_by}"],
                blocked_by="operation_guard",
                latency_ms=latency,
            )

        return GuardVerdict(
            allowed=True,
            risk_level="none",
            reason=(f"需人工审批: {guard_result.approval_reason}" if guard_result.requires_approval
                    else "能力与参数校验通过"),
            evidence=[f"action_type={guard_result.action_type.value}"] if guard_result.action_type else [],
            blocked_by="",
            latency_ms=latency,
        )

    def grant_tool(self, session_id: str, tool_name: str) -> Dict[str, Any]:
        """审批解锁：授予会话使用该工具的能力（限定范围，TTL 1h）"""
        granted = self._tokens.grant_for_tool(session_id, tool_name, role=self.role)
        return {"session_id": session_id, "tool_name": tool_name, "active_grants": sorted(granted)}

    # ==================== 计划级评估（A-1/A-2 Plan IR + B-4 不可逆性） ====================

    def assess_plan(
        self,
        calls: List[Dict[str, Any]],
        task_id: str = "sdk-task",
        description: str = "",
    ) -> GuardVerdict:
        """评估一个工具调用计划（多步序列风险 + 不可逆性建模）"""
        start = time.perf_counter()
        plan = self._plan_builder.build_from_calls(task_id, description or task_id, calls)
        assessment = self._seq_evaluator.assess(plan)
        latency = (time.perf_counter() - start) * 1000
        intervention = assessment.intervention.value if hasattr(assessment.intervention, "value") else str(assessment.intervention)
        blocked = intervention == "block"
        return GuardVerdict(
            allowed=not blocked,
            risk_level=assessment.overall_risk_level.value if hasattr(assessment.overall_risk_level, "value") else "medium",
            reason=assessment.reason,
            evidence=[p.get("name", "") for p in (assessment.matched_patterns or [])],
            blocked_by="sequence_risk_evaluator" if blocked else "",
            latency_ms=latency,
        )

    # ==================== 输出过滤（A-5 PII/密钥脱敏） ====================

    def filter_output(self, text: str) -> GuardVerdict:
        """LLM 输出脱敏：API 密钥/JWT/身份证/手机号等自动打码"""
        start = time.perf_counter()
        result = self._output_filter.sanitize(text)
        return GuardVerdict(
            allowed=not result.has_critical,
            risk_level="high" if result.has_critical else "none",
            reason=f"脱敏 {result.filtered_count} 处敏感数据" if result.filtered_count else "输出无敏感数据",
            evidence=[f"{f.type}:{f.masked}" for f in result.findings[:10]],
            blocked_by="output_filter" if result.has_critical else "",
            sanitized=result.filtered,
            latency_ms=(time.perf_counter() - start) * 1000,
        )
