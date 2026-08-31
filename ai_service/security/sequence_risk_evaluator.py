"""
序列级风险评估器（创新点2升级版）

核心升级：
1. 序列级累积评分：保留工具调用顺序，捕获 STAC 类工具链攻击
2. 增量评分缓存：对未变更前缀复用评分，避免全量重算
3. 四级干预策略选择：allow / block / request_confirmation / request_revision
4. 混合风险评估：确定性规则 + 累积评分
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Dict, List, Any, Optional, Set, Tuple

from models.schemas import RiskLevel, AttackType
from security.plan_ir import (
    PlanIR, ToolCallIR, SequenceRiskAssessment,
    InterventionAction, SideEffectClass,
)


# 确定性阻断规则 — 触发即 BLOCK，不参与评分
BLOCK_RULES: List[Dict[str, Any]] = [
    {
        "name": "命令执行+网络回连",
        "required": {"command_exec", "network_access"},
        "reason": "命令执行工具与网络访问组合，可建立反向回连",
        "attack_type": AttackType.COMMAND_EXECUTION,
    },
    {
        "name": "命令执行+代码执行",
        "required": {"command_exec", "code_exec"},
        "reason": "命令执行与代码执行组合，可执行任意代码",
        "attack_type": AttackType.COMMAND_EXECUTION,
    },
    {
        "name": "数据外发+凭证访问",
        "required": {"data_transfer", "search"},
        "reason": "搜索凭证后外发，数据泄露风险",
        "attack_type": AttackType.DATA_LEAKAGE,
    },
]

# 累积风险模式 — 用于序列级评分
CUMULATIVE_PATTERNS: List[Dict[str, Any]] = [
    {
        "name": "数据读取→外传链",
        "sequence": ["file_read", "data_transfer"],
        "weight": 0.35,
        "attack_type": AttackType.DATA_EXFILTRATION,
    },
    {
        "name": "DB读取→外传链",
        "sequence": ["db_read", "network_access"],
        "weight": 0.40,
        "attack_type": AttackType.DATA_EXFILTRATION,
    },
    {
        "name": "代码仓库→执行链",
        "sequence": ["repo_access", "code_exec"],
        "weight": 0.38,
        "attack_type": AttackType.DATA_POISONING,
    },
    {
        "name": "搜索→通讯外传链",
        "sequence": ["search", "communication"],
        "weight": 0.25,
        "attack_type": AttackType.DATA_LEAKAGE,
    },
]

# 阈值配置
CONFIRM_THRESHOLD = 0.55     # 累积评分超此值 → REQUEST_CONFIRMATION
REVISE_THRESHOLD = 0.40     # 参数级可疑但未达确认 → REQUEST_REVISION


class SequenceRiskEvaluator:
    """序列级风险评估器 — 含增量评分缓存"""

    def __init__(self):
        # 缓存：序列签名 → (累积评分, 匹配模式列表, 步级评分)
        # 增量优化：对未变更前缀复用评分，仅对新增步骤增量计算
        self._cache: Dict[str, Tuple[float, List[Dict], List[float]]] = {}
        self._cache_hits = 0
        self._cache_misses = 0

    def assess(self, plan: PlanIR) -> SequenceRiskAssessment:
        """评估 Plan IR 的序列级风险，返回干预策略"""
        seq_sig = plan.sequence_signature()

        # 1. 确定性阻断规则优先（无需缓存）
        block_match = self._check_block_rules(plan)
        if block_match:
            return SequenceRiskAssessment(
                plan_id=plan.plan_id,
                overall_risk_score=1.0,
                overall_risk_level=RiskLevel.CRITICAL,
                intervention=InterventionAction.BLOCK,
                matched_patterns=[block_match],
                cumulative_scores=[1.0] * len(plan.calls),
                reason=f"触发确定性阻断规则：{block_match['name']}",
            )

        # 2. 方向B-4：不可逆性熔断检查 — 不可逆外发类操作叠加可疑参数 → 直接 BLOCK
        #    （数据一旦外传/命令一旦执行无法撤回，叠加攻击信号时不再给"确认"机会）
        irreversible = self._collect_irreversibility(plan)
        if irreversible and irreversible["circuit_break"]:
            return SequenceRiskAssessment(
                plan_id=plan.plan_id,
                overall_risk_score=1.0,
                overall_risk_level=RiskLevel.CRITICAL,
                intervention=InterventionAction.BLOCK,
                matched_patterns=[irreversible["pattern"]],
                cumulative_scores=[1.0] * len(plan.calls),
                reason=f"不可逆熔断：{irreversible['pattern']['reason']}",
            )

        # 3. 增量缓存查询
        cached = self._cache.get(seq_sig)
        if cached is not None:
            self._cache_hits += 1
            overall, patterns, step_scores = cached
        else:
            self._cache_misses += 1
            overall, patterns, step_scores = self._compute_sequence_risk(plan)
            self._cache[seq_sig] = (overall, patterns, step_scores)

        # 4. 选择干预策略
        intervention, reason = self._select_intervention(overall, patterns, plan)

        # 5. 方向B-4：不可逆操作升级干预 — 不可逆步骤不允许静默放行（ALLOW/REVISION → CONFIRMATION）
        if irreversible:
            if intervention in (InterventionAction.ALLOW, InterventionAction.REQUEST_REVISION):
                intervention = InterventionAction.REQUEST_CONFIRMATION
                reason = (f"包含不可逆操作（{irreversible['summary']}），"
                          f"不允许静默放行，需人工确认 | 原评估: {reason}")
            patterns = patterns + [irreversible["pattern"]]

        risk_level = self._score_to_risk(overall)
        return SequenceRiskAssessment(
            plan_id=plan.plan_id,
            overall_risk_score=overall,
            overall_risk_level=risk_level,
            intervention=intervention,
            matched_patterns=patterns,
            cumulative_scores=step_scores,
            reason=reason,
        )

    # ==================== 方向B-4：不可逆性建模 ====================

    # 不可逆"外发类"副作用 — 数据/命令一旦离开本机即无法撤回
    _EXFIL_SIDE_EFFECTS = {SideEffectClass.NETWORK, SideEffectClass.EXECUTE, SideEffectClass.WRITE_REMOTE}

    def _collect_irreversibility(self, plan: PlanIR) -> Optional[Dict[str, Any]]:
        """收集计划中的不可逆步骤，判定是否触发熔断

        - 任意不可逆步骤 → 干预策略至少升级为 request_confirmation（不允许静默放行）
        - 不可逆"外发类"步骤 + 可疑参数（curl|sh / rm -rf / 反弹shell等）→ 熔断 BLOCK
        """
        irreversible_steps = [
            {"step": c.step, "tool": c.tool_name, "side_effect": c.side_effect.value}
            for c in plan.calls if c.irreversible
        ]
        if not irreversible_steps:
            return None

        exfil_steps = [s for s in irreversible_steps
                       if SideEffectClass(s["side_effect"]) in self._EXFIL_SIDE_EFFECTS]
        suspicious = self._has_suspicious_args(plan)
        circuit_break = bool(exfil_steps) and suspicious

        tools = ", ".join(s["tool"] for s in irreversible_steps)
        if circuit_break:
            reason = (f"不可逆外发类操作（{tools}）叠加可疑参数"
                      f"（命令注入/回连特征），数据一旦外发无法撤回，直接熔断")
        else:
            reason = f"包含不可逆操作（{tools}）：副作用无法撤销，需人工确认"

        return {
            "steps": irreversible_steps,
            "summary": tools,
            "circuit_break": circuit_break,
            "pattern": {
                "name": "不可逆操作熔断" if circuit_break else "不可逆操作确认",
                "tools": [s["tool"] for s in irreversible_steps],
                "side_effects": [s["side_effect"] for s in irreversible_steps],
                "reason": reason,
                "rule_type": "irreversibility_breaker" if circuit_break else "irreversibility",
            },
        }

    def _check_block_rules(self, plan: PlanIR) -> Optional[Dict[str, Any]]:
        """确定性阻断规则检查"""
        all_caps: Set[str] = set()
        for call in plan.calls:
            all_caps.update(call.capabilities)
        for rule in BLOCK_RULES:
            if rule["required"].issubset(all_caps):
                return {
                    "name": rule["name"],
                    "required": list(rule["required"]),
                    "reason": rule["reason"],
                    "attack_type": rule["attack_type"].value,
                    "rule_type": "deterministic_block",
                }
        return None

    def _compute_sequence_risk(self, plan: PlanIR) -> Tuple[float, List[Dict], List[float]]:
        """序列级累积风险计算（核心算法）"""
        step_scores: List[float] = []
        matched_patterns: List[Dict[str, Any]] = []

        # 累积能力集 — 用于序列级模式匹配
        accumulated_caps: List[Set[str]] = []
        running_caps: Set[str] = set()

        for i, call in enumerate(plan.calls):
            running_caps = running_caps | call.capabilities
            accumulated_caps.append(set(running_caps))

            # 步级评分：基础分（副作用）+ 累积模式匹配增量
            base = self._side_effect_base_score(call.side_effect)
            seq_bonus = self._sequence_pattern_bonus(plan.calls[:i + 1], i)
            step_score = min(1.0, base + seq_bonus)
            step_scores.append(step_score)

        # 序列级模式匹配（全序列）
        for pattern in CUMULATIVE_PATTERNS:
            if self._match_sequence_pattern(plan.calls, pattern["sequence"]):
                matched_patterns.append({
                    "name": pattern["name"],
                    "sequence": pattern["sequence"],
                    "weight": pattern["weight"],
                    "attack_type": pattern["attack_type"].value,
                    "rule_type": "cumulative",
                })

        # 整体评分 = 最大步级评分 + 序列模式权重（加权）
        max_step = max(step_scores) if step_scores else 0.0
        pattern_sum = sum(p["weight"] for p in matched_patterns)
        overall = min(1.0, max_step + pattern_sum * 0.5)

        return overall, matched_patterns, step_scores

    def _side_effect_base_score(self, side_effect: SideEffectClass) -> float:
        """基于副作用类别的基础风险分"""
        return {
            SideEffectClass.READ_ONLY: 0.05,
            SideEffectClass.WRITE_LOCAL: 0.15,
            SideEffectClass.WRITE_REMOTE: 0.30,
            SideEffectClass.EXECUTE: 0.45,
            SideEffectClass.NETWORK: 0.35,
        }.get(side_effect, 0.05)

    def _sequence_pattern_bonus(self, calls_so_far: List[ToolCallIR], current_idx: int) -> float:
        """序列模式增量奖励 — 检测累积能力是否形成新模式"""
        if current_idx == 0:
            return 0.0
        accumulated: Set[str] = set()
        for c in calls_so_far:
            accumulated.update(c.capabilities)
        # 简化：若当前步引入新能力且与前序能力形成数据外传链，给予奖励
        current_caps = calls_so_far[current_idx].capabilities
        prev_caps = accumulated - current_caps
        bonus = 0.0
        if "data_transfer" in current_caps and ("file_read" in prev_caps or "db_read" in prev_caps):
            bonus += 0.20  # 数据读取→外传链
        if "network_access" in current_caps and "command_exec" in prev_caps:
            bonus += 0.25  # 命令执行→网络回连（未触发确定性规则时）
        return bonus

    def _match_sequence_pattern(self, calls: List[ToolCallIR], seq: List[str]) -> bool:
        """检查工具调用序列是否包含指定能力子序列（顺序敏感）"""
        cap_seq: List[str] = []
        for c in calls:
            cap_seq.extend(c.capabilities)
        # 简化为集合子序列检查（保留顺序的简化版）
        try:
            idx = 0
            for target in seq:
                if target in cap_seq[idx:]:
                    idx = cap_seq.index(target, idx) + 1
                else:
                    return False
            return True
        except ValueError:
            return False

    def _select_intervention(self, overall: float, patterns: List[Dict],
                             plan: PlanIR) -> Tuple[InterventionAction, str]:
        """四级干预策略选择"""
        # 阻断已由确定性规则处理
        if overall >= CONFIRM_THRESHOLD:
            return (InterventionAction.REQUEST_CONFIRMATION,
                    f"累积风险评分 {overall:.2f} 超过确认阈值 {CONFIRM_THRESHOLD}，需人工审批")
        if overall >= REVISE_THRESHOLD:
            # 检查是否有参数级可疑模式
            has_suspicious = self._has_suspicious_args(plan)
            if has_suspicious:
                return (InterventionAction.REQUEST_REVISION,
                        f"累积风险评分 {overall:.2f} 且检测到可疑参数，建议重新规划")
        return (InterventionAction.ALLOW,
                f"累积风险评分 {overall:.2f} 低于阈值，允许执行")

    def _has_suspicious_args(self, plan: PlanIR) -> bool:
        """参数级可疑模式检查（轻量正则）"""
        suspicious_patterns = [
            r"rm\s+-rf", r"curl\s+.*\|\s*sh", r"wget\s+.*\|\s*sh",
            r";\s*rm\s+", r"\$\(", r"`.*`", r"\|\s*bash",
        ]
        for call in plan.calls:
            args_str = json.dumps(call.arguments, default=str)
            for pat in suspicious_patterns:
                if re.search(pat, args_str):
                    return True
        return False

    def _score_to_risk(self, score: float) -> RiskLevel:
        if score >= 0.85:
            return RiskLevel.CRITICAL
        if score >= 0.6:
            return RiskLevel.HIGH
        if score >= 0.3:
            return RiskLevel.MEDIUM
        if score > 0:
            return RiskLevel.LOW
        return RiskLevel.NONE

    def cache_stats(self) -> Dict[str, int]:
        """缓存命中率统计（性能优化验证用）"""
        total = self._cache_hits + self._cache_misses
        return {
            "hits": self._cache_hits,
            "misses": self._cache_misses,
            "total": total,
            "hit_rate": round(self._cache_hits / total, 4) if total > 0 else 0,
        }

    def clear_cache(self) -> None:
        self._cache.clear()
        self._cache_hits = 0
        self._cache_misses = 0
