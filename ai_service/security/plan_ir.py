"""
Plan IR — 工具调用计划中间表示（创新点2升级版）

基于 NEXUS (arXiv:2607.19356) 的 Plan IR 概念，将 LLM 生成的工具调用序列
结构化为可评估的中间表示，支持序列级累积风险评估与四级干预策略。

升级点（相对原 mcp_combination_detector）：
1. 序列级评估：保留工具调用顺序，捕获"单工具无害、组合致命"的 STAC 攻击
2. 增量评分缓存：对未变更前缀复用评分，避免全量重算
3. 四级干预：allow / block / request_confirmation / request_revision
4. 副作用建模：显式不可逆性标志、资源估计
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Any, Optional, Set, Tuple

from models.schemas import RiskLevel, AttackType


class InterventionAction(str, Enum):
    """四级干预策略 — 基于 Plan IR 评估结果选择"""
    ALLOW = "allow"                          # 放行：只读 + 累积风险低
    BLOCK = "block"                          # 阻断：触发确定性规则
    REQUEST_CONFIRMATION = "request_confirmation"  # 请求人工确认
    REQUEST_REVISION = "request_revision"   # 请求 LLM 重新规划


class SideEffectClass(str, Enum):
    """工具副作用类别"""
    READ_ONLY = "read_only"        # 无副作用
    WRITE_LOCAL = "write_local"    # 本地写入
    WRITE_REMOTE = "write_remote"  # 远程写入（DB/API）
    EXECUTE = "execute"            # 命令/代码执行
    NETWORK = "network"           # 网络外发


@dataclass
class ToolCallIR:
    """单个工具调用的中间表示"""
    step: int                                    # 序列位置（1-based）
    tool_name: str
    arguments: Dict[str, Any] = field(default_factory=dict)
    capabilities: Set[str] = field(default_factory=set)
    side_effect: SideEffectClass = SideEffectClass.READ_ONLY
    irreversible: bool = False                   # 不可逆性标志
    resource_estimate: Dict[str, float] = field(default_factory=dict)  # CPU/内存/网络/时长

    def signature(self) -> str:
        """工具调用签名 — 用于增量缓存键"""
        payload = {
            "step": self.step,
            "tool": self.tool_name,
            "args": json.dumps(self.arguments, sort_keys=True, default=str),
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]


@dataclass
class PlanIR:
    """完整工具调用计划的中间表示"""
    plan_id: str
    user_query: str
    calls: List[ToolCallIR] = field(default_factory=list)
    created_at: str = ""

    def sequence_signature(self) -> str:
        """序列签名 — 用于增量评分缓存"""
        sig = "|".join(c.signature() for c in self.calls)
        return hashlib.sha256(sig.encode()).hexdigest()[:32]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "user_query": self.user_query,
            "created_at": self.created_at,
            "calls": [
                {
                    **asdict(c),
                    "capabilities": list(c.capabilities),
                    "side_effect": c.side_effect.value,
                }
                for c in self.calls
            ],
        }


@dataclass
class SequenceRiskAssessment:
    """序列级风险评估结果"""
    plan_id: str
    overall_risk_score: float
    overall_risk_level: RiskLevel
    intervention: InterventionAction
    matched_patterns: List[Dict[str, Any]] = field(default_factory=list)
    cumulative_scores: List[float] = field(default_factory=list)  # 每步累积评分
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "plan_id": self.plan_id,
            "overall_risk_score": round(self.overall_risk_score, 4),
            "overall_risk_level": self.overall_risk_level.value,
            "intervention": self.intervention.value,
            "matched_patterns": self.matched_patterns,
            "cumulative_scores": [round(s, 4) for s in self.cumulative_scores],
            "reason": self.reason,
        }


class PlanIRBuilder:
    """从 LLM 工具调用序列构造 Plan IR"""

    # 能力矩阵（复用 mcp_combination_detector，补充 network_access）
    CAPABILITY_MATRIX: Dict[str, List[str]] = {
        "git": ["file_read", "file_write", "repo_access"],
        "github": ["file_read", "file_write", "repo_access", "pr_management"],
        "browser": ["web_browse", "form_fill", "screenshot", "network_access"],
        "web": ["web_browse", "web_search", "network_access", "data_transfer"],
        "http": ["http_request", "data_transfer", "network_access"],
        "api": ["api_call", "data_transfer", "network_access"],
        "database": ["db_read", "db_write"],
        "sql": ["db_read", "db_write"],
        "filesystem": ["file_read", "file_write", "file_delete"],
        "file": ["file_read", "file_write"],
        "export": ["data_transfer", "db_read"],   # 导出类工具：数据外发+读取
        "terminal": ["command_exec", "file_read", "file_write"],
        "shell": ["command_exec", "file_read", "file_write"],
        "exec": ["command_exec"],
        "python": ["code_exec", "file_read", "network_access"],
        "email": ["data_transfer", "communication", "network_access"],
        "slack": ["communication", "file_transfer", "network_access"],
    }

    def build_from_calls(self, plan_id: str, user_query: str,
                         raw_calls: List[Dict[str, Any]]) -> PlanIR:
        """从原始工具调用列表构造 Plan IR"""
        from datetime import datetime
        calls: List[ToolCallIR] = []
        for i, raw in enumerate(raw_calls, 1):
            tool_name = raw.get("name", raw.get("tool_name", "unknown"))
            args = raw.get("arguments", raw.get("args", {}))
            caps = self._infer_capabilities(tool_name, args)
            side_effect = self._infer_side_effect(caps, tool_name)
            irreversible = side_effect in (
                SideEffectClass.EXECUTE, SideEffectClass.WRITE_REMOTE,
                SideEffectClass.NETWORK,  # 网络外发不可逆（数据一旦外传无法撤回）
            ) or "file_delete" in caps or "db_write" in caps
            calls.append(ToolCallIR(
                step=i,
                tool_name=tool_name,
                arguments=args,
                capabilities=caps,
                side_effect=side_effect,
                irreversible=irreversible,
                resource_estimate=self._estimate_resource(tool_name, side_effect),
            ))
        return PlanIR(plan_id=plan_id, user_query=user_query, calls=calls,
                      created_at=datetime.now().isoformat())

    def _infer_capabilities(self, tool_name: str, args: Dict[str, Any]) -> Set[str]:
        caps: Set[str] = set()
        name_lower = (tool_name or "").lower()
        for keyword, cs in self.CAPABILITY_MATRIX.items():
            if keyword in name_lower:
                caps.update(cs)
        return caps

    def _infer_side_effect(self, caps: Set[str], tool_name: str) -> SideEffectClass:
        if "command_exec" in caps or "code_exec" in caps:
            return SideEffectClass.EXECUTE
        if "network_access" in caps or "data_transfer" in caps:
            return SideEffectClass.NETWORK
        if "db_write" in caps or "file_write" in caps:
            return SideEffectClass.WRITE_REMOTE if "db_write" in caps else SideEffectClass.WRITE_LOCAL
        return SideEffectClass.READ_ONLY

    def _estimate_resource(self, tool_name: str, side_effect: SideEffectClass) -> Dict[str, float]:
        """轻量资源估计 — 用于资源限额干预"""
        base = {"cpu": 0.1, "memory_mb": 50, "network_kb": 0, "duration_s": 1.0}
        if side_effect == SideEffectClass.EXECUTE:
            base.update({"cpu": 0.5, "memory_mb": 200, "duration_s": 5.0})
        elif side_effect == SideEffectClass.NETWORK:
            base.update({"network_kb": 1024, "duration_s": 3.0})
        elif side_effect == SideEffectClass.WRITE_REMOTE:
            base.update({"duration_s": 2.0})
        return base
