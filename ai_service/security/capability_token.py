"""
会话级能力令牌（方向B-2）— 默认最小权限 + 审批解锁授予

P1 架构消解的核心执行点："先给权限再检测"改为"默认不给、审批才给"。

工作方式：
1. 每个会话首次工具调用时自动发放令牌，默认只含角色的只读能力集（B-1 矩阵）
2. tool_execution 执行前校验令牌：工具所需"需授权能力"未在令牌中 → 拒绝（默认 deny）
3. 审批流通过（人工批准 / B-5 会话解锁复用）时，把该工具的能力授予令牌
4. 令牌校验为内存 dict + set 运算，微秒级（验收标准 < 5ms）

即使检测层（input_detection）被绕过或失效，攻击者构造的任意危险工具调用
（execute_command / write_file / export_data）仍会被令牌校验拒绝 —— 这就是
P1 验收标准："关掉检测层，攻击者拿到的能力仍不足以造成伤害"。
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Set

from security.capability_matrix import (
    get_tool_capabilities,
    get_grant_required_capabilities,
    get_default_grants,
    capability_info,
)

# 令牌有效期（秒）——过期后危险能力失效，需重新审批（只读默认能力不过期）
TOKEN_TTL_SECONDS = 3600


@dataclass
class CapabilityToken:
    """一个会话的能力令牌"""
    session_id: str
    role: str = "user"
    granted: Set[str] = field(default_factory=set)   # 当前持有的能力（含只读默认 + 审批授予）
    issued_at: float = field(default_factory=time.time)
    grants: Dict[str, float] = field(default_factory=dict)  # 授予的能力 → 授予时间戳（TTL 用）

    def _has(self, cap: str) -> bool:
        return "*" in self.granted or cap in self.granted

    def effective_grants(self) -> Set[str]:
        """仍有效的授予型能力（默认只读能力不过期，授予能力受 TTL 约束）"""
        now = time.time()
        return {
            cap for cap, ts in self.grants.items()
            if now - ts <= TOKEN_TTL_SECONDS
        }

    def snapshot(self) -> Dict:
        return {
            "session_id": self.session_id,
            "role": self.role,
            "granted": sorted(self.granted),
            "active_grants": sorted(self.effective_grants()),
        }


@dataclass
class CapabilityCheckResult:
    """令牌校验结果"""
    allowed: bool
    tool_name: str
    required_grant_caps: Set[str] = field(default_factory=set)  # 该工具需授权的能力
    missing_capabilities: Set[str] = field(default_factory=set)  # 令牌缺失的能力
    capabilities: Set[str] = field(default_factory=set)          # 工具全部所需能力
    reason: str = ""
    duration_ms: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "allowed": self.allowed,
            "tool_name": self.tool_name,
            "capabilities": sorted(self.capabilities),
            "required_grant_caps": sorted(self.required_grant_caps),
            "missing_capabilities": sorted(self.missing_capabilities),
            "reason": self.reason,
            "duration_ms": round(self.duration_ms, 3),
        }


class CapabilityTokenManager:
    """会话级能力令牌管理器"""

    def __init__(self):
        self._tokens: Dict[str, CapabilityToken] = {}
        # RLock（可重入）：check/grant 持锁调用 get_or_issue 时避免自锁死锁
        self._lock = threading.RLock()
        self._check_count = 0
        self._deny_count = 0
        self._total_check_ms = 0.0

    # ---------- 令牌生命周期 ----------

    def get_or_issue(self, session_id: str, role: str = "user") -> CapabilityToken:
        """获取会话令牌；首次访问自动发放（默认只读最小权限）"""
        with self._lock:
            token = self._tokens.get(session_id)
            if token is None:
                token = CapabilityToken(
                    session_id=session_id,
                    role=role,
                    granted=get_default_grants(role),
                )
                self._tokens[session_id] = token
            return token

    def grant(self, session_id: str, capabilities: Set[str], role: str = "user") -> Set[str]:
        """授予会话能力（审批通过 / 会话解锁时调用）。返回当前有效授予集。"""
        with self._lock:
            token = self.get_or_issue(session_id, role)
            now = time.time()
            for cap in capabilities:
                token.granted.add(cap)
                token.grants[cap] = now
            return set(token.granted)

    def grant_for_tool(self, session_id: str, tool_name: str, role: str = "user") -> Set[str]:
        """审批解锁某工具时，授予该工具所需的全部能力（限定范围，不是无限授权）"""
        caps = get_tool_capabilities(tool_name)
        return self.grant(session_id, caps, role)

    def revoke(self, session_id: str, capabilities: Set[str]) -> None:
        """收回能力（会话终止/风险熔断时调用）"""
        with self._lock:
            token = self._tokens.get(session_id)
            if token:
                token.granted -= set(capabilities)
                for cap in capabilities:
                    token.grants.pop(cap, None)

    def revoke_session(self, session_id: str) -> None:
        """作废整个会话令牌（下次访问按默认最小权限重新发放）"""
        with self._lock:
            self._tokens.pop(session_id, None)

    # ---------- 核心校验（tool_execution 执行前调用） ----------

    def check(self, session_id: str, tool_name: str, role: str = "user") -> CapabilityCheckResult:
        """校验会话令牌是否具备工具所需能力。内存 set 运算，微秒级。"""
        start = time.perf_counter()
        caps = get_tool_capabilities(tool_name)
        required = get_grant_required_capabilities(tool_name)

        with self._lock:
            token = self.get_or_issue(session_id, role)
            # 授予型能力校验 TTL；"*" 通配（admin）或能力在有效授予集内即通过
            if "*" in token.granted:
                missing: Set[str] = set()
            else:
                active = token.effective_grants() | {
                    c for c in token.granted
                    if not capability_info(c)["grant_required"]
                }
                missing = required - active
            snapshot_missing = set(missing)

        allowed = not snapshot_missing
        if allowed:
            reason = (f"令牌具备工具所需能力（授予型: {sorted(required) or '无'}）"
                      if required else "只读工具，默认能力即可执行")
        else:
            risk = max((capability_info(c)["risk"] for c in snapshot_missing), default="medium")
            reason = (f"能力不足（默认deny）：工具需要 {sorted(snapshot_missing)}，"
                      f"令牌未持有 —— 需审批解锁（缺失能力最高风险级: {risk}）")

        duration_ms = (time.perf_counter() - start) * 1000
        with self._lock:
            self._check_count += 1
            self._total_check_ms += duration_ms
            if not allowed:
                self._deny_count += 1

        return CapabilityCheckResult(
            allowed=allowed,
            tool_name=tool_name,
            required_grant_caps=required,
            missing_capabilities=snapshot_missing,
            capabilities=caps,
            reason=reason,
            duration_ms=duration_ms,
        )

    # ---------- 观测 ----------

    def stats(self) -> Dict:
        with self._lock:
            avg = (self._total_check_ms / self._check_count) if self._check_count else 0.0
            return {
                "sessions": len(self._tokens),
                "check_count": self._check_count,
                "deny_count": self._deny_count,
                "avg_check_ms": round(avg, 4),
            }

    def token_info(self, session_id: str) -> Dict:
        token = self._tokens.get(session_id)
        return token.snapshot() if token else {"session_id": session_id, "exists": False}


# 模块级单例：SecurityLayer 与 graph 节点共享同一令牌池（与会话解锁缓存同模式）
_capability_token_manager: CapabilityTokenManager | None = None
_token_lock = threading.Lock()


def get_capability_token_manager() -> CapabilityTokenManager:
    global _capability_token_manager
    if _capability_token_manager is None:
        with _token_lock:
            if _capability_token_manager is None:
                _capability_token_manager = CapabilityTokenManager()
    return _capability_token_manager
