"""
LlamaIndex 适配器（方向C-5）

用法（客户 Agent 侧）：

    from gov_safeagent_sdk import SecurityGuard
    from gov_safeagent_sdk.adapters import GuardedQueryEngine

    guard = SecurityGuard()
    engine = GuardedQueryEngine(index.as_query_engine(), guard, session_id="sess-1")
    answer = engine.query("查询公积金政策")   # 查询前输入检测，返回结果自动脱敏

GuardedQueryEngine:
1. query()/aquery() 前执行输入检测（high/critical 直接拒绝，注入攻击进不了检索）
2. 返回结果过 output_filter（PII/密钥脱敏后才给用户）
"""
from __future__ import annotations

from typing import Any, Optional

from ..guard import SecurityGuard


class QueryGuardException(Exception):
    """查询被安全层拒绝时抛出"""

    def __init__(self, verdict_dict: dict):
        self.verdict = verdict_dict
        super().__init__(
            f"[gov-safeagent] 查询被拦截: {verdict_dict.get('blocked_by')} | {verdict_dict.get('reason')}"
        )


class GuardedQueryEngine:
    """包装任意 LlamaIndex QueryEngine"""

    def __init__(self, engine: Any, guard: SecurityGuard, session_id: str = "default"):
        self._engine = engine
        self._guard = guard
        self._session_id = session_id

    def __getattr__(self, item: str) -> Any:
        return getattr(self._engine, item)

    # ---- LlamaIndex 调用入口 ----

    def _check_input(self, query: str) -> None:
        verdict = self._guard.detect_sync(query, session_id=self._session_id)
        if not verdict.allowed:
            raise QueryGuardException(verdict.to_dict())

    def _filter_response(self, response: Any) -> Any:
        text = getattr(response, "response", None) or str(response)
        filtered = self._guard.filter_output(text)
        if filtered.sanitized is not None and hasattr(response, "response"):
            try:
                response.response = filtered.sanitized  # LlamaIndex Response 对象可直接改写
            except Exception:
                return filtered.sanitized
            return response
        return filtered.sanitized if filtered.sanitized is not None else response

    def query(self, query: str, *args, **kwargs) -> Any:
        self._check_input(query)
        return self._filter_response(self._engine.query(query, *args, **kwargs))

    async def aquery(self, query: str, *args, **kwargs) -> Any:
        self._check_input(query)
        return self._filter_response(await self._engine.aquery(query, *args, **kwargs))
