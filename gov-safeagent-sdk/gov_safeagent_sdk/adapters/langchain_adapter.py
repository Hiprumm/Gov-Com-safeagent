"""
LangChain 适配器（方向C-5）

用法（客户 Agent 侧 <10 行接入）：

    from gov_safeagent_sdk import SecurityGuard
    from gov_safeagent_sdk.adapters import GuardedTool

    guard = SecurityGuard()
    safe_search = GuardedTool(my_search_tool, guard, session_id="sess-1")
    agent = create_react_agent(llm, [safe_search, safe_db])   # 原有代码不变

GuardedTool 会在每次工具调用前执行：
1. capability_token 能力校验（B-2 默认 deny —— 未审批的危险工具直接拒绝）
2. operation_guard 参数级校验（A-3 路径遍历/黑名单/速率限制）
被拦截时抛出 ToolGuardException，LangChain 的错误处理链路会将其反馈给 Agent。
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from ..guard import SecurityGuard


class ToolGuardException(Exception):
    """工具调用被安全层拒绝时抛出（LangChain 会作为工具错误捕获）"""

    def __init__(self, verdict_dict: Dict[str, Any]):
        self.verdict = verdict_dict
        super().__init__(
            f"[gov-safeagent] 工具调用被拦截: {verdict_dict.get('blocked_by')} | {verdict_dict.get('reason')}"
        )


class GuardedTool:
    """包装任意 LangChain Tool（BaseTool），调用前走安全校验"""

    def __init__(self, tool: Any, guard: SecurityGuard,
                 session_id: str = "default", user_input: str = ""):
        self._tool = tool
        self._guard = guard
        self._session_id = session_id
        self._user_input = user_input

    # ---- 让 GuardedTool 可以直接放进 LangChain 的 tools 列表 ----

    @property
    def name(self) -> str:
        return getattr(self._tool, "name", type(self._tool).__name__)

    @property
    def description(self) -> str:
        return getattr(self._tool, "description", "")

    def __getattr__(self, item: str) -> Any:
        # 其余属性（args_schema / return_direct / ainvoke 等）透传底层工具
        return getattr(self._tool, item)

    # ---- LangChain 调用入口 ----

    def _check(self, tool_input: Any) -> None:
        params: Dict[str, Any] = (
            {"input": tool_input} if not isinstance(tool_input, dict) else dict(tool_input)
        )
        verdict = self._guard.check_tool(
            session_id=self._session_id,
            tool_name=self.name,
            parameters=params,
            user_input=self._user_input,
        )
        if not verdict.allowed:
            raise ToolGuardException(verdict.to_dict())

    def run(self, tool_input: Any, *args, **kwargs) -> Any:
        self._check(tool_input)
        return self._tool.run(tool_input, *args, **kwargs)

    async def arun(self, tool_input: Any, *args, **kwargs) -> Any:
        self._check(tool_input)
        return await self._tool.arun(tool_input, *args, **kwargs)

    def invoke(self, tool_input: Any, config: Optional[Any] = None, **kwargs) -> Any:
        self._check(tool_input)
        return self._tool.invoke(tool_input, config=config, **kwargs)

    async def ainvoke(self, tool_input: Any, config: Optional[Any] = None, **kwargs) -> Any:
        self._check(tool_input)
        return await self._tool.ainvoke(tool_input, config=config, **kwargs)
