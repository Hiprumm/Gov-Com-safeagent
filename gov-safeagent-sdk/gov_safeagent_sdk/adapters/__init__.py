"""
框架适配器（方向C-5）—— LangChain / LlamaIndex / Dify

设计原则：适配逻辑框架无关（复用 SecurityGuard），框架类仅在真正使用时
才 import —— 未安装对应框架不影响 SDK 其他功能。

- langchain_adapter  : GuardedTool（包装任意 LangChain Tool，调用前能力校验+参数守卫）
- llamaindex_adapter : GuardedQueryEngine（包装 QueryEngine，查询前输入检测，结果脱敏）
- dify_adapter       : DifyGuardTool（Dify 自定义工具节点的接入桩，HTTP API 形态）
"""
from .langchain_adapter import GuardedTool
from .llamaindex_adapter import GuardedQueryEngine
from .dify_adapter import DifyGuardTool

__all__ = ["GuardedTool", "GuardedQueryEngine", "DifyGuardTool"]
