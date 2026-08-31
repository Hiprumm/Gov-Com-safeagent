# -*- coding: utf-8 -*-
"""框架适配 quickstart —— LangChain / LlamaIndex / Dify（<10 行接入）"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from gov_safeagent_sdk import SecurityGuard
from gov_safeagent_sdk.adapters import GuardedTool

guard = SecurityGuard()

# ---- LangChain：包装既有 Tool，Agent 代码其余不变 ----
class MySearchTool:                                  # 客户已有的任意 LangChain Tool
    name = "search_knowledge"
    description = "知识库检索"
    def run(self, tool_input, *a, **kw):
        return f"搜索结果: {tool_input}"

safe_tool = GuardedTool(MySearchTool(), guard, session_id="sess-1")
print("只读工具:", safe_tool.run({"query": "公积金政策"})[:30])

# ---- LlamaIndex: GuardedQueryEngine(引擎, guard) 查询前检测+结果脱敏 ----
# ---- Dify: DifyGuardTool(guard).build_openapi_schema() 粘贴进自定义工具 ----
