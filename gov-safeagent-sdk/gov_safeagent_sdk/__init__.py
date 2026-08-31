"""
gov-safeagent-sdk —— 政企大模型智能体安全防护 SDK

三种交付形态之一（SDK 嵌入）：
    from gov_safeagent_sdk import SecurityGuard
    guard = SecurityGuard()
    verdict = guard.detect_sync("用户的任意输入")

另见:
- SafeAgentClient : Gateway 远程客户端（形态2 中间件的配套）
- adapters/       : LangChain / LlamaIndex / Dify 框架适配器
"""
from .guard import SecurityGuard, GuardVerdict
from .client import SafeAgentClient

__version__ = "0.1.0"
__all__ = ["SecurityGuard", "GuardVerdict", "SafeAgentClient"]
