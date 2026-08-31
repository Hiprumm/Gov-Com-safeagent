"""
Dify 适配器（方向C-5）

Dify 通过"自定义工具（Custom Tool）"接入外部 HTTP API。本适配器生成
Dify 所需的 OpenAPI Schema，并提供一个可直接挂到 uvicorn 的 FastAPI 应用：

    from gov_safeagent_sdk import SecurityGuard
    from gov_safeagent_sdk.adapters import DifyGuardTool

    guard = SecurityGuard()
    dify_tool = DifyGuardTool(guard)
    app = dify_tool.build_app()                 # uvicorn 运行后，把
    schema = dify_tool.build_openapi_schema()   # schema 粘贴进 Dify 自定义工具即可

Dify 工作流中：输入检测节点 / 工具调用守卫节点，均走 POST /dify/check。
"""
from __future__ import annotations

from typing import Any, Dict

from ..guard import SecurityGuard


class DifyGuardTool:
    """把 SecurityGuard 暴露为 Dify 可调用的自定义 HTTP 工具"""

    def __init__(self, guard: SecurityGuard):
        self._guard = guard

    # ---- Dify 侧调用的判定入口 ----

    def handle(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """POST /dify/check 的处理器

        payload:
          {"kind": "input"|"tool", "text": "...", "session_id": "...",
           "tool_name": "...", "parameters": {...}}
        返回: {"allowed": bool, "risk_level": str, "reason": str, ...}
        """
        kind = payload.get("kind", "input")
        session_id = payload.get("session_id", "default")
        if kind == "tool":
            verdict = self._guard.check_tool(
                session_id=session_id,
                tool_name=payload.get("tool_name", ""),
                parameters=payload.get("parameters") or {},
                user_input=payload.get("text", ""),
            )
        else:
            verdict = self._guard.detect_sync(payload.get("text", ""), session_id=session_id)
        return verdict.to_dict()

    # ---- OpenAPI Schema（粘贴进 Dify 自定义工具） ----

    def build_openapi_schema(self, base_url: str = "http://127.0.0.1:8090") -> Dict[str, Any]:
        return {
            "openapi": "3.0.0",
            "info": {"title": "gov-safeagent-guard", "version": "1.0.0",
                     "description": "政企智能体安全防护：输入检测 / 工具调用守卫"},
            "servers": [{"url": base_url}],
            "paths": {
                "/dify/check": {
                    "post": {
                        "operationId": "safeagent_check",
                        "summary": "输入检测或工具调用守卫",
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "kind": {"type": "string", "enum": ["input", "tool"],
                                                     "default": "input"},
                                            "text": {"type": "string"},
                                            "session_id": {"type": "string", "default": "default"},
                                            "tool_name": {"type": "string"},
                                            "parameters": {"type": "object"},
                                        },
                                    }
                                }
                            },
                        },
                        "responses": {
                            "200": {
                                "description": "判定结果",
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "allowed": {"type": "boolean"},
                                                "risk_level": {"type": "string"},
                                                "reason": {"type": "string"},
                                                "blocked_by": {"type": "string"},
                                            },
                                        }
                                    }
                                },
                            }
                        },
                    }
                }
            },
        }

    # ---- FastAPI 应用工厂 ----

    def build_app(self):
        from fastapi import FastAPI
        from fastapi.middleware.cors import CORSMiddleware

        app = FastAPI(title="gov-safeagent-dify-tool", version="1.0.0")
        app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"],
                           allow_headers=["*"])

        @app.post("/dify/check")
        def check(payload: Dict[str, Any]) -> Dict[str, Any]:
            return self.handle(payload)

        return app
