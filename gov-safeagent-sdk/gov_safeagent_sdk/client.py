"""
SafeAgentClient —— 通过 Gateway 远程调用的轻量客户端（方向C-2）

适合"SDK 嵌入不方便、但 Gateway 已部署"的场景：
- 同步:  client.detect_sync(text)
- 异步:  await client.detect_async(text)
- 工具:  client.check_tool(session, tool, args)

网关侧（gateway/main.py）暴露对应 REST API：
POST /api/sdk/detect | /api/sdk/tool-check | /api/sdk/output-filter
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, Optional

import httpx


class SafeAgentClient:
    """Gov-SafeAgent Gateway 的同步/异步客户端"""

    def __init__(self, gateway_url: str = "http://127.0.0.1:8081", timeout: float = 30.0):
        self.base_url = gateway_url.rstrip("/")
        self._timeout = timeout
        self._async_client: Optional[httpx.AsyncClient] = None

    # ---------- 内部 ----------

    def _post(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        with httpx.Client(timeout=self._timeout) as client:
            resp = client.post(f"{self.base_url}{path}", json=payload)
            resp.raise_for_status()
            return resp.json()

    async def _post_async(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        if self._async_client is None:
            self._async_client = httpx.AsyncClient(timeout=self._timeout)
        resp = await self._async_client.post(f"{self.base_url}{path}", json=payload)
        resp.raise_for_status()
        return resp.json()

    # ---------- 同步接口 ----------

    def detect_sync(self, text: str, session_id: str = "default", source: str = "user_input") -> Dict[str, Any]:
        return self._post("/api/sdk/detect", {"text": text, "session_id": session_id, "source": source})

    def check_tool(self, session_id: str, tool_name: str,
                   parameters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self._post("/api/sdk/tool-check",
                          {"session_id": session_id, "tool_name": tool_name, "parameters": parameters or {}})

    def filter_output(self, text: str) -> Dict[str, Any]:
        return self._post("/api/sdk/output-filter", {"text": text})

    # ---------- 异步接口 ----------

    async def detect_async(self, text: str, session_id: str = "default", source: str = "user_input") -> Dict[str, Any]:
        return await self._post_async("/api/sdk/detect", {"text": text, "session_id": session_id, "source": source})

    async def check_tool_async(self, session_id: str, tool_name: str,
                               parameters: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return await self._post_async("/api/sdk/tool-check",
                                      {"session_id": session_id, "tool_name": tool_name, "parameters": parameters or {}})

    async def filter_output_async(self, text: str) -> Dict[str, Any]:
        return await self._post_async("/api/sdk/output-filter", {"text": text})

    async def aclose(self) -> None:
        if self._async_client:
            await self._async_client.aclose()
            self._async_client = None
