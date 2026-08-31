"""
Gateway 拦截器（方向C-4）—— 三个 hook 点，均能阻断或改写

┌─────────┐  ①请求前检测   ┌──────────┐  ③响应后过滤  ┌────────┐
│ 客户请求 │ ─────────────▶ │ 客户Agent │ ────────────▶ │ 客户端 │
└─────────┘                └──────────┘                └────────┘
                                 ▲ ②工具调用代理（Agent 的工具执行走守卫）

① intercept_request : 输入检测（high/critical → 403 阻断，不达 Agent）
② intercept_tool_call: 能力令牌 + operation_guard（默认 deny）
③ intercept_response : 输出脱敏（PII/密钥打码后改写响应体）

框架无关（纯 dict in/out），main.py 只做 HTTP 接线。
"""
from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from gov_safeagent_sdk import SecurityGuard

# 视为"用户输入"的请求字段名（命中即检测；可通过环境变量扩展）
DEFAULT_INPUT_FIELDS = (
    "user_input", "message", "query", "input", "prompt", "question", "text", "content",
)


class GatewayInterceptors:
    """三个拦截点的实现（持有共享 SecurityGuard）"""

    def __init__(self, guard: Optional[SecurityGuard] = None,
                 input_fields: Tuple[str, ...] = DEFAULT_INPUT_FIELDS):
        self.guard = guard or SecurityGuard()
        self.input_fields = input_fields
        self.stats = {"requests_checked": 0, "requests_blocked": 0,
                      "responses_filtered": 0, "findings_masked": 0,
                      "tool_calls_checked": 0, "tool_calls_blocked": 0}

    # ---------- 会话标识 ----------

    @staticmethod
    def _session_id(query_params: Dict[str, str], body: Optional[dict], headers: Dict[str, str]) -> str:
        for source in (query_params, body or {}):
            if isinstance(source, dict) and source.get("session_id"):
                return str(source["session_id"])
        return headers.get("x-session-id", "default")

    # ---------- ① 请求前检测 ----------

    def extract_input(self, query_params: Dict[str, str], body: Optional[dict]) -> Optional[str]:
        """从查询参数或 JSON 体中提取用户输入"""
        for field in self.input_fields:
            if query_params.get(field):
                return str(query_params[field])
        if isinstance(body, dict):
            for field in self.input_fields:
                if body.get(field):
                    return str(body[field])
        return None

    def intercept_request(self, query_params: Dict[str, str], body: Optional[dict],
                          headers: Dict[str, str]) -> Tuple[bool, Dict[str, Any]]:
        """返回 (allowed, verdict_dict)。阻断时网关直接回 403，不转发上游。"""
        user_input = self.extract_input(query_params, body)
        if not user_input:
            return True, {"allowed": True, "reason": "未发现用户输入字段，直通"}

        self.stats["requests_checked"] += 1
        session_id = self._session_id(query_params, body, headers)
        verdict = self.guard.detect_sync(user_input, session_id=session_id)
        if not verdict.allowed:
            self.stats["requests_blocked"] += 1
        return verdict.allowed, verdict.to_dict()

    # ---------- ② 工具调用代理 ----------

    def intercept_tool_call(self, session_id: str, tool_name: str,
                            parameters: Optional[Dict[str, Any]] = None,
                            user_input: str = "") -> Tuple[bool, Dict[str, Any]]:
        """Agent 的工具调用先过守卫：能力令牌（默认deny）→ operation_guard"""
        self.stats["tool_calls_checked"] += 1
        verdict = self.guard.check_tool(
            session_id=session_id, tool_name=tool_name,
            parameters=parameters or {}, user_input=user_input,
        )
        if not verdict.allowed:
            self.stats["tool_calls_blocked"] += 1
        return verdict.allowed, verdict.to_dict()

    # ---------- ③ 响应后过滤 ----------

    def intercept_response(self, body: Any) -> Tuple[Any, Dict[str, Any]]:
        """递归改写响应体中的字符串（PII/密钥脱敏）。非 JSON 直通。"""
        summary = {"filtered": 0, "masked_samples": []}

        def walk(node: Any) -> Any:
            if isinstance(node, str):
                if len(node) < 4:
                    return node
                result = self.guard.filter_output(node)
                if result.sanitized is not None and result.sanitized != node:
                    summary["filtered"] += 1
                    if len(summary["masked_samples"]) < 5:
                        summary["masked_samples"].extend(result.evidence[:2])
                    return result.sanitized
                return node
            if isinstance(node, dict):
                return {k: walk(v) for k, v in node.items()}
            if isinstance(node, list):
                return [walk(v) for v in node]
            return node

        filtered_body = walk(body)
        if summary["filtered"]:
            self.stats["responses_filtered"] += 1
            self.stats["findings_masked"] += summary["filtered"]
        return filtered_body, summary
