# -*- coding: utf-8 -*-
"""联网搜索工具（政企合规 · 国内搜索后端）
==========================================

真实政企场景下，由 LLM 直接抓取公网页面既不可控也不合规。本模块通过
「国内合规 LLM 联网搜索 API（博查 Bocha，ICP 备案、面向 LLM 的合规搜索）」
实现联网搜索能力，与市面上豆包/Kimi 等 AI 的"联网搜索"体验对齐。

安全红线（最安全方式）：
1. 结果 URL 全量过 BrowserAccessController 黑名单 / 危险协议检查；
2. 内网/保留/回环 IP 直连、非 http(s) 协议的结果一律剔除（防 SSRF 诱导）；
3. 工具执行的审计由上层工具执行链路统一留痕（tool_execution），本模块仅返回清洗后的摘要文本。

配置持久化：storage 落库（与 llm_runtime 同源），热生效；API Key 安全隐藏，仅回显存在性。
"""
import ipaddress
import threading
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse

try:
    import requests
except ImportError:  # 环境缺依赖时降级为明确报错，不静默
    requests = None

from storage import get_storage

STORE_KEY = "web_search"
BOCHA_ENDPOINT = "https://api.bochaai.com/v1/web-search"
PROVIDER_LABELS = {"bocha": "博查 Bocha（国内合规）"}
DEFAULT_MAX_RESULTS = 5
TIMEOUT_SECONDS = 15


class WebSearchProvider:
    """联网搜索执行器（配置按需从 storage 重载，保证热生效）"""

    def __init__(self):
        self._lock = threading.Lock()
        self._cfg: Dict[str, Any] = {}
        self._load()

    # ------------------------------------------------------------------
    # 配置持久化（写后读校验，语义与 llm_runtime 一致）
    # ------------------------------------------------------------------
    def _load(self):
        stored = get_storage().get_setting(STORE_KEY) or {}
        self._cfg = {
            "enabled": bool(stored.get("enabled", False)),
            "provider": stored.get("provider", "bocha"),
            "api_key": str(stored.get("api_key", "") or ""),
            "max_results": int(stored.get("max_results", DEFAULT_MAX_RESULTS) or DEFAULT_MAX_RESULTS),
        }

    def load_config(self, force: bool = False) -> dict:
        if force:
            self._load()
        return dict(self._cfg)

    def save_config(self, cfg: dict) -> dict:
        """保存联网搜索配置（仅管理员经路由层调用）。

        密钥语义：api_key=None → 不修改；'' → 清除；非空 → 覆盖。
        写后读校验失败抛 ValueError。
        """
        old = self._cfg
        api_key = cfg.get("api_key")
        new_cfg = {
            "enabled": bool(cfg.get("enabled", old.get("enabled", False))),
            "provider": cfg.get("provider") or old.get("provider", "bocha"),
            "max_results": max(1, min(10, int(cfg.get("max_results", old.get("max_results", DEFAULT_MAX_RESULTS)) or DEFAULT_MAX_RESULTS))),
        }
        if api_key is None:
            new_cfg["api_key"] = old.get("api_key", "")
        else:
            new_cfg["api_key"] = str(api_key)
        payload = {
            "enabled": new_cfg["enabled"],
            "provider": new_cfg["provider"],
            "api_key": new_cfg["api_key"],
            "max_results": new_cfg["max_results"],
        }
        get_storage().set_setting(STORE_KEY, payload)
        persisted = get_storage().get_setting(STORE_KEY) or {}
        if (persisted.get("enabled") != payload["enabled"]
                or persisted.get("provider") != payload["provider"]
                or (persisted.get("api_key") or "") != payload["api_key"]):
            raise ValueError("联网搜索配置写入校验失败（写后读不一致）")
        with self._lock:
            self._cfg = new_cfg
        return dict(self._cfg)

    def runtime_status(self) -> dict:
        """前端展示用（Key 安全隐藏，仅回显存在性）"""
        return {
            "enabled": bool(self._cfg.get("enabled")),
            "provider": self._cfg.get("provider", "bocha"),
            "has_key": bool(self._cfg.get("api_key")),
            "max_results": int(self._cfg.get("max_results", DEFAULT_MAX_RESULTS)),
        }

    def test_connect(self, api_key: Optional[str] = None, provider: Optional[str] = None,
                     query: str = "最新国家政策") -> dict:
        """连通性测试：用给定 Key（或当前已存 Key）执行一次搜索，不落库。"""
        saved = dict(self._cfg)
        self._cfg["enabled"] = True
        if api_key is not None:
            self._cfg["api_key"] = str(api_key)
        if provider:
            self._cfg["provider"] = str(provider)
        try:
            return self.search(query)
        finally:
            self._cfg = saved

    # ------------------------------------------------------------------
    # 搜索执行（真执行）
    # ------------------------------------------------------------------
    def search(self, query: str, max_results: Optional[int] = None) -> dict:
        """执行联网搜索。

        返回 {success, error?, query?, results:[{title,url,snippet}], blocked:[url]}
        未启用 / 无 Key / 请求失败时返回明确降级信息（success=False + error）。
        """
        if not self._cfg.get("enabled"):
            return {"success": False, "error": "联网搜索未启用（可在 系统与运维-模型接入-联网搜索 中开启）", "results": []}
        api_key = self._cfg.get("api_key", "")
        if not api_key:
            return {"success": False, "error": "联网搜索未配置 API Key", "results": []}
        if requests is None:
            return {"success": False, "error": "缺少 requests 依赖，无法执行联网搜索", "results": []}
        try:
            count = max(1, min(max_results or int(self._cfg.get("max_results", DEFAULT_MAX_RESULTS)), 10))
            resp = requests.post(
                BOCHA_ENDPOINT,
                headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
                json={"query": str(query or "")[:300], "freshness": "noLimit", "summary": True, "count": count},
                timeout=TIMEOUT_SECONDS,
            )
            if resp.status_code != 200:
                return {"success": False, "error": f"搜索服务返回 {resp.status_code}，请检查 API Key 是否有效", "results": []}
            data = resp.json()
            pages = (((data.get("data") or {}).get("webPages") or {}).get("value")) or []
            raw = [{
                "title": str(p.get("name", "")).strip(),
                "url": str(p.get("url", "")).strip(),
                "snippet": str(p.get("snippet") or p.get("summary") or "").strip()[:200],
            } for p in pages if p.get("url")]
            results, blocked = self._filter_results(raw)
            return {"success": True, "query": query, "results": results, "blocked": blocked}
        except requests.exceptions.Timeout:
            return {"success": False, "error": "搜索服务超时（>15s）", "results": []}
        except Exception as e:  # noqa: BLE001 —— 搜索失败不允许拖垮问答主流程
            return {"success": False, "error": f"联网搜索失败：{str(e)[:120]}", "results": []}

    def _filter_results(self, raw: List[dict]) -> (List[dict], List[str]):
        """结果 URL 安全过滤（最安全方式）：
        - 过 BrowserAccessController（黑名单模式/危险协议/自定义黑名单）
        - 内网/保留/回环 IP 直连、非 http(s) 协议一律剔除（防 SSRF 诱导）
        - 可疑类别（ip 直连、非标准端口）一并剔除
        """
        from security.browser_access_control import BrowserAccessController
        controller = BrowserAccessController()
        results: List[dict] = []
        blocked: List[str] = []
        for item in raw:
            url = item["url"]
            parsed = urlparse(url)
            scheme = (parsed.scheme or "").lower()
            host = (parsed.hostname or "").lower()
            reason = None
            if scheme not in ("http", "https"):
                reason = f"非 http(s) 协议 [{scheme}://]"
            elif not host:
                reason = "无有效主机名"
            else:
                try:
                    ip = ipaddress.ip_address(host)
                    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                        reason = f"内网/保留 IP 直连 [{host}]"
                    else:
                        reason = f"IP 直连 [{host}]（拒绝公网 IP 直链）"
                except ValueError:
                    ip = None
            if reason is None:
                check = controller.check_url(url)
                if not check.is_allowed or check.category in ("blacklist", "suspicious"):
                    reason = f"访问管控拦截：{check.reason}"
            if reason:
                blocked.append(url)
                continue
            results.append(item)
        return results, blocked


def _fmt_results_for_agent(out: dict) -> str:
    """把搜索输出格式化为喂给 LLM 的文本（带来源与安全过滤说明）"""
    if not out.get("success"):
        return f"[web_search] {out.get('error', '搜索失败')}"
    results = out.get("results", [])
    if not results:
        return "[web_search] 未搜索到相关结果"
    lines = ["联网搜索结果（来源：博查）:"]
    for i, r in enumerate(results, 1):
        lines.append(f"{i}. {r['title']}")
        lines.append(f"   链接: {r['url']}")
        if r["snippet"]:
            lines.append(f"   摘要: {r['snippet']}")
    blocked = out.get("blocked") or []
    if blocked:
        lines.append(f"（已安全过滤 {len(blocked)} 条不合规/高风险结果链接）")
    lines.append("提示：请基于以上摘要回答，如需引用可给出对应链接。")
    return "\n".join(lines)
