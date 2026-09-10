# -*- coding: utf-8 -*-
"""审计外发（SIEM 对接）

把审计事件以 **JSON 或 CEF** 格式实时推送到外部安全采集端（SIEM/态势平台/SOC），
供集中化安全运营与合规留痕。要点：
- 非阻塞：投递在后台线程执行，失败静默，绝不影响主业务流程；
- 可配置：地址/开关/格式持久化于 policy_config（key=audit_forward），后台可热改；
- 轻缓存：配置短时缓存（默认 5s），避免每条审计都读库。
"""
import json
import threading
import time
import urllib.request
from collections import deque
from typing import Dict, Optional

from storage import get_storage

CONFIG_KEY = "audit_forward"
_CACHE_TTL = 5.0
_cache: Dict[str, object] = {"ts": 0.0, "cfg": None}

# 投递历史（内存，最近 50 条），供治理面板可视化
_history: "deque[Dict]" = deque(maxlen=50)
_hist_lock = threading.Lock()

_SEV_MAP = {"none": 0, "low": 2, "medium": 5, "high": 8, "critical": 10}


def _record_history(log: Dict, ok: bool, error: str = "") -> None:
    try:
        entry = {
            "time": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "ok": bool(ok),
            "action_type": str(log.get("action_type", "")),
            "log_id": str(log.get("log_id", "")),
            "risk_level": str(log.get("risk_level", "")),
            "error": error[:200],
        }
        with _hist_lock:
            _history.append(entry)
    except Exception:
        pass


def forward_history(limit: int = 30) -> list:
    with _hist_lock:
        items = list(_history)
    return items[-int(limit):][::-1]  # 最近优先


def load_config(force: bool = False) -> Dict:
    now = time.time()
    if not force and _cache["cfg"] is not None and now - float(_cache["ts"]) < _CACHE_TTL:
        return dict(_cache["cfg"])  # type: ignore[arg-type]
    cfg = get_storage().get_setting(CONFIG_KEY, {}) or {}
    out = {
        "url": str(cfg.get("url", "") or ""),
        "enabled": bool(cfg.get("enabled", False)),
        "format": str(cfg.get("format", "json") or "json").lower(),
    }
    _cache["cfg"] = out
    _cache["ts"] = now
    return dict(out)


def save_config(url: str, enabled: bool, fmt: str = "json") -> None:
    get_storage().set_setting(CONFIG_KEY, {
        "url": str(url or "").strip(),
        "enabled": bool(enabled),
        "format": (fmt or "json").lower(),
    })
    _cache["cfg"] = None  # 立即失效缓存


def _to_cef(log: Dict) -> str:
    """按 CEF 规范格式化（Common Event Format），便于 SIEM 解析。"""
    sev = _SEV_MAP.get(str(log.get("risk_level", "none")), 0)
    sig = str(log.get("action_type", "audit"))
    ext = " ".join(
        f"{k}={log.get(k, '')}"
        for k in ("log_id", "user_id", "user_role", "agent_id",
                  "action_type", "risk_level", "is_blocked")
    )
    return f"CEF:0|SafeAgent|GovComSafeAgent|1.0|{sig}|{sig}|{sev}|{ext}"


def _post(url: str, payload: str, content_type: str) -> bool:
    req = urllib.request.Request(
        url, data=payload.encode("utf-8"),
        headers={"Content-Type": content_type}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310 用户自配内网地址
        return 200 <= resp.status < 300


def forward_event(log: Dict) -> bool:
    """同步投递单条审计事件；未启用/未配置返回 False。"""
    cfg = load_config()
    if not cfg["enabled"] or not cfg["url"]:
        return False
    if cfg["format"] == "cef":
        payload, ctype = _to_cef(log), "text/plain"
    else:
        payload, ctype = json.dumps(log, ensure_ascii=False, default=str), "application/json"
    try:
        ok = _post(cfg["url"], payload, ctype)
        _record_history(log, ok)
        return ok
    except Exception as e:
        _record_history(log, False, str(e))
        raise


def _safe_forward(log: Dict) -> None:
    try:
        forward_event(log)
    except Exception:
        # 外发失败不影响主流程（静默，避免审计写库被外部依赖拖垮）
        pass


def forward_event_async(log: Dict) -> None:
    """异步投递（后台线程、daemon），供审计写入后调用。"""
    try:
        if not load_config().get("enabled"):
            return
        threading.Thread(target=_safe_forward, args=(log,), daemon=True).start()
    except Exception:
        pass


def test_forward(sample: Optional[Dict] = None) -> Dict:
    """连通性测试：投递一条样例事件，返回结果（供后台配置页即时反馈）。"""
    cfg = load_config(force=True)
    if not cfg["url"]:
        return {"ok": False, "message": "未配置外发地址"}
    if not cfg["enabled"]:
        return {"ok": False, "message": "外发未启用（开关为关）"}
    evt = sample or {
        "log_id": "forward-test", "action_type": "audit_forward_test",
        "user_id": "system", "user_role": "system", "agent_id": "audit",
        "risk_level": "none", "is_blocked": False,
    }
    try:
        ok = forward_event(evt)
        return {"ok": bool(ok), "message": "已送达采集端" if ok else "目标返回非 2xx"}
    except Exception as e:
        return {"ok": False, "message": f"投递失败：{e}"}
