# -*- coding: utf-8 -*-
"""通知外发渠道：Webhook 配置与后台投递

配置持久化于 policy_config 表（key=notify_webhook），支持：
- Webhook URL 与开关
- 事件后台异步 POST（不阻塞主流程）
- 连通性测试（同步，供配置页即时反馈）
"""
import json
import threading
import urllib.request
from datetime import datetime
from storage import get_storage

WEBHOOK_KEY = "notify_webhook"


def load_webhook() -> dict:
    cfg = get_storage().get_setting(WEBHOOK_KEY, {}) or {}
    return {
        "url": cfg.get("url", ""),
        "enabled": bool(cfg.get("enabled", False)),
    }


def save_webhook(url: str, enabled: bool):
    get_storage().set_setting(WEBHOOK_KEY, {"url": url, "enabled": enabled})


def _post(url: str, payload: dict):
    req = urllib.request.Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=6) as resp:  # noqa: S310 内网/用户自配地址
        return resp.status


def _post_safe(url: str, payload: dict):
    try:
        _post(url, payload)
    except Exception:
        # Webhook 投递失败不影响主流程（静默）
        pass


def fire_webhook_background(event: dict):
    """后台投递事件（非阻塞）；未启用或未配置 URL 时直接跳过"""
    try:
        cfg = load_webhook()
        if cfg["enabled"] and cfg["url"]:
            payload = {
                "type": event.get("type", "event"),
                "title": event.get("title", ""),
                "message": event.get("message", ""),
                "level": event.get("level", "info"),
                "timestamp": datetime.now().isoformat(),
                "data": event.get("data", {}),
            }
            threading.Thread(
                target=_post_safe, args=(cfg["url"], payload), daemon=True
            ).start()
    except Exception:
        pass


def test_webhook(url: str):
    """连通性测试（同步）。返回 (ok, detail)"""
    try:
        status = _post(url, {
            "type": "test",
            "title": "Webhook 连通性测试",
            "message": "SafeAgent 通知渠道测试消息",
            "level": "info",
            "timestamp": datetime.now().isoformat(),
        })
        return True, f"发送成功（HTTP {status}）"
    except Exception as e:
        return False, str(e)[:180]
