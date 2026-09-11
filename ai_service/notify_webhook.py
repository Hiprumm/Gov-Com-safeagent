# -*- coding: utf-8 -*-
"""通知外发渠道：Webhook / 飞书机器人 / SMTP 邮件

配置持久化于 policy_config 表，支持三类通道（可同时启用）：
- 通用 Webhook（key=notify_webhook，向后兼容）
- 飞书/企微机器人 Webhook（key=notify_lark，应用内告警即时触达）
- SMTP 邮件（key=notify_smtp，值守/值班邮件兜底）

统一入口 `fire_all_background(event)`：后台异步投递到所有已启用通道，
任一条失败不影响主流程与其余通道。测试函数为同步，供配置页即时反馈。
"""
import json
import smtplib
import threading
import urllib.request
from email.header import Header
from email.mime.text import MIMEText
from datetime import datetime

from storage import get_storage

WEBHOOK_KEY = "notify_webhook"
LARK_KEY = "notify_lark"
SMTP_KEY = "notify_smtp"


# ---------------------------------------------------------------------------
# 通道配置读写
# ---------------------------------------------------------------------------
def load_channels() -> dict:
    cfg = get_storage()
    webhook = cfg.get_setting(WEBHOOK_KEY, {}) or {}
    lark = cfg.get_setting(LARK_KEY, {}) or {}
    smtp = cfg.get_setting(SMTP_KEY, {}) or {}
    return {
        "webhook": {
            "url": webhook.get("url", ""),
            "enabled": bool(webhook.get("enabled", False)),
        },
        "lark": {
            "url": lark.get("url", ""),
            "enabled": bool(lark.get("enabled", False)),
        },
        "smtp": {
            "smtp_host": smtp.get("smtp_host", ""),
            "smtp_port": int(smtp.get("smtp_port", 465) or 465),
            "smtp_user": smtp.get("smtp_user", ""),
            "smtp_password": smtp.get("smtp_password", ""),
            "from_addr": smtp.get("from_addr", smtp.get("smtp_user", "")),
            "to_addrs": list(smtp.get("to_addrs", []) or []),
            "use_ssl": bool(smtp.get("use_ssl", True)),
            "enabled": bool(smtp.get("enabled", False)),
        },
    }


def save_channel(name: str, payload: dict):
    """保存某一通道配置（name: webhook | lark | smtp）。"""
    cfg = get_storage()
    key = {"webhook": WEBHOOK_KEY, "lark": LARK_KEY, "smtp": SMTP_KEY}[name]
    existing = cfg.get_setting(key, {}) or {}
    merged = {**existing, **payload}
    cfg.set_setting(key, merged)


def load_webhook() -> dict:
    return load_channels()["webhook"]


def save_webhook(url: str, enabled: bool):
    save_channel("webhook", {"url": url, "enabled": enabled})


# ---------------------------------------------------------------------------
# 单通道发送
# ---------------------------------------------------------------------------
def _http_post(url: str, payload: dict, timeout: int = 6) -> int:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 内网/用户自配地址
        return resp.status


def _send_webhook(url: str, event: dict) -> int:
    payload = {
        "type": event.get("type", "event"),
        "title": event.get("title", ""),
        "message": event.get("message", ""),
        "level": event.get("level", "info"),
        "timestamp": datetime.now().isoformat(),
        "data": event.get("data", {}),
    }
    return _http_post(url, payload)


def _send_lark(url: str, event: dict) -> int:
    """飞书/企微机器人 Webhook：推送文本卡片，观测更佳。"""
    level_tag = {"critical": "🔴", "high": "🟠", "medium": "🟡", "info": "🔵"}.get(
        event.get("level", "info"), "🔵"
    )
    data = event.get("data") or {}
    text = f"{level_tag} {event.get('title', '')}\n{event.get('message', '')}"
    if data:
        text += f"\n```json\n{json.dumps(data, ensure_ascii=False)[:400]}\n```"
    payload = {"msg_type": "text", "content": {"text": text}}
    return _http_post(url, payload)


def _send_smtp(cfg: dict, event: dict) -> None:
    to_addrs = [a for a in (cfg.get("to_addrs") or []) if a.strip()]
    if not to_addrs:
        raise ValueError("SMTP 未配置收件人 to_addrs")
    server, port = cfg["smtp_host"], cfg["smtp_port"]
    user, pwd = cfg["smtp_user"], cfg["smtp_password"]
    from_addr = cfg.get("from_addr") or user
    msg = MIMEText(
        f"{event.get('title', '')}\n\n{event.get('message', '')}\n\n"
        f"等级：{event.get('level', 'info')}\n时间：{datetime.now().isoformat()}\n"
        f"附加：{json.dumps(event.get('data') or {}, ensure_ascii=False)}",
        "plain", "utf-8",
    )
    msg["Subject"] = Header(f"[SafeAgent] {event.get('title', '通知')}", "utf-8")
    msg["From"] = from_addr
    msg["To"] = ",".join(to_addrs)
    if cfg.get("use_ssl", True):
        with smtplib.SMTP_SSL(server, port, timeout=10) as s:
            if user:
                s.login(user, pwd)
            s.sendmail(from_addr, to_addrs, msg.as_string())
    else:
        with smtplib.SMTP(server, port, timeout=10) as s:
            s.starttls()
            if user:
                s.login(user, pwd)
            s.sendmail(from_addr, to_addrs, msg.as_string())


# ---------------------------------------------------------------------------
# 统一出口
# ---------------------------------------------------------------------------
def _dispatch_one(channel_fn, *args):
    try:
        channel_fn(*args)
    except Exception:
        # 单通道失败不影响主流程与其余通道（静默）
        pass


def fire_all_background(event: dict):
    """后台异步投递到所有已启用通道（webhook/lark/smtp）。"""
    try:
        channels = load_channels()
        ev = dict(event or {})
        jobs = []
        if channels["webhook"]["enabled"] and channels["webhook"]["url"]:
            jobs.append(lambda: _send_webhook(channels["webhook"]["url"], ev))
        if channels["lark"]["enabled"] and channels["lark"]["url"]:
            jobs.append(lambda: _send_lark(channels["lark"]["url"], ev))
        if channels["smtp"]["enabled"]:
            jobs.append(lambda: _send_smtp(channels["smtp"], ev))
        for j in jobs:
            threading.Thread(target=_dispatch_one, args=(j,), daemon=True).start()
    except Exception:
        pass


def fire_webhook_background(event: dict):
    """向后兼容：仅投递通用 Webhook。新代码请使用 fire_all_background。"""
    try:
        cfg = load_webhook()
        if cfg["enabled"] and cfg["url"]:
            threading.Thread(
                target=_dispatch_one, args=(_send_webhook, cfg["url"], event), daemon=True
            ).start()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# 连通性测试（同步）
# ---------------------------------------------------------------------------
def test_webhook(url: str):
    try:
        status = _http_post(url, {
            "type": "test",
            "title": "Webhook 连通性测试",
            "message": "SafeAgent 通知渠道测试消息",
            "level": "info",
            "timestamp": datetime.now().isoformat(),
        })
        return True, f"发送成功（HTTP {status}）"
    except Exception as e:
        return False, str(e)[:180]


def test_lark(url: str):
    try:
        status = _send_lark(url, {
            "type": "test", "title": "飞书连通性测试",
            "message": "SafeAgent 应急通知通道测试", "level": "info",
        })
        return True, f"发送成功（HTTP {status}）"
    except Exception as e:
        return False, str(e)[:180]


def test_smtp(cfg: dict, title: str = "SMTP 通知通道测试", message: str = "SafeAgent 邮件通道测试成功"):
    try:
        _send_smtp(cfg, {"type": "test", "title": title, "message": message, "level": "info"})
        return True, "邮件发送成功"
    except Exception as e:
        return False, str(e)[:180]