# -*- coding: utf-8 -*-
"""可信时间戳（TSA）与审计锚点（Checkpoint）

解决的问题：哈希链 + 签名能证明"内容未被改"，但**无法自证某时刻链头的存在**（可被整体截断/回滚）。
做法：周期性把当前审计链头哈希提交**可信时间戳服务（TSA）**，得到带时间的锚点并留档；
日后用锚点可证明"该链头在某时刻已存在"，且当前链未被截断——满足等保证据固定与时间可信要求。

- TSA 通过 HTTP JSON 契约对接（{digest, alg} → {timestamp, serial,...}）；
  生产可替换为符合 RFC3161 的时间戳服务或单位自建 TSA（只需适配 request_timestamp）。
- 未配置 TSA 时降级为**本地可信时钟锚点**（mode=local），仍可固定链头、检测截断。

配置持久化于 policy_config（key=audit_tsa）；锚点存 policy_config（key=audit_anchors，保留最近 50 条）。
"""
import json
import time
import urllib.request
import uuid
from datetime import datetime
from typing import Dict, List, Optional

from storage import get_storage

CONFIG_KEY = "audit_tsa"
ANCHOR_KEY = "audit_anchors"
ANCHOR_KEEP = 50


# ==================================================================
# 配置
# ==================================================================
def load_tsa_config(force: bool = False) -> Dict:
    cfg = get_storage().get_setting(CONFIG_KEY, {}) or {}
    return {
        "url": str(cfg.get("url", "") or ""),
        "enabled": bool(cfg.get("enabled", False)),
    }


def save_tsa_config(url: str, enabled: bool) -> Dict:
    cfg = {"url": str(url or "").strip(), "enabled": bool(enabled)}
    get_storage().set_setting(CONFIG_KEY, cfg)
    return load_tsa_config(force=True)


# ==================================================================
# 时间戳请求
# ==================================================================
def _now_iso() -> str:
    return datetime.now().isoformat()


def _post_json(url: str, payload: Dict) -> Dict:
    req = urllib.request.Request(
        url, data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=6) as resp:  # noqa: S310 用户自配 TSA 地址
        body = resp.read().decode("utf-8", "ignore")
    try:
        return json.loads(body) if body else {}
    except (ValueError, TypeError):
        return {"raw": body}


def request_timestamp(digest_hex: str) -> Dict:
    """为摘要请求可信时间戳；TSA 未启用/失败时降级为本地时间戳。"""
    cfg = load_tsa_config(force=True)
    if cfg["enabled"] and cfg["url"]:
        try:
            resp = _post_json(cfg["url"], {"digest": digest_hex, "alg": "sha256"})
            return {
                "mode": "tsa",
                "digest": digest_hex,
                "timestamp": resp.get("timestamp") or _now_iso(),
                "serial": str(resp.get("serial", "")),
                "tsa_url": cfg["url"],
                "token": resp,
            }
        except Exception as e:
            return {
                "mode": "tsa-failed",
                "digest": digest_hex,
                "timestamp": _now_iso(),
                "error": str(e)[:200],
            }
    return {"mode": "local", "digest": digest_hex, "timestamp": _now_iso()}


# ==================================================================
# 审计锚点
# ==================================================================
def chain_head() -> Dict:
    """当前审计链头信息（用于锚定）。"""
    st = get_storage()
    last = st.get_last_audit_log()
    head_hash = ""
    if last:
        extra = last.get("extra_data") or {}
        if isinstance(extra, str):
            try:
                extra = json.loads(extra)
            except (ValueError, TypeError):
                extra = {}
        head_hash = extra.get("log_hash", "")
    return {
        "head_hash": head_hash,
        "count": st.count_audit_logs(),
        "last_log_id": (last or {}).get("log_id", ""),
        "last_timestamp": (last or {}).get("timestamp", ""),
    }


def create_anchor() -> Dict:
    """创建锚点：取当前链头 → 请求时间戳 → 追加归档。"""
    st = get_storage()
    head = chain_head()
    ts = request_timestamp(head["head_hash"] or "empty")
    anchor = {
        "anchor_id": uuid.uuid4().hex[:16],
        "created_at": _now_iso(),
        **head,
        "timestamp": ts,
    }
    anchors = st.get_setting(ANCHOR_KEY, []) or []
    if not isinstance(anchors, list):
        anchors = []
    anchors.append(anchor)
    st.set_setting(ANCHOR_KEY, anchors[-ANCHOR_KEEP:])
    return anchor


def list_anchors() -> List[Dict]:
    anchors = get_storage().get_setting(ANCHOR_KEY, []) or []
    return anchors if isinstance(anchors, list) else []


def latest_anchor() -> Optional[Dict]:
    anchors = list_anchors()
    return anchors[-1] if anchors else None


def verify_anchor() -> Dict:
    """校验当前链相对最近锚点是否一致（未截断/回滚）。"""
    anchor = latest_anchor()
    if not anchor:
        return {"ok": False, "message": "尚无锚点，请先创建锚点"}
    head = chain_head()
    anchored_count = int(anchor.get("count", 0) or 0)
    if head["count"] < anchored_count:
        return {"ok": False, "message": "审计条数少于锚点，疑似被截断/回滚", "anchor": anchor, "current_head": head}
    if head["count"] == anchored_count:
        same = head["head_hash"] == anchor.get("head_hash")
        return {
            "ok": bool(same),
            "message": "链头与锚点一致" if same else "链头哈希与锚点不一致，疑似被篡改",
            "anchor": anchor, "current_head": head,
        }
    return {
        "ok": True,
        "message": f"锚点后新增 {head['count'] - anchored_count} 条记录（锚点仍有效）",
        "anchor": anchor, "current_head": head,
    }
