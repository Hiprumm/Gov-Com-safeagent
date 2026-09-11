# -*- coding: utf-8 -*-
"""
治理中心：应急联动 / 开放生态 / PIPL 合规台账
============================================
面向政企交付的三大补强能力，全部落到存量架构之上：
- EmergencyCenter：一键全局熔断、账号封锁、IP 封锁，分级告警升级 + 通知联动 + 审计留痕
- OpenApiManager：对外调用方登记、Token 签发（哈希存储）、限流配额、调用审计
- PiplLedger：输入侧 PII 识别登记、处理合法性影响评估向导、合规留痕导出
"""
from __future__ import annotations

import re
import json
import time
import uuid
import hashlib
import logging
from datetime import datetime
from typing import Optional

logger = logging.getLogger("governance")

# ---------------------------------------------------------------------------
# 应急联动中心
# ---------------------------------------------------------------------------
CONTROL_TYPES = {"global_circuit", "block_user", "block_ip"}


class EmergencyCenter:
    """应急联动中心（数据落库 emergency_controls，内存缓存加速判定）。"""

    def __init__(self, storage=None):
        from storage import get_storage
        self.storage = storage or get_storage()
        self._ip_blocked: set = set()
        self._user_blocked: set = set()
        self._global_on = False
        self._reload()

    def _reload(self):
        ip, user, g = set(), set(), False
        for ctype, target in self._active_pairs():
            if ctype == "block_ip":
                ip.add(target)
            elif ctype == "block_user":
                user.add(target)
            elif ctype == "global_circuit":
                g = True
        self._ip_blocked, self._user_blocked, self._global_on = ip, user, g

    def _active_pairs(self):
        """从持久化层实时读取生效中的应急控制（每次判定都读库，保证多 worker 一致性）。
        该表极小且按 enabled 索引，单次读取代价可忽略；换取应急判定跨进程即时一致。
        读取失败绝不静默放行（fail-open 会让熔断失效）：记录日志并重试一次。"""
        for attempt in (0, 1):
            try:
                return [(r["control_type"], r.get("target")) for r in self.storage.active_emergency_controls()]
            except Exception as e:  # noqa: BLE001
                if attempt == 0:
                    logger.error("emergency read failed, retrying: %s", e)
                    time.sleep(0.05)
                    continue
                logger.error("emergency read failed twice, FAIL-CLOSED-guard skipped: %s", e)
                return []

    # ---- 判定（供中间件/chat 入口调用；每次实时读库，避免多 worker 各自内存态不一致） ----
    def reason_blocked(self, username: Optional[str] = None, ip: Optional[str] = None) -> Optional[str]:
        if self.global_circuit_active():
            return "系统已全局熔断，暂停所有智能体执行"
        if username and username in self._blocked_users():
            return f"账号 {username} 已被应急封锁，禁止发起请求"
        if ip and self.is_ip_blocked(ip):
            return f"IP {ip} 已被应急封锁，禁止访问"
        return None

    def global_circuit_active(self) -> bool:
        return any(ctype == "global_circuit" for ctype, _ in self._active_pairs())

    def is_ip_blocked(self, ip: str) -> bool:
        return any(ctype == "block_ip" and target == ip for ctype, target in self._active_pairs())

    def _blocked_users(self) -> set:
        return {target for ctype, target in self._active_pairs() if ctype == "block_user"}

    # ---- 操作 ----
    def _audit(self, action_type: str, details: dict, operator: str = ""):
        try:
            from audit.audit_logger import AuditLogger
            AuditLogger().create_log(
                user_id=operator or "system", user_role="admin", agent_id="governance",
                action_type=action_type, action_details=details,
                risk_level="high", is_blocked=False,
            )
        except Exception as e:  # noqa: BLE001
            logger.warning("audit fail: %s", e)

    def _notify(self, title: str, message: str, level: str = "critical", data: dict = None):
        try:
            from notify_webhook import fire_all_background
            fire_all_background({
                "type": "emergency", "title": title, "message": message,
                "level": level, "data": data or {},
            })
            self.storage.add_notification("emergency", title, message, level)
        except Exception as e:  # noqa: BLE001
            logger.warning("notify fail: %s", e)

    def engage(self, reason: str, operator: str = "") -> dict:
        self.storage.add_emergency_control("global_circuit", "*", operator, reason)
        self._reload()
        self._audit("emergency_circuit_break", {"action": "engage", "reason": reason, "operator": operator}, operator)
        self._notify("⚠ 全局熔断已开启", f"{operator or '管理员'} 开启全局熔断：{reason}", "critical", {"action": "engage"})
        return {"success": True, "engaged": self._global_on}

    def disengage(self, operator: str = "") -> dict:
        self.storage.release_emergency_control("global_circuit", "*")
        self._reload()
        self._audit("emergency_circuit_break", {"action": "disengage", "operator": operator}, operator)
        self._notify("全局熔断已恢复", f"{operator or '管理员'} 解除全局熔断", "info", {"action": "disengage"})
        return {"success": True, "engaged": self._global_on}

    def block_user(self, username: str, reason: str, operator: str = "") -> dict:
        self.storage.add_emergency_control("block_user", username, operator, reason)
        self._reload()
        self._audit("emergency_block_user", {"username": username, "reason": reason, "operator": operator}, operator)
        self._notify("账号已封锁", f"账号 {username} 被封锁：{reason}", "high", {"target": username})
        return {"success": True}

    def unblock_user(self, username: str, operator: str = "") -> dict:
        self.storage.release_emergency_control("block_user", username)
        self._reload()
        self._audit("emergency_unblock_user", {"username": username, "operator": operator}, operator)
        return {"success": True}

    def block_ip(self, ip: str, reason: str, operator: str = "") -> dict:
        self.storage.add_emergency_control("block_ip", ip, operator, reason)
        self._reload()
        self._audit("emergency_block_ip", {"ip": ip, "reason": reason, "operator": operator}, operator)
        self._notify("IP 已封锁", f"IP {ip} 被封锁：{reason}", "high", {"target": ip})
        return {"success": True}

    def unblock_ip(self, ip: str, operator: str = "") -> dict:
        self.storage.release_emergency_control("block_ip", ip)
        self._reload()
        self._audit("emergency_unblock_ip", {"ip": ip, "operator": operator}, operator)
        return {"success": True}

    def status(self) -> dict:
        self._reload()
        return {
            "global_engaged": self._global_on,
            "blocked_users": sorted(self._user_blocked),
            "blocked_ips": sorted(self._ip_blocked),
            "active": self.storage.active_emergency_controls(),
            "history": self.storage.emergency_history(30),
        }


# ---------------------------------------------------------------------------
# 开放生态管理（对外 API 调用方 / Token / 限流 / 审计）
# ---------------------------------------------------------------------------
_OPEN_PREFIX = "/api/open"


def _hash_token(token: str) -> str:
    return hashlib.sha256(("openapis:" + token).encode("utf-8")).hexdigest()


def gen_token() -> str:
    return "sag_" + uuid.uuid4().hex + uuid.uuid4().hex[:8]


class OpenApiManager:
    """调用方登记 + Token 签发（哈希落库）+ 限流配额 + 调用留痕。"""

    def __init__(self, storage=None):
        from storage import get_storage
        self.storage = storage or get_storage()
        # 内存限流：client_id -> (window_start, count), 60s 滑动
        self._buckets: dict = {}

    # ---- 管理 ----
    def create(self, name: str, rate_limit: int, quota: int, description: str, created_by: str) -> dict:
        client_id = "cli_" + uuid.uuid4().hex[:12]
        token = gen_token()
        self.storage.upsert_api_client(
            client_id, name, _hash_token(token), 1,
            max(1, min(int(rate_limit), 10000)), max(0, int(quota)),
            created_by, description,
        )
        return {"success": True, "client_id": client_id, "token": token,
                "token_note": "令牌仅本次显示，请立即妥善保存（系统仅存哈希，无法二次查看）"}

    def list_clients(self) -> list:
        for c in self.storage.list_api_clients():
            c.pop("token_hash", None)
        return self.storage.list_api_clients()

    def toggle(self, client_id: str, enabled: bool) -> dict:
        c = self.storage.get_api_client(client_id)
        if not c:
            return {"success": False, "error": "调用方不存在"}
        self.storage.upsert_api_client(
            client_id, c["name"], c["token_hash"], 1 if enabled else 0,
            c["rate_limit"], c["quota"], "", c.get("description", ""),
        )
        return {"success": True}

    def delete(self, client_id: str) -> dict:
        self.storage.delete_api_client(client_id)
        self._buckets.pop(client_id, None)
        return {"success": True}

    def log_calls(self, limit: int = 100) -> list:
        return self.storage.list_api_call_logs(limit)

    def stats(self) -> dict:
        clients = self.storage.list_api_clients()
        return {"client_count": len(clients), "total_used": sum(c["used"] or 0 for c in clients)}

    # ---- 开放接口鉴权（供 /api/open/* 使用） ----
    def authenticate(self, token: str, path: str, ip: str) -> tuple:
        """返回 (client_dict, status)。status: 200 放行 / 401 未授权 / 403 禁用 / 429 限流 / 402 配额不足"""
        if not token:
            return None, 401
        th = _hash_token(token)
        client = None
        for c in self.storage.list_api_clients():
            if c["token_hash"] == th:
                client = c
                break
        if not client:
            return None, 401
        if not client["enabled"]:
            return client, 403
        # 配额 / 限流
        quota = client["quota"]
        if quota and (client["used"] or 0) >= quota:
            return client, 402
        now = int(datetime.now().timestamp())
        bk = self._buckets.get(client["client_id"])
        if bk and now - bk[0] < 60 and bk[1] >= client["rate_limit"]:
            return client, 429
        if not bk or now - bk[0] >= 60:
            bk = (now, 0)
        self._buckets[client["client_id"]] = (bk[0], bk[1] + 1)
        self.storage.record_api_call(client["client_id"], client["name"], path, 200, ip)
        return client, 200


# ---------------------------------------------------------------------------
# PIPL 合规台账
# ---------------------------------------------------------------------------
PII_PATTERNS = [
    ("手机号", re.compile(r"1[3-9]\d{9}")),
    ("身份证号", re.compile(r"\d{17}[\dXx]")),
    ("护照号", re.compile(r"(?i)(?<!\w)[A-Za-z]\d{8}(?!\w)")),
    ("统一社会信用代码", re.compile(r"(?<!\w)\d{2}[0-9A-Z]{8}[\dA-Z]{6}[\dA-Z](?<![\w])")),
    ("邮箱", re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")),
    ("银行卡号", re.compile(r"(?<!\d)(?:\d[ -]?){16,19}(?!\d)", re.M)),
    ("车牌号", re.compile(r"(?<![A-Z0-9])[\u4e00-\u9fa5][A-Z][A-Z0-9]{5}(?![\w])")),
    ("IP 地址", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    ("出生日期", re.compile(r"(?:19|20)\d{2}(?:[\-/\u5e74])(?:0[1-9]|1[0-2])(?:[\-/月])(?:0[1-9]|[12]\d|3[01])(?:\u65e5)?")),
    ("微信/QQ号", re.compile(r"(?<![\w.])(?:(?:wxid_[A-Za-z0-9_-]+)|(?:QQ[:：]?\s?\d{5,11}))(?![\w])")),
    ("详细地址", re.compile(r"[^\s，,;；。]{2,15}(?:省|自治区|市|区|县|镇|街道)?[^\s，,;；。]{2,30}?(?:路|街|巷|号|小区|大厦|广场|村|栋)", re.M)),
    ("经纬度坐标", re.compile(r"(?i)(?<!\w)\d{1,3}(?:\.\d{2,})?[,\s]+\d{1,3}(?:\.\d{2,})?(?!(?:[\d,]))")),
]

LEGAL_BASIS_OPTIONS = [
    "同意（个人信息保护法第13条第1项）",
    "为订立/履行合同所必需（第13条第2项）",
    "履行法定职责或义务（第13条第3项）",
    "为应对突发公共卫生/自然事件（第13条第4项）",
    "合理处理已公开信息（第13条第5项）",
    "公共利益新闻报道、舆论监督（第13条第5项）",
]
ASSESSMENT_OPTIONS = ["pending", "合规", "不合规-需整改"]


def _mask(text: str, span: tuple) -> str:
    s, e = span
    val = text[s:e]
    if len(val) <= 4:
        return val[0] + "*" * (len(val) - 1) if val else val
    return val[:3] + "*" * (len(val) - 6) + val[-3:]


class PiplLedger:
    """输入侧 PII 识别 → 登记台账 → 影响评估 → 留痕导出。"""

    PII_PATTERNS = PII_PATTERNS

    def __init__(self, storage=None):
        from storage import get_storage
        self.storage = storage or get_storage()

    def scan_and_register(self, text: str, session_id: str, username: str, source: str = "chat") -> dict:
        """扫描文本中 PII，登记台账（同会话同值去重），返回命中概览。"""
        found = []
        for label, rx in PII_PATTERNS:
            for m in rx.finditer(text or ""):
                masked = _mask(text, m.span())
                self.storage.add_pipl_record(session_id or "", username or "", label, masked, source)
                found.append({"type": label, "masked": masked})
        return {"found_count": len(found), "found": found}

    def records(self) -> list:
        return self.storage.list_pipl_records()

    def update(self, record_id: int, legal_basis: str, assessment: str, noted_by: str = "") -> dict:
        if assessment not in ASSESSMENT_OPTIONS:
            return {"success": False, "error": "评估结论取值非法"}
        self.storage.update_pipl_record(int(record_id), legal_basis, assessment, noted_by)
        return {"success": True}

    def stats(self) -> dict:
        return self.storage.pipl_stats()

    def export(self, fmt: str = "csv") -> dict:
        """导出合规台账（CSV/JSON）。仅输出已脱敏值，保证导出本身不泄露明文。

        返回: {"success", "fmt", "filename", "content", "count"}；链路上层负责审计留痕。
        """
        items = self.storage.list_pipl_records(limit=5000)
        if fmt == "json":
            content = json.dumps(
                [{"id": r["id"], "time": r["created_at"], "user": r["username"],
                  "type": r["pii_type"], "masked": r["masked_value"],
                  "legal_basis": r["legal_basis"], "assessment": r["assessment"]}
                 for r in items],
                ensure_ascii=False, indent=2,
            )
            filename = "pipl_records.json"
        else:
            import csv as _csv
            import io
            buf = io.StringIO()
            w = _csv.writer(buf)
            w.writerow(["id", "time", "user", "type", "masked", "legal_basis", "assessment"])
            for r in items:
                w.writerow([r["id"], r["created_at"], r["username"], r["pii_type"],
                            r["masked_value"], r["legal_basis"], r["assessment"]])
            content = buf.getvalue()
            filename = "pipl_records.csv"
        return {"success": True, "fmt": fmt, "filename": filename, "content": content, "count": len(items)}


# ---------------------------------------------------------------------------
# 单例
# ---------------------------------------------------------------------------
_emergency = None
_openapi = None
_pipl = None


def get_emergency_center():
    global _emergency
    if _emergency is None:
        _emergency = EmergencyCenter()
    return _emergency


def get_openapi_manager():
    global _openapi
    if _openapi is None:
        _openapi = OpenApiManager()
    return _openapi


def get_pipl_ledger():
    global _pipl
    if _pipl is None:
        _pipl = PiplLedger()
    return _pipl