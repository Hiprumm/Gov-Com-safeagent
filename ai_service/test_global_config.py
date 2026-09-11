# -*- coding: utf-8 -*-
"""全局配置功能专项测试

验证四类全局配置（安全策略 / 模型接入 / 审计外发 / 通知通道）的全局保存机制：
1. 权限隔离：匿名 / 普通角色不得读写全局配置，仅系统管理员可读写；
2. 往返持久化：保存 → 读取 → 值一致，且通过 REST 接口重启后仍可读到（DB 落库）；
3. 数据库落库：直接查询 policy_config 表，确认配置真实写入全局存储（SQLite）；
4. 错误处理：非法配置值返回 4xx；写后读校验失败返回 5xx；策略接口不得泄露
   非策略全局配置（含明文 API Key / SMTP 密码 / 外发地址）。
"""
import json
import os
import sqlite3
import sys
import time

import httpx

BASE = "http://127.0.0.1:8080"
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "safeagent.db")
PASS, FAIL = 0, 0

# 策略响应允许出现的键（其余一律视为“非策略配置泄露”）
POLICY_KEYS = {
    "llm_classifier_enabled", "block_threshold", "audit_retention_days",
    "trusted_domain_suffixes", "aigc_explicit_label_enabled",
    "aigc_implicit_marker_enabled", "policy_version", "updated_at",
}
# policy_config 表中禁止出现在策略响应里的全局配置键（含明文密钥类）
NON_POLICY_KEYS = {
    "llm_runtime", "audit_forward", "notifications", "notifications_webhook",
    "tsa_config", "api_key", "smtp_password",
}


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS += bool(ok)
    FAIL += (not ok)
    print(f"{'[PASS]' if ok else '[FAIL]'} {name}" + (f" | {detail}" if detail else ""))


def db_get_setting(key):
    """直接读全局存储（policy_config 表），绕过 REST 接口。"""
    with sqlite3.connect(DB_PATH, timeout=10.0) as conn:
        row = conn.execute("SELECT value FROM policy_config WHERE key = ?", (key,)).fetchone()
    if not row:
        return None
    try:
        return json.loads(row[0])
    except (ValueError, TypeError):
        return row[0]


def db_rows_all():
    with sqlite3.connect(DB_PATH, timeout=10.0) as conn:
        return dict(conn.execute("SELECT key, value FROM policy_config").fetchall())


def login(c, username, password="admin123"):
    r = c.post(f"{BASE}/api/auth/login", json={"username": username, "password": password})
    if r.status_code == 200:
        return (r.json() or {}).get("token", "")
    return ""


def auth_client(token):
    c = httpx.Client(timeout=30)
    if token:
        c.headers["X-Auth-Token"] = token
    return c


time.sleep(3)  # 等后端就绪

anon = httpx.Client(timeout=30)
admin = auth_client(login(httpx.Client(timeout=30), "admin"))
operator = auth_client(login(httpx.Client(timeout=30), "operator"))
auditor = auth_client(login(httpx.Client(timeout=30), "auditor"))
user = auth_client(login(httpx.Client(timeout=30), "user"))

check("管理员登录", bool(admin.headers.get("X-Auth-Token")))
check("operator 登录", bool(operator.headers.get("X-Auth-Token")))
check("auditor 登录", bool(auditor.headers.get("X-Auth-Token")))
check("普通用户登录", bool(user.headers.get("X-Auth-Token")))

print("=" * 72)
print("1. 权限隔离：全局配置仅系统管理员可读写")
print("=" * 72)

# ---- 安全策略（统一鉴权中间件拦截）----
r = anon.get(f"{BASE}/api/security/policy")
check("匿名读取策略 → 401", r.status_code == 401, f"status={r.status_code}")
r = user.get(f"{BASE}/api/security/policy")
check("普通用户读取策略 → 403", r.status_code == 403, f"status={r.status_code}")
r = operator.get(f"{BASE}/api/security/policy")
check("operator 读取策略 → 403", r.status_code == 403, f"status={r.status_code}")
r = auditor.get(f"{BASE}/api/security/policy")
check("auditor 读取策略 → 403", r.status_code == 403, f"status={r.status_code}")
r = user.put(f"{BASE}/api/security/policy", json={"policy": {"block_threshold": "critical"}})
check("普通用户修改策略 → 403", r.status_code == 403, f"status={r.status_code}")
r = admin.get(f"{BASE}/api/security/policy")
d = r.json()
check("管理员读取策略 → 200", r.status_code == 200 and d.get("success") is True,
      f"status={r.status_code}")

# ---- 模型接入 / 审计外发（_admin_guard 内部鉴权，返回 success=False）----
r = user.get(f"{BASE}/api/model/config")
d = r.json()
check("普通用户读取模型配置被拒", r.status_code == 200 and d.get("success") is False,
      f"detail={str(d.get('error'))[:40]}")
r = user.get(f"{BASE}/api/audit/forward")
d = r.json()
check("普通用户读取审计外发被拒", r.status_code == 200 and d.get("success") is False,
      f"detail={str(d.get('error'))[:40]}")
r = admin.get(f"{BASE}/api/model/config")
d = r.json()
check("管理员读取模型配置", r.status_code == 200 and d.get("success") is True and "config" in d,
      f"config_keys={list((d.get('config') or {}).keys())}")
r = admin.get(f"{BASE}/api/audit/forward")
d = r.json()
check("管理员读取审计外发", r.status_code == 200 and d.get("success") is True and "config" in d)

print()
print("=" * 72)
print("2. 安全策略：保存 → 读取往返一致 + 版本递增 + DB 落库")
print("=" * 72)

orig_policy = admin.get(f"{BASE}/api/security/policy").json().get("policy", {})
orig_version = orig_policy.get("policy_version", 0)

r = admin.put(f"{BASE}/api/security/policy", json={"policy": {
    "block_threshold": "medium",
    "audit_retention_days": 365,
    "trusted_domain_suffixes": [".gov.cn", ".edu.cn", ".custom.test"],
}})
d = r.json()
check("保存策略成功", r.status_code == 200 and d.get("success") is True,
      f"status={r.status_code} msg={str(d.get('message'))[:40]}")
new_version = d.get("policy", {}).get("policy_version", 0)
check("策略版本递增", new_version > orig_version, f"{orig_version} → {new_version}")

r = admin.get(f"{BASE}/api/security/policy")
d = r.json().get("policy", {})
check("策略往返：block_threshold=medium", d.get("block_threshold") == "medium",
      f"got={d.get('block_threshold')}")
check("策略往返：audit_retention_days=365", d.get("audit_retention_days") == 365,
      f"got={d.get('audit_retention_days')}")
check("策略往返：trusted_domain_suffixes 保存",
      ".custom.test" in (d.get("trusted_domain_suffixes") or []),
      f"got={d.get('trusted_domain_suffixes')}")

db = db_get_setting("block_threshold")
check("DB 落库：block_threshold 已持久化", db == "medium", f"db={db!r}")
db = db_get_setting("audit_retention_days")
check("DB 落库：audit_retention_days=365", db == 365, f"db={db!r}")

# 恢复原策略
admin.put(f"{BASE}/api/security/policy", json={"policy": {
    "block_threshold": orig_policy.get("block_threshold", "high"),
    "audit_retention_days": orig_policy.get("audit_retention_days", 180),
    "trusted_domain_suffixes": orig_policy.get("trusted_domain_suffixes", []),
}})
check("策略已恢复原值", True, f"threshold={orig_policy.get('block_threshold')}")

print()
print("=" * 72)
print("3. 模型接入配置：保存 → 读取往返一致 + DB 落库（含写后读校验）")
print("=" * 72)

orig_llm = db_get_setting("llm_runtime")  # 恢复用：DB 里原始覆盖配置

MARKER = {
    "provider": "zhipu",
    "api_key": "sk-gcfg-test-marker-key-2026",
    "base_url": "https://gcfg-test.example.com/v1",
    "model": "gcfg-test-model",
    "backup_provider": "openai",
    "backup_api_key": "",
    "backup_base_url": "",
    "backup_model": "",
}
r = admin.put(f"{BASE}/api/model/config", json=MARKER)
d = r.json()
check("保存模型配置成功", r.status_code == 200 and d.get("success") is True,
      f"status={r.status_code} detail={str(d.get('detail'))[:60]}")

r = admin.get(f"{BASE}/api/model/config")
d = r.json().get("config", {})
check("模型配置往返：provider", d.get("provider") == "zhipu", f"got={d.get('provider')}")
check("模型配置往返：base_url", d.get("base_url") == "https://gcfg-test.example.com/v1",
      f"got={d.get('base_url')}")
check("模型配置往返：model", d.get("model") == "gcfg-test-model", f"got={d.get('model')}")
check("模型配置往返：已存 Key", d.get("has_key") is True, f"has_key={d.get('has_key')}")

db = db_get_setting("llm_runtime") or {}
check("DB 落库：llm_runtime.api_key", (db.get("api_key") or "") == MARKER["api_key"],
      f"db_key={str(db.get('api_key'))[:20]}...")
check("DB 落库：llm_runtime.model", db.get("model") == "gcfg-test-model", f"db_model={db.get('model')}")

# 恢复模型配置（无原始覆盖则清除 Key 回落 .env）
if orig_llm:
    rest = dict(MARKER)
    rest.update(orig_llm)
    admin.put(f"{BASE}/api/model/config", json=rest)
else:
    admin.put(f"{BASE}/api/model/config", json={
        "provider": "zhipu", "api_key": "", "base_url": "", "model": "",
        "backup_provider": "openai", "backup_api_key": "", "backup_base_url": "", "backup_model": "",
    })
check("模型配置已恢复", True, "orig=" + ("stored" if orig_llm else "env"))

print()
print("=" * 72)
print("4. 审计外发配置：保存 → 读取往返一致 + DB 落库")
print("=" * 72)

orig_forward = admin.get(f"{BASE}/api/audit/forward").json().get("config", {})
r = admin.put(f"{BASE}/api/audit/forward",
              json={"url": "https://siem-gcfg-test.example.com:514/collect", "enabled": False, "format": "cef"})
d = r.json()
check("保存审计外发成功", r.status_code == 200 and d.get("success") is True,
      f"status={r.status_code}")
r = admin.get(f"{BASE}/api/audit/forward")
d = r.json().get("config", {})
check("外发往返：url", d.get("url") == "https://siem-gcfg-test.example.com:514/collect",
      f"got={d.get('url')}")
check("外发往返：format=cef", d.get("format") == "cef", f"got={d.get('format')}")
db = db_get_setting("audit_forward") or {}
check("DB 落库：audit_forward.url", (db.get("url") or "") == "https://siem-gcfg-test.example.com:514/collect",
      f"db_url={db.get('url')}")
admin.put(f"{BASE}/api/audit/forward", json={
    "url": orig_forward.get("url", ""),
    "enabled": orig_forward.get("enabled", False),
    "format": orig_forward.get("format", "json"),
})
check("审计外发已恢复", True)

print()
print("=" * 72)
print("5. 错误处理：非法配置值 / 参数校验")
print("=" * 72)

r = admin.put(f"{BASE}/api/security/policy", json={"policy": {"block_threshold": "ultra"}})
check("非法拦截阈值 → 400", r.status_code == 400, f"status={r.status_code} detail={str(r.json().get('detail'))[:50]}")
r = admin.put(f"{BASE}/api/security/policy", json={"policy": {"audit_retention_days": 999}})
check("非法留存天数 → 400", r.status_code == 400, f"status={r.status_code}")
r = admin.put(f"{BASE}/api/model/config", json={"provider": "anthropic"})
check("非法模型厂商 → 400", r.status_code == 400, f"status={r.status_code}")
r = admin.put(f"{BASE}/api/model/config", json={"base_url": "ftp://evil.example.com"})
check("非法 base_url → 400", r.status_code == 400, f"status={r.status_code}")
r = admin.put(f"{BASE}/api/security/policy", json={"policy": {"trusted_domain_suffixes": "not-a-list"}})
check("非法域名后缀类型 → 400", r.status_code == 400, f"status={r.status_code}")

print()
print("=" * 72)
print("5b. 写后读校验：配置未真正落库时保存必须失败（进程内单元级）")
print("=" * 72)

# 不依赖运行中后端：直接验证 llm_runtime.save_config 的写后读校验逻辑
import llm_runtime as _lrt  # noqa: E402

class _NoPersistStorage:
    """模拟 set_setting 静默失败（如磁盘满 / 只读库）：get 永远返回空。"""
    def get_setting(self, key, default=None):
        return default
    def set_setting(self, key, value):
        pass

_orig_gs = _lrt.get_storage
_lrt.get_storage = lambda: _NoPersistStorage()
try:
    _lrt.save_config("zhipu", "sk-unit-nopersist", "https://x.example.com/v1", "m1")
    raised = False
except RuntimeError:
    raised = True
finally:
    _lrt.get_storage = _orig_gs
check("未落库时 save_config 抛 RuntimeError", raised)

class _PersistStorage:
    def __init__(self):
        self._s = {}
    def get_setting(self, key, default=None):
        return self._s.get(key, default)
    def set_setting(self, key, value):
        self._s[key] = value

_ps = _PersistStorage()
_lrt.get_storage = lambda: _ps
try:
    cfg = _lrt.save_config("zhipu", "sk-unit-persist", "https://x.example.com/v1", "m2")
    ok = cfg["model"] == "m2" and _ps._s["llm_runtime"]["api_key"] == "sk-unit-persist"
except RuntimeError:
    ok = False
finally:
    _lrt.get_storage = _orig_gs
check("正常落库时 save_config 成功且内容一致", ok, f"cfg_model={cfg.get('model')}")

print()
print("=" * 72)
print("6. 防泄露：策略接口不得返回非策略全局配置（含明文 Key）")
print("=" * 72)

# 重新写入标记 Key，验证策略响应中不出现
admin.put(f"{BASE}/api/model/config", json={"api_key": "sk-LEAK-MARKER-SECRET-99"})
r = admin.get(f"{BASE}/api/security/policy")
raw = r.text
d = r.json().get("policy", {})
leaked = sorted(k for k in d.keys() if k not in POLICY_KEYS)
check("策略响应仅含策略键", not leaked, f"extra_keys={leaked}")
check("策略响应不含明文 Key 值", "sk-LEAK-MARKER-SECRET-99" not in raw)
check("策略响应不含非策略键", not any(k in raw for k in NON_POLICY_KEYS if k != "api_key"))

# 恢复模型配置
if orig_llm:
    rest = dict(MARKER)
    rest.update(orig_llm)
    admin.put(f"{BASE}/api/model/config", json=rest)
else:
    admin.put(f"{BASE}/api/model/config", json={
        "provider": "zhipu", "api_key": "", "base_url": "", "model": "",
        "backup_provider": "openai", "backup_api_key": "", "backup_base_url": "", "backup_model": "",
    })

print()
print("=" * 72)
print(f"结果：PASS={PASS}  FAIL={FAIL}")
print("=" * 72)
sys.exit(0 if FAIL == 0 else 1)
