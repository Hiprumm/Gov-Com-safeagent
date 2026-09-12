# -*- coding: utf-8 -*-

# P0-1 工程收敛注入：统一路径引导（原脚本逻辑根目录）
import os as _os, sys as _sys
_BASE_DIR = r"x:\ZuoYe\揭榜挂帅26\Gov-Com-safeagent\ai_service"
_sys.path.insert(0, _BASE_DIR)
"""新功能 bug 测试：认证/权限/后台/审计加固/通知/系统状态/模型接入"""
import base64
import hashlib
import hmac
import json
import sqlite3
import struct
import time
import urllib.error
import urllib.parse
import urllib.request

import os

BASE = "http://localhost:8080"
# SQLite 库路径按脚本位置推导（脚本位于 ai_service/ 下运行）
DB = os.path.join(_BASE_DIR, "data", "safeagent.db")

results = []


def call(method, path, token=None, body=None, raw_token=None):
    url = BASE + path
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    tk = raw_token if raw_token is not None else token
    if tk:
        headers["X-Auth-Token"] = tk
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            text = resp.read().decode("utf-8", "ignore")
            try:
                return resp.status, json.loads(text)
            except ValueError:
                return resp.status, text
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", "ignore")
        try:
            return e.code, json.loads(text)
        except ValueError:
            return e.code, text
    except Exception as e:  # noqa
        return 0, str(e)


def check(name, cond, detail=""):
    ok = bool(cond)
    results.append((name, ok, detail))
    print(("[PASS] " if ok else "[FAIL] ") + name + ("" if ok else "  -> " + str(detail)[:300]))


def totp_code(secret, for_time=None, step=30, digits=6):
    s = (secret or "").strip().replace(" ", "").upper()
    s += "=" * ((8 - len(s) % 8) % 8)
    key = base64.b32decode(s)
    counter = int((for_time if for_time is not None else time.time()) // step)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


# ==================== A. 认证 ====================
st, d = call("GET", "/api/auth/me")
check("A1 me-未登录 user=null", st == 200 and d.get("user") is None, d)
check("A2 me 返回演示账号(4)", isinstance(d.get("demo_accounts"), list) and len(d["demo_accounts"]) == 4, d)

st, d = call("POST", "/api/auth/login", body={"username": "admin", "password": "admin123"})
admin_tk = d.get("token", "") if isinstance(d, dict) else ""
check("A3 admin 登录", st == 200 and bool(admin_tk) and d.get("user", {}).get("role") == "admin", d)

st, d = call("GET", "/api/auth/me", token=admin_tk)
check("A4 admin 身份回读", st == 200 and (d.get("user") or {}).get("username") == "admin", d)

st, d = call("POST", "/api/auth/login", body={"username": "admin", "password": "wrong-pw-xxx"})
check("A5 错误口令 401", st == 401, (st, d))

st, d = call("POST", "/api/auth/login", body={"username": "", "password": ""})
check("A6 空口令 401", st == 401, (st, d))

bad = admin_tk[:-1] + ("A" if admin_tk[-1] != "A" else "B")
st, d = call("GET", "/api/auth/me", raw_token=bad)
check("A7 篡改令牌无效", st == 200 and d.get("user") is None, d)

st, d = call("POST", "/api/auth/refresh", token=admin_tk)
new_tk = d.get("token", "") if isinstance(d, dict) else ""
check("A8 refresh 签发新令牌", st == 200 and bool(new_tk) and new_tk != admin_tk, d)
st, d = call("GET", "/api/auth/me", token=admin_tk)
check("A9 旧令牌已失效", st == 200 and d.get("user") is None, d)
st, d = call("GET", "/api/auth/me", token=new_tk)
check("A10 新令牌有效", st == 200 and (d.get("user") or {}).get("username") == "admin", d)

st, d = call("POST", "/api/auth/logout", token=new_tk)
st2, d2 = call("GET", "/api/auth/me", token=new_tk)
check("A11 登出后令牌失效", st == 200 and st2 == 200 and d2.get("user") is None, (st, d, d2))

st, d = call("GET", "/api/auth/sso/config")
check("A12 SSO 默认未启用", st == 200 and d.get("sso_enabled") is False, d)
check("A12b SSO 配置含加固字段(签名/IP)",
      d.get("signature_required") is False and d.get("ip_restricted") is False, d)
st, d = call("POST", "/api/auth/sso")
check("A13 SSO 未启用 404", st == 404, (st, d))

# ==================== B. 权限引擎 ====================
st, d = call("POST", "/api/auth/login", body={"username": "admin", "password": "admin123"})
admin_tk = d.get("token", "")

EXPECT = {
    "admin": {"chat", "dashboard", "runtime", "security", "redteam", "tools", "approval", "audit", "policy", "system"},
    "operator": {"chat", "dashboard", "runtime", "security", "tools", "approval", "audit"},
    "auditor": {"chat", "dashboard", "approval", "audit"},
    "manager": {"chat", "dashboard", "approval", "audit"},
    "user": {"chat", "dashboard", "audit"},
}
tokens = {}
# 各角色对应的真实演示账号（manager 的账号是 mgr_biz，非 "manager"）
ACCOUNT_FOR_ROLE = {"admin": "admin", "operator": "operator", "auditor": "auditor",
                    "manager": "mgr_biz", "user": "user"}
for role, acct in ACCOUNT_FOR_ROLE.items():
    st, d = call("POST", "/api/auth/login", body={"username": acct, "password": "admin123"})
    tk = d.get("token", "") if isinstance(d, dict) else ""
    tokens[role] = tk
    check(f"B1 {role}({acct}) 登录", st == 200 and bool(tk), d)

for role, exp in EXPECT.items():
    st, d = call("GET", "/api/auth/permissions", token=tokens.get(role, ""))
    mods = set(d.get("modules", [])) if isinstance(d, dict) else set()
    check(f"B2 {role} 模块收敛", st == 200 and mods == exp, (mods, exp))

st, d = call("GET", "/api/admin/users", token=tokens.get("user", ""))
check("B3 非管理员访问后台被拒", isinstance(d, dict) and d.get("success") is False, d)
st, d = call("GET", "/api/admin/users", token=admin_tk)
check("B4 管理员可访问后台", isinstance(d, dict) and d.get("success") is True, d)

st, d = call("GET", "/api/dashboard/overview", token=admin_tk)
adm_scope = d.get("scope") or d.get("scope_meta") or (d.get("meta") if isinstance(d, dict) else None)
st2, d2 = call("GET", "/api/dashboard/overview", token=tokens.get("user", ""))
usr_scope = d2.get("scope") or d2.get("scope_meta") or (d2.get("meta") if isinstance(d2, dict) else None)
check("B5 看板按角色收敛字段存在", adm_scope is not None and usr_scope is not None, (adm_scope, usr_scope))

# ==================== C. 后台管理 ====================
QA_PW = "QaProbe#2026"
st, d = call("DELETE", "/api/admin/users/qa_probe", token=admin_tk)  # 清理历史残留

st, d = call("POST", "/api/admin/users", token=admin_tk,
             body={"username": "qa_probe", "password": "abc", "role": "user"})
check("C1 弱口令被拒", isinstance(d, dict) and d.get("success") is False, d)

st, d = call("POST", "/api/admin/users", token=admin_tk,
             body={"username": "qa_probe", "password": "admin123", "role": "user"})
check("C2 口令复杂度策略生效", isinstance(d, dict) and d.get("success") is False, d)

st, d = call("POST", "/api/admin/users", token=admin_tk,
             body={"username": "qa_probe", "password": QA_PW, "display_name": "QA探针",
                   "role": "invalid_role", "department": "测试部"})
check("C3 非法角色被拒", isinstance(d, dict) and d.get("success") is False, d)

st, d = call("POST", "/api/admin/users", token=admin_tk,
             body={"username": "qa_probe", "password": QA_PW, "display_name": "QA探针",
                   "role": "user", "department": "测试部", "position": "测试员"})
check("C4 创建账号成功", isinstance(d, dict) and d.get("success") is True, d)

st, d = call("POST", "/api/admin/users", token=admin_tk,
             body={"username": "qa_probe", "password": QA_PW, "role": "user"})
check("C5 重复账号被拒", isinstance(d, dict) and d.get("success") is False, d)

st, d = call("GET", "/api/admin/users", token=admin_tk)
users = d.get("users", []) if isinstance(d, dict) else []
check("C6 用户列表含新账号", any(u.get("username") == "qa_probe" for u in users), len(users))
check("C7 用户列表不泄露口令", all("password_hash" not in u and "salt" not in u for u in users))

st, d = call("PUT", "/api/admin/users/qa_probe", token=admin_tk,
             body={"position": "高级测试员", "department": "测试部"})
check("C8 更新资料成功", isinstance(d, dict) and d.get("success") is True, d)
st, d = call("PUT", "/api/admin/users/qa_probe", token=admin_tk, body={"role": "bad"})
check("C9 更新非法角色被拒", isinstance(d, dict) and d.get("success") is False, d)

st, d = call("PUT", "/api/admin/users/admin", token=admin_tk, body={"role": "user"})
check("C10 管理员自我降级被拒", isinstance(d, dict) and d.get("success") is False, d)
st, d = call("PUT", "/api/admin/users/admin", token=admin_tk, body={"role": "manager"})
check("C10b 管理员自我降级为 manager 被拒", isinstance(d, dict) and d.get("success") is False, d)
st, d = call("PUT", "/api/admin/users/admin", token=admin_tk, body={"status": "disabled"})
check("C11 管理员自我停用被拒", isinstance(d, dict) and d.get("success") is False, d)
st, d = call("DELETE", "/api/admin/users/admin", token=admin_tk)
check("C12 删除自身被拒", isinstance(d, dict) and d.get("success") is False, d)
st, d = call("DELETE", "/api/admin/users/user", token=admin_tk)
check("C13 删除内置演示账号被拒", isinstance(d, dict) and d.get("success") is False, d)

st, d = call("GET", "/api/admin/stats", token=admin_tk)
check("C14 后台统计结构", isinstance(d, dict) and d.get("success") and "total" in (d.get("stats") or {}), d)

st, d = call("GET", "/api/admin/departments", token=admin_tk)
depts = d.get("departments", []) if isinstance(d, dict) else []
check("C15 部门目录存在", st == 200 and "测试部" in depts, depts)
st, d = call("POST", "/api/admin/departments", token=admin_tk, body={"name": "测试部"})
check("C16 重复部门返回已存在", isinstance(d, dict) and d.get("success") is False, d)
st, d = call("POST", "/api/admin/departments", token=admin_tk, body={"name": ""})
check("C17 空部门名被拒", isinstance(d, dict) and d.get("success") is False, d)

# ==================== D. 自我口令 + MFA ====================
st, d = call("POST", "/api/auth/login", body={"username": "qa_probe", "password": QA_PW})
qa_tk = d.get("token", "") if isinstance(d, dict) else ""
check("D1 新账号可登录", st == 200 and bool(qa_tk), d)

st, d = call("POST", "/api/auth/password", token=qa_tk, body={"old_password": QA_PW, "new_password": "weak"})
check("D2 自助改弱口令被拒", st == 400, (st, d))
st, d = call("POST", "/api/auth/password", token=qa_tk, body={"old_password": "wrong-old", "new_password": "NewProbe#2026"})
check("D3 原口令错误被拒", st == 400, (st, d))
st, d = call("POST", "/api/auth/password", token=qa_tk, body={"old_password": QA_PW, "new_password": "NewProbe#2026"})
check("D4 自助改强口令成功", st == 200 and d.get("success") is True, (st, d))
st, d = call("POST", "/api/auth/login", body={"username": "qa_probe", "password": "NewProbe#2026"})
qa_tk = d.get("token", "") if isinstance(d, dict) else ""
check("D5 新口令可登录", st == 200 and bool(qa_tk), d)

st, d = call("GET", "/api/auth/mfa/status", token=qa_tk)
check("D6 MFA 状态查询", st == 200 and d.get("mfa_enabled") is False and d.get("available") is True, d)
st, d = call("POST", "/api/auth/mfa/enroll", token=qa_tk)
secret = d.get("secret", "") if isinstance(d, dict) else ""
check("D7 MFA 绑定生成密钥", st == 200 and d.get("success") and bool(secret) and "otpauth://" in d.get("otpauth_uri", ""), d)
st, d = call("POST", "/api/auth/mfa/confirm", token=qa_tk, body={"code": "000000"})
check("D8 错误验证码被拒", isinstance(d, dict) and d.get("success") is False, d)

# TOTP 密钥加密入库（防止"拿到库即生成验证码"）
_conn = sqlite3.connect(DB)
_row = _conn.execute("SELECT totp_secret FROM sys_users WHERE username='qa_probe'").fetchone()
_conn.close()
_stored = _row[0] if _row else ""
check("D8b TOTP 密钥密文入库(enc:v1:)", str(_stored).startswith("enc:v1:"), str(_stored)[:40])
check("D8c 库中不含明文密钥", bool(secret) and secret not in str(_stored), "ok")
st, d = call("POST", "/api/auth/mfa/confirm", token=qa_tk, body={"code": totp_code(secret)})
check("D9 正确验证码启用 MFA", isinstance(d, dict) and d.get("success") is True, d)
st, d = call("POST", "/api/auth/login", body={"username": "qa_probe", "password": "NewProbe#2026"})
ticket = d.get("mfa_ticket", "") if isinstance(d, dict) else ""
check("D10 启用 MFA 后登录返回票据", st == 200 and d.get("mfa_required") is True and bool(ticket), d)
st, d = call("GET", "/api/auth/me", token=ticket)
check("D11 MFA 票据不能访问业务接口", st == 200 and d.get("user") is None, d)
st, d = call("POST", "/api/auth/mfa/verify", body={"ticket": ticket, "code": "000000"})
check("D12 MFA 错误验证码 401", st == 401, (st, d))
st, d = call("POST", "/api/auth/mfa/verify", body={"ticket": ticket, "code": totp_code(secret)})
qa_tk = d.get("token", "") if isinstance(d, dict) else ""
check("D13 MFA 验证签发令牌", st == 200 and bool(qa_tk), d)
st, d = call("POST", "/api/auth/mfa/disable", token=qa_tk)
check("D14 停用 MFA", st == 200 and d.get("success") is True, d)
st, d = call("POST", "/api/auth/login", body={"username": "qa_probe", "password": "NewProbe#2026"})
check("D15 停用后可正常登录", st == 200 and bool(d.get("token")), d)

# ==================== E. 审计加固 ====================
st, d = call("POST", "/api/auth/login", body={"username": "admin", "password": "admin123"})
admin_tk = d.get("token", "")

st, d = call("GET", "/api/audit/protection", token=tokens.get("user", ""))
check("E1 审计保护非管理员被拒", isinstance(d, dict) and d.get("success") is False, d)
st, d = call("GET", "/api/audit/protection", token=admin_tk)
prot = d.get("protection", {}) if isinstance(d, dict) else {}
check("E2 WORM 已安装", isinstance(d, dict) and d.get("success") and prot.get("installed") is True, d)
st, d = call("POST", "/api/audit/protection/install", token=admin_tk)
check("E3 WORM 幂等安装", isinstance(d, dict) and d.get("success") and d.get("protection", {}).get("installed") is True, d)

# WORM 物理验证：直接改库应被触发器拒绝
worm_ok = True
worm_detail = ""
try:
    c = sqlite3.connect(DB)
    try:
        c.execute("UPDATE audit_logs SET risk_level='none' WHERE rowid=1")
        c.commit()
        worm_ok = False
        worm_detail = "UPDATE 未被拒绝"
    except sqlite3.Error as e:
        worm_detail = "update:" + str(e)[:80]
    try:
        c.execute("DELETE FROM audit_logs WHERE rowid=1")
        c.commit()
        worm_ok = False
        worm_detail += " | DELETE 未被拒绝"
    except sqlite3.Error as e:
        worm_detail += " | delete:" + str(e)[:80]
    c.close()
except Exception as e:
    worm_ok = False
    worm_detail = str(e)
check("E4 WORM 直连改库被拒(UPDATE+DELETE)", worm_ok, worm_detail)

st, d = call("POST", "/api/audit/anchor", token=admin_tk)
anchor = d.get("anchor", {}) if isinstance(d, dict) else {}
check("E5 创建审计锚点", isinstance(d, dict) and d.get("success") and anchor.get("head_hash") is not None, d)
st, d = call("POST", "/api/audit/anchor/verify", token=admin_tk)
check("E6 锚点校验通过", isinstance(d, dict) and d.get("success") is True, d)
st, d = call("GET", "/api/audit/anchor", token=admin_tk)
check("E7 锚点列表含最新", isinstance(d, dict) and len(d.get("anchors", [])) >= 1, d)

st, d = call("GET", "/api/audit/tsa", token=admin_tk)
check("E8 TSA 配置查询", isinstance(d, dict) and d.get("success") and "url" in (d.get("config") or {}), d)
st, d = call("PUT", "/api/audit/tsa", token=admin_tk, body={"url": "http://127.0.0.1:9/tsa", "enabled": False})
check("E9 TSA 配置保存", isinstance(d, dict) and d.get("success") and d.get("config", {}).get("enabled") is False, d)

st, d = call("GET", "/api/audit/forward", token=admin_tk)
check("E10 外发配置查询", isinstance(d, dict) and d.get("success") and "enabled" in (d.get("config") or {}), d)
st, d = call("PUT", "/api/audit/forward", token=admin_tk, body={"url": "http://127.0.0.1:9/siem", "enabled": True, "format": "cef"})
check("E11 外发配置保存", isinstance(d, dict) and d.get("success") and d.get("config", {}).get("format") == "cef", d)
st, d = call("POST", "/api/audit/forward/test", token=admin_tk)
check("E12 外发连通测试失败可识别", isinstance(d, dict) and d.get("success") is False, d)
st, d = call("PUT", "/api/audit/forward", token=admin_tk, body={"url": "", "enabled": False, "format": "json"})
check("E13 外发配置复位", isinstance(d, dict) and d.get("success") and d.get("config", {}).get("enabled") is False, d)
st, d = call("GET", "/api/audit/forward/history", token=admin_tk)
check("E14 外发历史可查", isinstance(d, dict) and d.get("success") is True, d)

st, d = call("GET", "/api/audit/archives", token=admin_tk)
check("E15 归档列表可查", isinstance(d, dict) and d.get("success") and isinstance(d.get("archives"), list), d)
st, d = call("GET", "/api/audit/archives/..%2F..%2Fsafeagent.db", token=admin_tk)
check("E16 归档下载防穿越", st in (404, 403, 400), (st, d))
st, d = call("GET", "/api/audit/logs/verify", token=admin_tk)
check("E17 审计链验签接口", st == 200 and isinstance(d, dict), (st, type(d).__name__))
st, d = call("GET", "/api/audit/logs/verify-graded", token=admin_tk)
check("E18 分级验签接口", st == 200 and isinstance(d, dict), (st, type(d).__name__))

# ==================== F. 通知（需登录；配置类仅管理员） ====================
st, d = call("GET", "/api/notifications")
check("F0 通知列表匿名被拒(401)", st == 401, (st, d))
st, d = call("GET", "/api/notifications", token=admin_tk)
check("F1 通知列表结构", st == 200 and isinstance(d.get("list"), list) and isinstance(d.get("unread"), int), d)
st, d = call("POST", "/api/notifications/read", token=admin_tk, body={})
check("F2 全部标记已读", st == 200 and d.get("success") and d.get("unread") == 0, d)
st, d = call("GET", "/api/notifications/webhook")
check("F2b Webhook 匿名被拒", not (st == 200 and (d or {}).get("success")), (st, d))
st, d = call("GET", "/api/notifications/webhook", token=admin_tk)
check("F3 Webhook 配置查询", st == 200 and d.get("success") is True, d)
st, d = call("PUT", "/api/notifications/webhook", token=admin_tk, body={"url": "ftp://bad", "enabled": True})
check("F4 非法 Webhook 地址 400", st == 400, (st, d))
st, d = call("PUT", "/api/notifications/webhook", token=admin_tk, body={"url": "http://127.0.0.1:9/hook", "enabled": True})
check("F5 Webhook 保存", st == 200 and d.get("success") is True, d)
st, d = call("POST", "/api/notifications/webhook/test", token=admin_tk, body={"url": "http://127.0.0.1:9/hook"})
check("F6 Webhook 测试失败可识别", st == 400, (st, d))
st, d = call("PUT", "/api/notifications/webhook", token=admin_tk, body={"url": "", "enabled": False})
check("F7 Webhook 复位", st == 200 and d.get("success") is True, d)
st, d = call("POST", "/api/notifications/clear", token=admin_tk)
check("F8 通知清空", st == 200 and d.get("success") is True, d)
st, d = call("PUT", "/api/notifications/webhook", token=tokens.get("user", ""), body={"url": "http://x", "enabled": True})
check("F9 非管理员改 Webhook 被拒", isinstance(d, dict) and d.get("success") is False, d)

# ==================== G. 系统状态 / 模型接入（仅管理员） ====================
st, d = call("GET", "/api/system/status")
check("G0 系统自检匿名被拒", not (st == 200 and (d or {}).get("success")), (st, d))
st, d = call("GET", "/api/system/status", token=admin_tk)
ok = (st == 200 and isinstance(d, dict) and d.get("success")
      and all(k in d for k in ("service", "websocket", "llm", "policy", "data"))
      and "uptime_seconds" in (d.get("service") or {}))
check("G1 系统自检结构完整", ok, d)
st, d = call("POST", "/api/system/maintenance/clean_sessions", token=admin_tk)
check("G2 清理空会话", st == 200 and d.get("success") is True, d)

st, d = call("GET", "/api/model/config")
check("G2b 模型配置匿名被拒", not (st == 200 and (d or {}).get("success")), (st, d))
st, d = call("PUT", "/api/model/config", body={"provider": "bad"})
check("G2c 模型配置匿名写入被拒", not (st == 200 and (d or {}).get("success")), (st, d))
st, d = call("GET", "/api/model/config", token=admin_tk)
check("G3 模型配置查询", st == 200 and d.get("success") and "provider" in (d.get("config") or {}), d)
st, d = call("PUT", "/api/model/config", token=admin_tk, body={"provider": "bad-provider"})
check("G4 非法 provider 400", st == 400, (st, d))
st, d = call("PUT", "/api/model/config", token=admin_tk, body={"provider": "openai", "base_url": "ftp://x"})
check("G5 非法 base_url 400", st == 400, (st, d))
st, d = call("POST", "/api/model/config/test", token=admin_tk, body={"provider": "openai", "base_url": "http://127.0.0.1:9", "api_key": "x"})
check("G6 模型连通测试失败可识别", st == 400, (st, d))
st, d = call("PUT", "/api/model/config", token=tokens.get("user", ""), body={"provider": "bad"})
check("G7 非管理员改模型配置被拒", isinstance(d, dict) and d.get("success") is False, d)

# ==================== I. 审批端点安全 ====================
st, d = call("POST", "/api/security/approval/approve?request_id=X&approver_id=attacker&approver_role=super_admin")
check("I1 legacy 审批端点已移除(不可匿名批准)", st in (404, 405, 403), (st, d))

st, d = call("GET", "/api/security/approval/pending")
check("I2 待审列表匿名被拒(403)", st == 403, (st, d))
st, d = call("GET", "/api/security/approval/pending", token=admin_tk)
check("I3 待审列表管理员可读", st == 200 and "pending" in d, (st, str(d)[:120]))
st, d = call("GET", "/api/security/approval/pending", token=tokens.get("user", ""))
check("I4 待审列表无审批权限被拒", st == 403, (st, d))
st, d = call("GET", "/api/security/approval/history")
check("I5 审批历史匿名被拒(403)", st == 403, (st, d))
st, d = call("GET", "/api/security/approval/history", token=admin_tk)
check("I6 审批历史管理员可读", st == 200 and "records" in d, (st, str(d)[:120]))

# ==================== J. 审计导出鉴权 ====================
st, d = call("GET", "/api/audit/export")
check("J1 审计导出匿名被拒(401)", st == 401, (st, str(d)[:120]))
st, d = call("GET", "/api/audit/export", token=tokens.get("user", ""))
check("J2 审计导出无 audit.export 权限被拒(403)", st == 403, (st, str(d)[:120]))
st, d = call("GET", "/api/audit/export", token=tokens.get("auditor", ""))
check("J3 auditor 可导出", st == 200, (st, str(d)[:80]))
st, d = call("GET", "/api/audit/export", token=admin_tk)
check("J4 admin 可导出", st == 200, (st, str(d)[:80]))

# ==================== K. 审计读取数据范围收敛 ====================
st, d = call("GET", "/api/audit/logs/recent")
check("K1 审计日志匿名被拒(401)", st == 401, (st, str(d)[:120]))
st, d = call("GET", "/api/audit/logs/recent", token=admin_tk)
check("K2 admin 视角 scope=all", st == 200 and d.get("scope") == "all", (st, str(d)[:120]))
st, d = call("GET", "/api/audit/logs/recent", token=tokens.get("user", ""))
check("K3 user 视角 scope=self", st == 200 and d.get("scope") == "self", (st, str(d)[:120]))
rows = d.get("logs", []) if isinstance(d, dict) else []
check("K4 user 仅见本人记录", all((r.get("user_id") or "") == "user" for r in rows), [r.get("user_id") for r in rows[:5]])
st, d = call("GET", "/api/audit/logs/page?page=1&page_size=5", token=admin_tk)
check("K5 admin 分页可见 scope=all", st == 200 and d.get("scope") == "all" and "total" in d, (st, str(d)[:150]))
st, d = call("GET", "/api/audit/logs/page?page=1&page_size=5", token=tokens.get("user", ""))
check("K6 user 分页可见 scope=self", st == 200 and d.get("scope") == "self", (st, str(d)[:150]))
st, d = call("POST", "/api/audit/logs/search", token=tokens.get("user", ""), body={})
check("K7 user 检索收敛 scope=self", st == 200 and d.get("scope") == "self", (st, str(d)[:150]))
st, d = call("POST", "/api/audit/logs/search", body={})
check("K8 审计检索匿名被拒(401)", st == 401, (st, str(d)[:120]))

# ==================== L. 统一鉴权中间件覆盖 ====================
for m, p, b in [
    ("PUT", "/api/security/policy", {"policy": {}}),
    ("POST", "/api/security/tool_management/toggle", {"enabled": True}),
    ("POST", "/api/security/runtime/terminate/qa_probe", None),
    ("POST", "/api/security/operation_guard/clear/qa_probe", None),
    ("POST", "/api/security/session_risk/clear/qa_probe", None),
    ("POST", "/api/security/cross_source/clear/qa_probe", None),
    ("POST", "/api/kb/rebuild", None),
    ("POST", "/api/optimization/tune", {}),
    ("POST", "/api/agent/delete_session?session_id=qa_probe", None),
    ("POST", "/api/agent/chat?user_input=hi&session_id=qa_probe", None),
]:
    st, d = call(m, p, body=b)
    check(f"L1 匿名被拒 {p.split('?')[0]}", st == 401, (st, str(d)[:80]))

st, d = call("PUT", "/api/security/policy", token=tokens.get("operator", ""), body={"policy": {}})
check("L2 operator 无 policy.manage 被拒(403)", st == 403, (st, str(d)[:100]))
st, d = call("POST", "/api/security/runtime/terminate/qa_probe", token=tokens.get("auditor", ""))
check("L3 auditor 无 runtime.terminate 被拒(403)", st == 403, (st, str(d)[:100]))
st, d = call("POST", "/api/optimization/tune", token=tokens.get("user", ""), body={})
check("L4 user 无 security.scan 被拒(403)", st == 403, (st, str(d)[:100]))
st, d = call("GET", "/api/security/tool_management/status")
cur = d.get("enabled") if isinstance(d, dict) else True
st, d = call("POST", "/api/security/tool_management/toggle", token=admin_tk, body={"enabled": bool(cur)})
check("L5 admin 可操作工具管控（原值回写）", st == 200 and d.get("enabled") == bool(cur), (st, d))
# 会话隔离后：登录用户仅能管理自己的会话。新建归属自己的会话再删除，应返回 200。
st, d = call("POST", "/api/agent/new_session", token=admin_tk)
_sid = d.get("session_id") if isinstance(d, dict) else ""
st, d = call("POST", f"/api/agent/delete_session?session_id={_sid}", token=admin_tk)
check("L6 登录后可管理（自己的）会话", st == 200, (st, str(d)[:100]))

# ==================== H. 登录锁定（独立账号：登录失败计数在进程内存，跨运行会残留） ====================
call("DELETE", "/api/admin/users/qa_lock_probe", token=admin_tk)
st, d = call("POST", "/api/admin/users", token=admin_tk,
             body={"username": "qa_lock_probe", "password": "QaLock#2026", "role": "user"})
check("H0 创建锁定测试账号", isinstance(d, dict) and d.get("success") is True, d)
lock_codes = []
for _ in range(5):
    st, d = call("POST", "/api/auth/login", body={"username": "qa_lock_probe", "password": "definitely-wrong"})
    lock_codes.append(st)
check("H1 连续失败触发锁定(423)", 423 in lock_codes, lock_codes)
st, d = call("POST", "/api/auth/login", body={"username": "qa_lock_probe", "password": "QaLock#2026"})
check("H2 锁定期内正确口令也被拒(423)", st == 423, (st, d))
call("DELETE", "/api/admin/users/qa_lock_probe", token=admin_tk)

# ==================== 清理 ====================
st, d = call("DELETE", "/api/admin/users/qa_probe", token=admin_tk)
check("Z1 清理测试账号", isinstance(d, dict) and d.get("success") is True, d)
st, d = call("GET", "/api/admin/users", token=admin_tk)
users = d.get("users", []) if isinstance(d, dict) else []
check("Z2 测试账号已移除", not any(u.get("username") == "qa_probe" for u in users))

passed = sum(1 for _, ok, _ in results if ok)
total = len(results)
print("\n===== SUMMARY: %d/%d passed =====" % (passed, total))
fails = [(n, dt) for n, ok, dt in results if not ok]
if fails:
    print("FAILED CASES:")
    for n, dt in fails:
        print(" - %s -> %s" % (n, str(dt)[:300]))
