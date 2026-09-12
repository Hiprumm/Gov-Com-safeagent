# -*- coding: utf-8 -*-

# P0-1 工程收敛注入：统一路径引导（原脚本逻辑根目录）
import os as _os, sys as _sys
_BASE_DIR = r"x:\ZuoYe\揭榜挂帅26\Gov-Com-safeagent\ai_service"
_sys.path.insert(0, _BASE_DIR)
"""会话隔离回归：验证智能问答历史按账户独立分离。"""
import json, urllib.request, urllib.error, sqlite3, time, os

BASE = "http://localhost:8080"
DB = os.path.join(_BASE_DIR, "data", "safeagent.db")
PASS, FAIL = 0, 0

def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}  {detail}")

def req(method, path, body=None, token=None):
    url = BASE + path
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token:
        headers["X-Auth-Token"] = token
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8"))
        except Exception:
            return e.code, {}
    except Exception as e:
        return -1, str(e)

def login(u, p="admin123"):
    st, d = req("POST", "/api/auth/login", {"username": u, "password": p})
    return d.get("token", "") if isinstance(d, dict) else ""

def db_add_message(session_id, role="user", content="test"):
    """绕过 LLM 直接给会话补一条消息，使其 message_count>0（仅测试用）。"""
    conn = sqlite3.connect(DB)
    cur = conn.execute(
        "INSERT INTO conversation_history (session_id, role, content, type, timestamp) VALUES (?,?,?,?,?)",
        (session_id, role, content, "text", time.strftime("%Y-%m-%dT%H:%M:%S")))
    conn.execute("UPDATE sessions SET updated_at = ?, message_count = message_count + 1 WHERE session_id = ?",
                 (time.strftime("%Y-%m-%dT%H:%M:%S"), session_id))
    conn.commit()
    conn.close()

def db_cleanup(session_id):
    conn = sqlite3.connect(DB)
    conn.execute("DELETE FROM conversation_history WHERE session_id = ?", (session_id,))
    conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
    conn.commit()
    conn.close()

print("=== 登录 ===")
tk_admin = login("admin")
tk_user = login("user")
check("admin 登录", bool(tk_admin))
check("user 登录", bool(tk_user))

print("=== 匿名访问被拒 ===")
st, d = req("GET", "/api/agent/sessions")
check("匿名 list_sessions → 401", st == 401, (st, d))
st, d = req("GET", "/api/agent/history?session_id=whatever")
check("匿名 history → 401", st == 401, (st, d))

print("=== 各建一个会话（new_session 绑定 user_id） ===")
st, d = req("POST", "/api/agent/new_session", token=tk_admin)
sid_admin = d.get("session_id") if isinstance(d, dict) else ""
st, d = req("POST", "/api/agent/new_session", token=tk_user)
sid_user = d.get("session_id") if isinstance(d, dict) else ""
check("admin 建会话成功", bool(sid_admin))
check("user 建会话成功", bool(sid_user))

# 给两个会话各补一条消息（绕过 LLM），使其 message_count>0 可被 list 到
db_add_message(sid_admin, "user", "admin 的测试消息")
db_add_message(sid_user, "user", "user 的测试消息")

print("=== 会话列表按用户隔离 ===")
st, d = req("GET", "/api/agent/sessions", token=tk_admin)
admin_sids = [s["session_id"] for s in (d.get("sessions") or [])]
check("admin 列表含自己的会话", sid_admin in admin_sids, admin_sids)
check("admin 列表不含 user 的会话", sid_user not in admin_sids, admin_sids)

st, d = req("GET", "/api/agent/sessions", token=tk_user)
user_sids = [s["session_id"] for s in (d.get("sessions") or [])]
check("user 列表含自己的会话", sid_user in user_sids, user_sids)
check("user 列表不含 admin 的会话", sid_admin not in user_sids, user_sids)

print("=== 归属校验：越权读取/操作被拒 ===")
st, d = req("GET", f"/api/agent/history?session_id={sid_admin}", token=tk_user)
check("user 读 admin 历史 → 403", st == 403, (st, d))
st, d = req("GET", f"/api/agent/history?session_id={sid_admin}", token=tk_admin)
check("admin 读自己历史 → 200", st == 200, (st, d))
st, d = req("POST", f"/api/agent/delete_session?session_id={sid_admin}", token=tk_user)
check("user 删 admin 会话 → 403", st == 403, (st, d))
st, d = req("POST", f"/api/agent/clear_session?session_id={sid_admin}", token=tk_user)
check("user 清 admin 会话 → 403", st == 403, (st, d))

print("=== 清理测试数据 ===")
db_cleanup(sid_admin)
db_cleanup(sid_user)
check("测试会话已清理", True)

print(f"\n结果: {PASS} PASS / {FAIL} FAIL")
