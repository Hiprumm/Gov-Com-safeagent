# -*- coding: utf-8 -*-
"""异步审批闭环 E2E 验证：请求→待审批提示→面板批准→重试放行"""
import httpx
import time
import sys

BASE = "http://127.0.0.1:8080"
PASS, FAIL = 0, 0


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS += ok
    FAIL += (not ok)
    print(f"{'[PASS]' if ok else '[FAIL]'} {name}" + (f" | {detail}" if detail else ""))


time.sleep(8)  # 等后端就绪
c = httpx.Client(timeout=120)

# 认证：审批查看与批准均需登录令牌（admin 具备审批权限）
_lr = c.post(f"{BASE}/api/auth/login", json={"username": "admin", "password": "admin123"})
_TOKEN = (_lr.json() or {}).get("token", "") if _lr.status_code == 200 else ""
c.headers["X-Auth-Token"] = _TOKEN
check("登录获取审批令牌", bool(_TOKEN), f"status={_lr.status_code}")

print("=" * 72)
print("1. 发送导出请求 → 应立即返回待人工审批（不阻塞 30 秒）")
print("=" * 72)
sid = f"e2e-approval-{int(time.time())}"
t0 = time.perf_counter()
r = c.post(f"{BASE}/api/agent/chat", params={
    "user_input": "请帮我导出本季度的公积金业务统计报表，用于部门季度总结",
    "session_id": sid,
})
dt = time.perf_counter() - t0
d = r.json()
step = d.get("current_step")
resp = d.get("final_response", "") or ""
check("立即返回（<15秒，原为60秒+）", dt < 15, f"耗时 {dt:.1f}s")
check("current_step=approval_pending", step == "approval_pending", f"step={step}")
check("回复含待审批提示", "人工审批" in resp, resp[:80].replace(chr(10), ' '))

print()
print("=" * 72)
print("2. 待审批列表应包含该请求")
print("=" * 72)
r = c.get(f"{BASE}/api/security/approval/pending")
pending = r.json().get("pending", [])
check("待审批列表非空", len(pending) > 0, f"count={len(pending)}")
req_id = None
for p in pending:
    det = p.get("action_details", {}) or {}
    if det.get("_session_id") == sid or "export" in str(p.get("action_type", "")):
        req_id = p.get("request_id")
        print(f"  找到: {req_id} | type={p.get('action_type')} | risk={p.get('risk_level')}")
        break
if req_id is None and pending:
    req_id = pending[0].get("request_id")
    print(f"  使用第一个: {req_id}")
check("定位到本会话审批单", req_id is not None)

print()
print("=" * 72)
print("3. 管理员批准 → 应授予能力+解锁会话")
print("=" * 72)
if req_id:
    r = c.post(f"{BASE}/api/security/approval/approve/{req_id}")
    ad = r.json()
    check("批准成功", ad.get("success") is True, str(ad)[:150])
    check("返回授予信息（session/tool）", ad.get("session_id") == sid, f"session={ad.get('session_id')}, tool={ad.get('tool_name')}")

print()
print("=" * 72)
print("4. 用户重试同一请求 → 应自动放行执行（无需重复审批）")
print("=" * 72)
t0 = time.perf_counter()
r = c.post(f"{BASE}/api/agent/chat", params={
    "user_input": "请帮我导出本季度的公积金业务统计报表，用于部门季度总结",
    "session_id": sid,
})
dt = time.perf_counter() - t0
d2 = r.json()
step2 = d2.get("current_step")
resp2 = d2.get("final_response", "") or ""
check("不再返回 approval_pending", step2 != "approval_pending", f"step={step2}")
check("不再含待审批提示", "人工审批" not in resp2, resp2[:80].replace(chr(10), ' '))

print()
print("=" * 72)
print(f"结果: {PASS} PASS / {FAIL} FAIL")
print("=" * 72)
sys.exit(1 if FAIL else 0)
