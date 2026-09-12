# -*- coding: utf-8 -*-

# P0-1 工程收敛注入：统一路径引导（原脚本逻辑根目录）
import os as _os, sys as _sys
_BASE_DIR = r"x:\ZuoYe\揭榜挂帅26\Gov-Com-safeagent\ai_service"
_sys.path.insert(0, _BASE_DIR)
"""跨 worker 一致性验证：--workers 2 下，熔断/封IP 判定必须跨进程一致（读库为准）。"""
import requests, sys, time

BASE = "http://localhost:8080"
def post(p, b=None, tok=None):
    h = {"Content-Type":"application/json"}
    if tok: h["X-Auth-Token"]=tok
    return requests.post(BASE+p, json=b or {}, headers=h, timeout=30)
def get(p, tok=None):
    h = {"X-Auth-Token":tok} if tok else {}
    return requests.get(BASE+p, headers=h, timeout=30)

tok = post("/api/auth/login", {"username":"admin","password":"admin123"}).json()["token"]
ok = lambda r: r.status_code==200 and r.json().get("success") is True

res = []
def record(name, cond, info): res.append((name, cond, info))

# 1) 全局熔断：engage 后，无论落到哪个 worker，都须 403
r = post("/api/emergency/engage", {"reason":"多worker一致性验证","operator":"QA"}, tok)
record("engage", ok(r), r.status_code)
# 先确认读库判定已被当前状态反映
st = get("/api/emergency/status", tok).json()
record("status.engaged", st.get("global_engaged") is True, st)

n403, nread, nleak = 0, 0, 0
codes = {}
for _ in range(30):
    # 模拟真实登录用户：带 token，熔断期间应被应急中间件 403 拦截（而非到达 handler）
    r = post("/api/agent/chat", {"user_input":"x","input_source":"user_input"}, tok)
    codes[r.status_code] = codes.get(r.status_code, 0) + 1
    if r.status_code == 403 and "EMERGENCY_BLOCKED" in r.text:
        n403 += 1
    else:
        nleak += 1
    rr = get("/api/audit/logs/recent", tok)   # 只读研判应保持放行(200)
    if rr.status_code == 200:
        nread += 1
    time.sleep(0.05)
record("circuit: chat 403 across all workers", n403 == 30 and nleak == 0,
       f"403={n403} leak={nleak} statuses={codes}")
record("circuit: readonly still 200 across all workers", nread == 30, f"read200={nread}/30")

# 2) IP 封锁：封 127.0.0.1（此处源 IP），跨 worker 连只读也应 403；解除后恢复
post("/api/emergency/disengage", {}, tok)          # 先解除熔断，避免与 IP 测试叠加
r = post("/api/emergency/block_ip", {"ip":"127.0.0.1","reason":"IP跨worker验证"}, tok)
record("block ip", ok(r), r.text[:80])
n403ip = 0
for _ in range(20):
    r = get("/api/audit/logs/recent", tok)         # 只读也应连带拦截
    if r.status_code == 403 and "EMERGENCY_BLOCKED" in r.text:
        n403ip += 1
record("ip-block readonly 403 across all workers", n403ip == 20, f"403={n403ip}/20")

# 3) 账号封锁：封 admin 不应生效于本地管理端点验证——此处封一个测试账号，跨 worker 阻断其入口
r = post("/api/emergency/block_user", {"username":"demo_user_xyz","reason":"账号跨worker"}, tok)
record("block user", ok(r), r.text[:80])

# 清理：解除一切应急控制，恢复干净态
post("/api/emergency/disengage", {}, tok)
post("/api/emergency/unblock_ip", {"ip":"127.0.0.1"}, tok)
post("/api/emergency/unblock_user", {"username":"demo_user_xyz"}, tok)

print("== 跨 worker 一致性 ==")
f = [x for x in res if not x[1]]
for n,c,i in res: print(f"  [{'PASS' if c else 'FAIL'}] {n} | {i}")
print(f"TOTAL={len(res)} PASS={len(res)-len(f)} FAIL={len(f)}")
sys.exit(0 if not f else 1)