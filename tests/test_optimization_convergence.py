# -*- coding: utf-8 -*-

# P0-1 工程收敛注入：统一路径引导（原脚本逻辑根目录）
import os as _os, sys as _sys
_BASE_DIR = r"x:\ZuoYe\揭榜挂帅26\Gov-Com-safeagent\ai_service"
_sys.path.insert(0, _BASE_DIR)

"""P1-3 无消费者 API 收敛专项测试

优化闭环 12 个端点中仅 GET /api/optimization/attack_samples 被前端消费，
其余写端点默认关闭（ENABLE_OPTIMIZATION_WRITE=false → 501）：
1. 全部写端点默认返回 501（反馈标注 / 自动调优 / 版本应用 / 样例扩充 / 聚类 / 威胁情报导入 / 回归）；
2. 只读端点保持可用（feedback 列表 / stats / versions / attack_samples / threat_intel / trend）；
3. 新增只读汇总 GET /api/optimization/summary 返回 write_enabled 与各表计数；
4. 开启开关后写端点恢复可用（反馈标注可写入）。
"""
import os

from fastapi.testclient import TestClient

import main as main_mod

PASS, FAIL = 0, 0

# 写端点（默认应 501）
WRITE_ENDPOINTS = [
    ("POST", "/api/optimization/feedback", {"sample_text": "t", "annotator_label": "attack"}),
    ("POST", "/api/optimization/tune", {"auto_apply": False}),
    ("POST", "/api/optimization/versions/abc/apply", {}),
    ("POST", "/api/optimization/attack_samples", {"content": "t"}),
    ("POST", "/api/optimization/cluster", {"min_cluster": 2}),
    ("POST", "/api/optimization/threat_intel", {"iocs": []}),
    ("POST", "/api/optimization/regression", {"samples": []}),
]

# 只读端点（默认应 200）
READ_ENDPOINTS = [
    ("GET", "/api/optimization/feedback", {}),
    ("GET", "/api/optimization/feedback/stats", {}),
    ("GET", "/api/optimization/versions", {}),
    ("GET", "/api/optimization/attack_samples", {}),
    ("GET", "/api/optimization/threat_intel", {}),
    ("GET", "/api/optimization/trend", {}),
    ("GET", "/api/optimization/summary", {}),
]


def check(name, ok, detail=""):
    global PASS, FAIL
    PASS += bool(ok)
    FAIL += (not ok)
    print(f"{'[PASS]' if ok else '[FAIL]'} {name}" + (f" | {detail}" if detail else ""))


def login(client, username, password="admin123"):
    r = client.post("/api/auth/login", json={"username": username, "password": password})
    if r.status_code == 200:
        return (r.json() or {}).get("token", "")
    return ""


def auth_client(client, token):
    client.headers["X-Auth-Token"] = token
    return client


def main():
    client = TestClient(main_mod.app)
    token = login(client, "admin")
    check("管理员登录获取令牌", bool(token), f"token={token[:12] if token else 'EMPTY'}")
    admin = auth_client(client, token)

    # 1. 写端点默认 501（登录态下）
    for method, url, payload in WRITE_ENDPOINTS:
        resp = admin.request(method, url, json=payload)
        check(f"{method} {url} 默认关闭 501",
              resp.status_code == 501,
              f"status={resp.status_code} body={resp.text[:120]}")

    # 2. 只读端点保持可用
    for method, url, payload in READ_ENDPOINTS:
        resp = client.request(method, url, params=payload)
        check(f"{method} {url} 只读可用 200",
              resp.status_code == 200,
              f"status={resp.status_code} body={resp.text[:120]}")

    # 3. 汇总端点结构与开关位
    resp = client.get("/api/optimization/summary")
    data = resp.json()
    check("summary.write_enabled 为 false(默认关闭)",
          data.get("write_enabled") is False,
          f"write_enabled={data.get('write_enabled')}")
    check("summary 含版本/样例/IOC 计数",
          all(k in data for k in ("version_count", "attack_sample_count", "threat_ioc_count", "feedback")),
          f"keys={sorted(data.keys())}")
    check("summary.feedback 含误报/漏报统计",
          all(k in data.get("feedback", {}) for k in ("total", "false_negatives", "false_positives")),
          f"feedback={data.get('feedback')}")

    # 4. 开启开关后写端点恢复
    old = main_mod.settings.ENABLE_OPTIMIZATION_WRITE
    main_mod.settings.ENABLE_OPTIMIZATION_WRITE = True
    try:
        resp = admin.post("/api/optimization/feedback", json={
            "sample_text": "convergence-test 钓鱼链接诱导点击窃取账号",
            "predicted_label": "benign",
            "predicted_risk": "none",
            "annotator_label": "attack",
            "comment": "p1-3 test",
        })
        check("开启开关后 POST feedback 恢复 200",
              resp.status_code == 200,
              f"status={resp.status_code} body={resp.text[:150]}")
        resp2 = client.get("/api/optimization/summary")
        check("写入后 summary.write_enabled 为 true",
              resp2.json().get("write_enabled") is True,
              f"write_enabled={resp2.json().get('write_enabled')}")
        check("写入后 summary.feedback.total >= 1",
              resp2.json().get("feedback", {}).get("total", 0) >= 1,
              f"total={resp2.json().get('feedback', {}).get('total')}")
    finally:
        main_mod.settings.ENABLE_OPTIMIZATION_WRITE = old

    # 5. 复位后写端点再次 501
    resp = admin.post("/api/optimization/feedback", json={"sample_text": "x"})
    check("复位后 POST feedback 再次 501",
          resp.status_code == 501,
          f"status={resp.status_code}")

    print(f"\n结果: PASS={PASS} FAIL={FAIL}")
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
