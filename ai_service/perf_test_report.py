# -*- coding: utf-8 -*-
"""性能压测 + 检测准确率抽测脚本（比赛/汇报用）

三阶段：
  A. 本地链路并发压测：login 预热取 token → detect_single（本地检测）/ audit logs / dashboard overview
  B. LLM 全链路抽样：/api/agent/chat（含大模型调用）少量抽样，记录冷启动与平均耗时（--llm-off 跳过）
  C. 检测准确率抽测：攻击样本 + 正常样本 → 漏报率/误报率（每样本独立 session_id，隔离会话风险累积）

用法（Windows PowerShell）：
  python perf_test_report.py --base-url http://localhost:8080 --concurrency 10 20 50
  python perf_test_report.py --llm-off                     # 跳过 LLM 抽样（不耗额度）
  python perf_test_report.py --base-url https://host       # 生产域名

输出：perf_report.json + perf_report.md（与脚本同目录）
"""
import argparse
import json
import os
import statistics
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

BASE = os.path.dirname(os.path.abspath(__file__))
OUT_JSON = os.path.join(BASE, "perf_report.json")
OUT_MD = os.path.join(BASE, "perf_report.md")

# ---- 阶段 C 默认样本量 ----
FN_SAMPLE_CNT = 24     # 攻击样本抽测数
NORMAL_SAMPLE_CNT = 24  # 正常样本抽测数

# ---- 阶段 A 本地链路 ----
BENIGN_TEXT = "我需要在政务大厅预约办理营业执照，请问需要带哪些材料？"
AUDIT_URL = "/api/audit/logs/recent"
DASH_URL = "/api/dashboard/overview"


def pct(latencies, p):
    if not latencies:
        return 0.0
    s = sorted(latencies)
    idx = min(len(s) - 1, int(len(s) * p))
    return round(s[idx], 1)


def login(base, username, password, timeout=15):
    r = requests.post(f"{base}/api/auth/login", json={"username": username, "password": password}, timeout=timeout)
    r.raise_for_status()
    return r.json()["token"]


def _worker(base, headers, kind, session_id, rl):
    """阶段 A 单个请求：返回 (ok, latency_ms)"""
    start = time.perf_counter()
    try:
        if kind == "detect":
            resp = requests.post(f"{base}/api/security/detect_single",
                                 params={"text": BENIGN_TEXT, "source": "user_input", "session_id": session_id},
                                 headers=headers, timeout=rl)
        elif kind == "audit":
            resp = requests.get(f"{base}{AUDIT_URL}?limit=20", headers=headers, timeout=rl)
        else:
            resp = requests.get(f"{base}{DASH_URL}", headers=headers, timeout=rl)
        ok = resp.status_code == 200
        return ok, (time.perf_counter() - start) * 1000
    except Exception:
        return False, (time.perf_counter() - start) * 1000


def run_load_phase(base, headers, kind, concurrency, duration, rl=30):
    """并发压测某端点：预热 2s 后计时 duration 秒"""
    # 预热
    warm_start = time.time()
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futs = []
        for i in range(concurrency * 3):
            futs.append(ex.submit(_worker, base, headers, kind, f"warm-{i}", rl))
        for f in as_completed(futs):
            f.result()
    # 正式计时
    latencies = []
    ok_cnt = 0
    total = 0
    stop = time.time() + duration
    with ThreadPoolExecutor(max_workers=concurrency) as ex:
        futs = []
        sid = 0
        while time.time() < stop:
            sid += 1
            futs.append(ex.submit(_worker, base, headers, kind, f"load-{sid}", rl))
            # 控制提交节奏：约等于并发数在途
            while len([f for f in futs if not f.done()]) >= concurrency * 2 and time.time() < stop:
                time.sleep(0.005)
        for f in as_completed(futs):
            ok, ms = f.result()
            total += 1
            if ok:
                ok_cnt += 1
            latencies.append(ms)
    qps = total / duration
    return {
        "concurrency": concurrency,
        "duration_s": duration,
        "total": total,
        "ok": ok_cnt,
        "fail": total - ok_cnt,
        "qps": round(qps, 1),
        "p50_ms": pct(latencies, 0.5),
        "p95_ms": pct(latencies, 0.95),
        "p99_ms": pct(latencies, 0.99),
    }


def run_llm_sampling(base, headers, count, rl=180):
    """阶段 B：LLM 全链路抽样（含大模型调用的 chat）"""
    results = []
    for i in range(count):
        start = time.perf_counter()
        try:
            resp = requests.post(f"{base}/api/agent/chat",
                                 data={"user_input": f"请用一句话介绍政务办事大厅的服务内容（压测第{i+1}次）",
                                       "session_id": f"perf-llm-{i}", "input_source": "user_input"},
                                 headers=headers, timeout=rl)
            ok = resp.status_code == 200
            results.append({"ok": ok, "ms": round((time.perf_counter() - start) * 1000, 1)})
        except Exception as e:
            results.append({"ok": False, "ms": round((time.perf_counter() - start) * 1000, 1), "err": str(e)[:100]})
    if results:
        ok_ms = [r["ms"] for r in results if r["ok"]]
        return {
            "total": len(results),
            "ok": len(ok_ms),
            "cold_start_ms": results[0]["ms"] if results else 0,
            "avg_ms": round(statistics.mean(ok_ms), 1) if ok_ms else 0,
            "p95_ms": pct(ok_ms, 0.95),
            "per_call": results,
        }
    return {"total": 0, "ok": 0, "cold_start_ms": 0, "avg_ms": 0, "p95_ms": 0, "per_call": []}


def run_accuracy_phase(base, headers, attack_samples, normal_samples):
    """阶段 C：检测准确率抽测。每样本独立 session_id（隔离会话风险累积）。"""
    def check(s, sess):
        try:
            r = requests.post(f"{base}/api/security/detect_single",
                              params={"text": s["text"], "source": s.get("source", "user_input"),
                                      "session_id": sess},
                              headers=headers, timeout=60)
            if r.status_code != 200:
                return None
            d = r.json()
            risk = (d.get("risk_level") or "none").lower()
            blocked = bool(d.get("is_blocked"))
            return {"risk": risk, "blocked": blocked,
                    "attack_type": (d.get("attack_type") or "").lower()}
        except Exception:
            return None

    fn = []   # 漏报：攻击样本未被拦截（risk 非 medium/high/critical 且未 blocked）
    fp = []   # 误报：正常样本被拦截
    fn_hits = 0
    fp_hits = 0
    for i, s in enumerate(attack_samples):
        res = check(s, f"acc-{i}")
        if res is None:
            continue
        blocked = res["blocked"] or res["risk"] in ("medium", "high", "critical")
        if not blocked:
            fn.append({"id": s.get("id"), "risk": res["risk"]})
        else:
            fn_hits += 1
    for i, s in enumerate(normal_samples):
        res = check(s, f"acc-n-{i}")
        if res is None:
            continue
        blocked = res["blocked"] or res["risk"] in ("medium", "high", "critical")
        if blocked:
            fp.append({"id": s.get("id"), "risk": res["risk"]})
        else:
            fp_hits += 1
    fn_total = fn_hits + len(fn)
    fp_total = fp_hits + len(fp)
    return {
        "attack_samples": fn_total,
        "fn_count": len(fn),
        "fn_rate": round(len(fn) / fn_total, 4) if fn_total else 0,
        "fn_detail": fn[:10],
        "normal_samples": fp_total,
        "fp_count": len(fp),
        "fp_rate": round(len(fp) / fp_total, 4) if fp_total else 0,
        "fp_detail": fp[:10],
    }


def load_samples():
    """从 audit/attack_samples.json 加载攻击/正常样本"""
    path = os.path.join(BASE, "audit", "attack_samples.json")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    samples = data.get("samples", [])
    attacks = [s for s in samples if s.get("is_attack")]
    normals = [s for s in samples if not s.get("is_attack")]
    # 按类型均匀取样（攻击样本跨类型覆盖）
    import random
    random.seed(42)
    by_type = {}
    for s in attacks:
        by_type.setdefault(s.get("expected_attack_type", "other"), []).append(s)
    picked = []
    for t in by_type:
        picked.extend(by_type[t][: max(1, FN_SAMPLE_CNT // max(1, len(by_type)))])
    if len(picked) < FN_SAMPLE_CNT:
        rest = [s for s in attacks if s not in picked]
        picked.extend(rest[: FN_SAMPLE_CNT - len(picked)])
    norm = random.sample(normals, min(NORMAL_SAMPLE_CNT, len(normals)))
    return picked[:FN_SAMPLE_CNT], norm


def main():
    ap = argparse.ArgumentParser(description="SafeAgent 性能压测 + 检测准确率抽测")
    ap.add_argument("--base-url", default="http://localhost:8080", help="后端地址")
    ap.add_argument("--username", default="admin", help="压测账号（建议 admin）")
    ap.add_argument("--password", default="admin123")
    ap.add_argument("--concurrency", nargs="+", type=int, default=[10, 20, 50], help="并发档位")
    ap.add_argument("--duration", type=int, default=15, help="每档压测秒数（建议 10-30，避免限流干扰）")
    ap.add_argument("--llm-samples", type=int, default=3, help="LLM 全链路抽样次数")
    ap.add_argument("--llm-off", action="store_true", help="跳过 LLM 抽样阶段")
    args = ap.parse_args()

    base = args.base_url.rstrip("/")
    print(f"[*] 压测目标: {base}  账号: {args.username}")
    token = login(base, args.username, args.password)
    headers = {"X-Auth-Token": token}
    print("[*] 登录成功，开始压测...\n")

    report = {
        "target": base,
        "account": args.username,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "stages": {},
    }

    # ---- 阶段 A ----
    print("[阶段 A] 本地链路并发压测")
    report["stages"]["A_local"] = {}
    for kind in ("detect", "audit", "dashboard"):
        report["stages"]["A_local"][kind] = []
        for c in args.concurrency:
            r = run_load_phase(base, headers, kind, c, args.duration)
            report["stages"]["A_local"][kind].append(r)
            print(f"  {kind:10s} 并发={c:3d}  QPS={r['qps']:8.1f}  p50={r['p50_ms']:7.1f}ms  "
                  f"p95={r['p95_ms']:7.1f}ms  p99={r['p99_ms']:7.1f}ms  ok={r['ok']}/{r['total']}")

    # ---- 阶段 B ----
    if args.llm_off:
        print("[阶段 B] 已跳过（--llm-off）")
        report["stages"]["B_llm"] = {"skipped": True}
    else:
        print(f"[阶段 B] LLM 全链路抽样（{args.llm_samples} 次，含冷启动）")
        r = run_llm_sampling(base, headers, args.llm_samples)
        report["stages"]["B_llm"] = r
        print(f"  总={r['total']} 成功={r['ok']} 冷启动={r['cold_start_ms']}ms "
              f"平均={r['avg_ms']}ms p95={r['p95_ms']}ms")

    # ---- 阶段 C ----
    print("[阶段 C] 检测准确率抽测（攻击样本 + 正常样本，独立会话）")
    attacks, normals = load_samples()
    print(f"  攻击样本 {len(attacks)} 条 / 正常样本 {len(normals)} 条")
    r = run_accuracy_phase(base, headers, attacks, normals)
    report["stages"]["C_accuracy"] = r
    print(f"  漏报率={r['fn_rate']*100:.2f}% ({r['fn_count']}/{r['attack_samples']})  "
          f"误报率={r['fp_rate']*100:.2f}% ({r['fp_count']}/{r['normal_samples']})")

    # ---- 输出 ----
    with open(OUT_JSON, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    render_md(report)
    print(f"\n[*] 报告已生成: {OUT_JSON} / {OUT_MD}")


def render_md(r):
    L = []
    L.append("# SafeAgent 性能压测与检测准确率报告")
    L.append("")
    L.append(f"- 目标：`{r['target']}`（账号 {r['account']}）")
    L.append(f"- 时间：{r['timestamp']}")
    L.append("")
    A = r["stages"].get("A_local", {})
    if A:
        L.append("## 一、本地链路并发压测")
        L.append("")
        L.append("| 接口 | 并发 | QPS | p50(ms) | p95(ms) | p99(ms) | 成功率 |")
        L.append("|---|---|---|---|---|---|---|")
        for kind, tiers in A.items():
            for t in tiers:
                name = {"detect": "安全检测 detect_single", "audit": "审计日志", "dashboard": "风险看板"}.get(kind, kind)
                L.append(f"| {name} | {t['concurrency']} | {t['qps']} | {t['p50_ms']} | {t['p95_ms']} | {t['p99_ms']} | "
                         f"{t['ok']}/{t['total']} |")
    B = r["stages"].get("B_llm", {})
    if B and not B.get("skipped"):
        L.append("")
        L.append("## 二、LLM 全链路抽样（含大模型调用）")
        L.append("")
        L.append(f"- 抽样 {B['total']} 次，成功 {B['ok']} 次")
        L.append(f"- 冷启动（首调用）：{B['cold_start_ms']} ms")
        L.append(f"- 平均耗时：{B['avg_ms']} ms；p95：{B['p95_ms']} ms")
    C = r["stages"].get("C_accuracy", {})
    if C:
        L.append("")
        L.append("## 三、检测准确率抽测")
        L.append("")
        L.append(f"- 攻击样本 {C['attack_samples']} 条，漏报 {C['fn_count']} 条，**漏报率 {C['fn_rate']*100:.2f}%**")
        L.append(f"- 正常样本 {C['normal_samples']} 条，误报 {C['fp_count']} 条，**误报率 {C['fp_rate']*100:.2f}%**")
        if C.get("fn_detail"):
            L.append("")
            L.append("漏报明细（前 10）：")
            for d in C["fn_detail"]:
                L.append(f"- `{d['id']}` → {d['risk']}")
        if C.get("fp_detail"):
            L.append("")
            L.append("误报明细（前 10）：")
            for d in C["fp_detail"]:
                L.append(f"- `{d['id']}` → {d['risk']}")
    L.append("")
    L.append("## 四、结论与说明")
    L.append("")
    L.append("- 本地链路（安全检测/审计/看板）不依赖外部 LLM，反映平台核心吞吐能力。")
    L.append("- LLM 全链路耗时取决于所选模型服务（在线 API / 私有化），受网络与模型负载影响。")
    L.append("- 检测准确率抽测每样本使用独立 session_id，避免会话风险累积导致的误关联。")
    L.append("- 多 worker 部署时 QPS 会随 worker 数近似线性提升。")
    with open(OUT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(L))


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"[!] 压测失败: {e}")
        sys.exit(1)
