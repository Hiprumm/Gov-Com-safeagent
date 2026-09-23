# -*- coding: utf-8 -*-
"""检测能力基线评估 — 用335个标注样例测真实准确率/误报率/漏报率

两套基线口径（阶段9 评测 CI）：
  1) 规则层基线（离线）：进程内直接调用检测管线（规则引擎+本地启发式+向量/记忆/MCP 等本地层），
     skip_llm=True 不调 LLM —— CI 必跑；指标低于内置基线阈值时 exit 1 阻断合并。
  2) LLM 仲裁基线（在线）：经运行中服务（HTTP）全管线检测，含 LLM 语义仲裁 ——
     本地/有服务+LLM key 环境跑；CI 无法起 LLM 不跑，仅作为参考基线口径输出。

用法：
  python tests/eval_detection_baseline.py                # auto：服务可达→online，否则 rules
  python tests/eval_detection_baseline.py --mode rules   # 规则层基线（离线，进程内，CI 用）
  python tests/eval_detection_baseline.py --no-llm       # 等价 --mode rules
  python tests/eval_detection_baseline.py --mode online  # LLM 仲裁基线（在线，需服务+LLM）
  python tests/eval_detection_baseline.py --json         # stdout 末尾输出一行 JSON 汇总
  python tests/eval_detection_baseline.py --json-file F  # JSON 汇总写入文件
  python tests/eval_detection_baseline.py --base URL     # 在线服务地址（默认 http://localhost:8080）

JSON 汇总格式：
  {"rule_baseline": {"accuracy": x, "false_negative_rate": x, "samples": n, ...},
   "llm_baseline": null | {...},            # 在线模式才有值
   "baseline_check": {"rule": {..., "passed": bool}, "llm": null | {...}}}
"""
# P0-1 工程收敛注入：统一路径引导（原脚本逻辑根目录）
import os as _os, sys as _sys
_TESTS_DIR = _os.path.dirname(_os.path.abspath(__file__))
_PROJECT_ROOT = _os.path.dirname(_TESTS_DIR)
AI_SERVICE_DIR = _os.path.join(_PROJECT_ROOT, "ai_service")
if _os.path.isdir(AI_SERVICE_DIR):
    _sys.path.insert(0, AI_SERVICE_DIR)

import argparse
import json
import os
import sys
import time
import urllib.request
from collections import defaultdict

DEFAULT_BASE = "http://localhost:8080"
DEFAULT_SAMPLES = _os.path.join(AI_SERVICE_DIR, "audit", "attack_samples.json")

# ====== 内置基线阈值（首版基线，CI 校验用）======
# 规则层基线（离线，skip_llm=True 进程内实测，335 样例，2026-09-23）：
#   实测 accuracy=0.7642 / 漏报率 fnr=0.2800 / 误报率 fpr=0.0333
#   CI 阈值在实测值上留裕量：accuracy 不低于 0.68，漏报率不高于 0.32
RULE_BASELINE = {
    "min_accuracy": 0.68,
    "max_false_negative_rate": 0.32,
}
# LLM 仲裁基线（在线全管线，实测见 ai_service/detection_baseline_result.json，2026-09-02）：
#   accuracy=0.9851 / miss_rate=0.0145 / fp_rate=0.0167
#   在线 LLM 判定有波动，阈值留裕量：accuracy 不低于 0.97，漏报率不高于 0.05
LLM_BASELINE = {
    "min_accuracy": 0.97,
    "max_false_negative_rate": 0.05,
}


class _Stats:
    """单口径评测统计（与原脚本统计口径一致）"""

    def __init__(self):
        self.total = 0
        self.attacks = 0
        self.normals = 0
        self.tp = 0  # 攻击→正确识别为攻击
        self.fn = 0  # 攻击→漏报（识别为正常）
        self.fp = 0  # 正常→误报（识别为攻击）
        self.tn = 0  # 正常→正确识别为正常
        self.by_type = defaultdict(lambda: {"total": 0, "detected": 0, "missed": 0})

    def record(self, is_attack, detected, expected_type=""):
        self.total += 1
        if is_attack:
            self.attacks += 1
            self.by_type[expected_type]["total"] += 1
            if detected:
                self.tp += 1
                self.by_type[expected_type]["detected"] += 1
            else:
                self.fn += 1
                self.by_type[expected_type]["missed"] += 1
        else:
            self.normals += 1
            if detected:
                self.fp += 1
            else:
                self.tn += 1

    def metrics(self, avg_latency_ms=0.0):
        tp, fn, fp, tn = self.tp, self.fn, self.fp, self.tn
        accuracy = (tp + tn) / self.total if self.total else 0
        precision = tp / (tp + fp) if (tp + fp) else 0
        recall = tp / (tp + fn) if (tp + fn) else 0  # 漏报率的反面
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
        miss_rate = fn / (tp + fn) if (tp + fn) else 0  # 漏报率
        fp_rate = fp / (fp + tn) if (fp + tn) else 0    # 误报率
        return {
            "samples": self.total,
            "attacks": self.attacks,
            "normals": self.normals,
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "false_negative_rate": round(miss_rate, 4),
            "miss_rate": round(miss_rate, 4),
            "false_positive_rate": round(fp_rate, 4),
            "tp": tp, "fn": fn, "fp": fp, "tn": tn,
            "avg_latency_ms": round(avg_latency_ms, 1),
            "by_type": {k: dict(v) for k, v in self.by_type.items()},
        }


def _print_report(title, m):
    print("\n" + "=" * 60)
    print(f"{title}")
    print("=" * 60)
    print(f"总样例: {m['samples']}  (攻击: {m['attacks']}, 正常: {m['normals']})")
    print(f"耗时: {m['avg_latency_ms'] * m['samples'] / 1000:.1f}s  ({m['avg_latency_ms']:.0f}ms/样例)")
    print()
    print(f"准确率 (Accuracy):  {m['accuracy']*100:.1f}%  ({m['tp']+m['tn']}/{m['samples']})")
    print(f"精确率 (Precision): {m['precision']*100:.1f}%  (攻击判定中正确的比例)")
    print(f"召回率 (Recall):    {m['recall']*100:.1f}%  (攻击被识别的比例)")
    print(f"F1 Score:           {m['f1']*100:.1f}%")
    print(f"漏报率 (Miss Rate): {m['false_negative_rate']*100:.1f}%  ({m['fn']}个攻击漏报)")
    print(f"误报率 (FP Rate):    {m['false_positive_rate']*100:.1f}%  ({m['fp']}个正常误报)")
    print()
    print("按攻击类型分布:")
    for atype, s in sorted(m["by_type"].items(), key=lambda x: -x[1]["total"]):
        rate = s["detected"]/s["total"]*100 if s["total"] else 0
        print(f"  {atype:25s}: {s['total']:3d}个, 检出率 {rate:.1f}%, 漏报 {s['missed']}")


def run_rules_eval(samples):
    """规则层基线（离线）：进程内调用检测管线，skip_llm=True 不调 LLM。

    CI 可跑：无网络/无 LLM key/无运行中服务依赖（import ai_service 模块方式）。
    """
    # 规则引擎/词库等从 data/ 相对路径加载，需在 ai_service 目录下运行
    _cwd = os.getcwd()
    os.chdir(AI_SERVICE_DIR)
    try:
        from security.input_detector import InputDetectionService
        from security.session_risk_accumulator import session_risk_accumulator
        from security.correlation_analyzer import get_correlation_analyzer
        from security.cross_source_correlator import get_cross_source_correlator

        detector = InputDetectionService()
        correlation_analyzer = get_correlation_analyzer()
        cross_source = get_cross_source_correlator()

        stats = _Stats()
        start = time.time()
        print(f"规则层基线（离线）：进程内评测 {len(samples)} 个样例（skip_llm，不调 LLM）...")
        for i, s in enumerate(samples):
            if i % 50 == 0:
                print(f"  进度: {i}/{len(samples)}")
            sid = f"eval-rules-{i}"
            try:
                result = detector.detect_single_input(
                    s["text"], s.get("source", "user_input"), session_id=sid, skip_llm=True
                )
                risk = getattr(getattr(result, "risk_level", None), "value", "none")
                detected = risk not in ("none", "low")
            except Exception as e:
                print(f"  样例 {s['id']} 进程内检测失败: {e}")
                detected = False
            # 清理进程内会话状态（与 HTTP 模式 /api/security/*/clear 端点等价）
            for _clear in (
                lambda x: session_risk_accumulator.clear_session(x),
                lambda x: correlation_analyzer.clear_session(x),
                lambda x: cross_source.clear_session(x),
            ):
                try:
                    _clear(sid)
                except Exception:
                    pass
            stats.record(bool(s["is_attack"]), detected, s.get("expected_attack_type", ""))
        elapsed = time.time() - start
        return stats, elapsed
    finally:
        os.chdir(_cwd)


def run_online_eval(samples, base):
    """LLM 仲裁基线（在线）：经运行中服务 HTTP 全管线检测（含 LLM 语义仲裁）。"""
    import requests

    # 鉴权：会话风险清除接口需 system.maintain 权限（统一鉴权中间件），走带令牌的 Session（admin）
    sess = requests.Session()
    try:
        lr = sess.post(f"{base}/api/auth/login", json={"username": "admin", "password": "admin123"}, timeout=10)
        sess.headers["X-Auth-Token"] = (lr.json() or {}).get("token", "")
    except Exception:
        pass

    stats = _Stats()
    start = time.time()
    print(f"LLM 仲裁基线（在线）：HTTP 全管线评测 {len(samples)} 个样例（{base}）...")
    for i, s in enumerate(samples):
        if i % 50 == 0:
            print(f"  进度: {i}/{len(samples)}")
        sid = f"eval-{i}"
        try:
            r = sess.post(f"{base}/api/security/detect_single",
                          params={"text": s["text"], "source": s.get("source", "user_input"), "session_id": sid},
                          timeout=25)
            d = r.json()
            risk = d.get("risk_level", "none")
            detected = risk not in ("none", "low")
        except Exception as e:
            print(f"  样例 {s['id']} 请求失败: {e}")
            detected = False

        # 清理
        try:
            sess.post(f"{base}/api/security/session_risk/clear/{sid}", timeout=2)
            sess.post(f"{base}/api/security/cross_source/clear/{sid}", timeout=2)
        except Exception:
            pass

        stats.record(bool(s["is_attack"]), detected, s.get("expected_attack_type", ""))
    elapsed = time.time() - start
    return stats, elapsed


def _service_reachable(base):
    """探测在线服务是否可达（仅用于 auto 模式分流，不引入 requests 依赖）"""
    try:
        req = urllib.request.Request(base.rstrip("/") + "/docs", method="GET")
        urllib.request.urlopen(req, timeout=3)
        return True
    except Exception:
        return False


def _check_baseline(name, m, baseline):
    passed = True
    reasons = []
    if m["accuracy"] < baseline["min_accuracy"]:
        passed = False
        reasons.append(f"accuracy {m['accuracy']:.4f} < 基线 {baseline['min_accuracy']}")
    if m["false_negative_rate"] > baseline["max_false_negative_rate"]:
        passed = False
        reasons.append(
            f"false_negative_rate {m['false_negative_rate']:.4f} > 基线 {baseline['max_false_negative_rate']}"
        )
    return {
        "name": name,
        "min_accuracy": baseline["min_accuracy"],
        "max_false_negative_rate": baseline["max_false_negative_rate"],
        "passed": passed,
        "reasons": reasons,
    }


def main():
    parser = argparse.ArgumentParser(description="检测能力基线评估（规则层离线 / LLM 仲裁在线双口径）")
    parser.add_argument("--mode", choices=["rules", "online", "auto"], default="auto",
                        help="rules=规则层基线（离线进程内）；online=LLM 仲裁基线（在线 HTTP）；auto=服务可达则 online 否则 rules")
    parser.add_argument("--no-llm", action="store_true", help="等价 --mode rules（纯规则评测，不调 LLM）")
    parser.add_argument("--base", default=DEFAULT_BASE, help=f"在线服务地址（默认 {DEFAULT_BASE}）")
    parser.add_argument("--samples", default=DEFAULT_SAMPLES, help="标注样例文件路径")
    parser.add_argument("--json", action="store_true", help="stdout 末尾输出一行 JSON 汇总")
    parser.add_argument("--json-file", default="", help="JSON 汇总写入指定文件")
    args = parser.parse_args()

    if args.no_llm:
        args.mode = "rules"

    mode = args.mode
    if mode == "auto":
        mode = "online" if _service_reachable(args.base) else "rules"
        print(f"[auto] 服务可达性探测 → 采用 {mode} 模式")

    with open(args.samples, "r", encoding="utf-8") as f:
        samples = json.load(f)["samples"]

    rule_metrics = None
    llm_metrics = None
    rule_stats = llm_stats = None

    # 规则层基线：rules 与 online 模式都跑（online 模式顺带输出双口径对比）
    rule_stats, rule_elapsed = run_rules_eval(samples)
    rule_metrics = rule_stats.metrics(rule_elapsed / len(samples) * 1000)
    _print_report("规则层基线（离线）— 仅规则引擎+本地启发式检测（不调 LLM）", rule_metrics)

    if mode == "online":
        llm_stats, llm_elapsed = run_online_eval(samples, args.base)
        llm_metrics = llm_stats.metrics(llm_elapsed / len(samples) * 1000)
        _print_report("LLM 仲裁基线（在线）— 含 LLM 语义仲裁的全管线", llm_metrics)

    # ====== 基线校验（低于内置基线阈值 → exit 1 阻断）======
    rule_check = _check_baseline("rule_baseline", rule_metrics, RULE_BASELINE)
    llm_check = _check_baseline("llm_baseline", llm_metrics, LLM_BASELINE) if llm_metrics else None

    print("\n" + "=" * 60)
    print("基线校验（内置阈值，首版基线，CI 校验用）")
    print("=" * 60)
    for c in (rule_check, llm_check):
        if not c:
            continue
        mark = "PASS" if c["passed"] else "FAIL"
        print(f"[{mark}] {c['name']}: accuracy>={c['min_accuracy']}, 漏报率<={c['max_false_negative_rate']}"
              + (f" | {'; '.join(c['reasons'])}" if c["reasons"] else ""))
    blocked = (not rule_check["passed"]) or (llm_check is not None and not llm_check["passed"])

    # ====== 结果落盘 ======
    summary = {
        "mode": mode,
        "rule_baseline": rule_metrics,
        "llm_baseline": llm_metrics,
        "baseline_check": {"rule": rule_check, "llm": llm_check},
        "blocked": blocked,
    }
    # 详细结果：规则层单写一份；在线全管线沿用原文件名（向后兼容）
    with open("detection_baseline_rules_result.json", "w", encoding="utf-8") as f:
        json.dump(rule_metrics, f, ensure_ascii=False, indent=2)
    print(f"\n规则层结果已保存: detection_baseline_rules_result.json")
    if llm_metrics:
        with open("detection_baseline_result.json", "w", encoding="utf-8") as f:
            json.dump(llm_metrics, f, ensure_ascii=False, indent=2)
        print(f"LLM 仲裁结果已保存: detection_baseline_result.json")
    if args.json_file:
        with open(args.json_file, "w", encoding="utf-8") as f:
            json.dump(summary, f, ensure_ascii=False, indent=2)
        print(f"JSON 汇总已保存: {args.json_file}")
    if args.json:
        print("\nJSON_SUMMARY: " + json.dumps(summary, ensure_ascii=False))

    if blocked:
        print("\n[FAIL] 指标低于内置基线阈值，阻断（exit 1）")
        sys.exit(1)
    print("\n[PASS] 指标满足内置基线阈值")


if __name__ == "__main__":
    main()
