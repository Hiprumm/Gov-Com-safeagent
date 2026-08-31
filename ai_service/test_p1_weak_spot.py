# -*- coding: utf-8 -*-
"""P1 弱项优化专项测试：
1. 第 8 轮基线 36 个漏报样本 → 新检测逻辑（rule_engine 新检测器 + memory_guard 加权）应拦截
2. 60 个正常样本 → 新检测器/加权零误报
"""
import json
import sys

sys.path.insert(0, ".")
from security.rule_engine import RuleEngine
from security.memory_guard import MemoryGuard
from models.schemas import RiskLevel

MISSED_IDS = {
    # 聚类1 公文篡改（P1-1 目标）
    "S-001", "S-003", "S-005", "S-023", "S-026",
    # 聚类3 虚假共识（P1-2 目标）
    "BP-002", "MC-001", "MC-002", "MC-006", "MC-008",
    # 聚类4 记忆投毒加权（P1-4 目标）
    "MC-013", "MC-017", "MC-025", "MC-027",
    # 聚类5 多工具外传链（P1-3 目标）
    "PL-018", "PL-023", "PL-027", "PL-031",
}

def main():
    with open("audit/attack_samples.json", "r", encoding="utf-8") as f:
        samples = json.load(f)["samples"]

    engine = RuleEngine()
    guard = MemoryGuard()

    # ---- 1. 目标漏报样本应被新逻辑拦截 ----
    passed, failed = [], []
    for s in samples:
        if s["id"] not in MISSED_IDS:
            continue
        text = s["text"]
        risk, atype, conf, _ = engine.detect_by_rules(text)
        mem = guard.check_before_write(text)
        rule_hit = risk in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)
        mem_hit = mem.is_poisoned and mem.confidence >= 0.45
        if rule_hit or mem_hit:
            src = "rule" if rule_hit else "memory"
            atype_s = atype.value if atype else "none"
            passed.append((s["id"], src, f"{risk.value}/{atype_s}/{conf:.2f}"))
        else:
            atype_s = atype.value if atype else "none"
            failed.append((s["id"], f"{risk.value}/{atype_s}/{conf:.2f}", f"mem={mem.confidence:.2f}"))

    # ---- 2. 正常样本零误报（新检测器 + memory 加权） ----
    fp_new = []
    for s in samples:
        if s["is_attack"]:
            continue
        text = s["text"]
        # 新 rule 检测器单独触发情况
        dt = engine._detect_issued_doc_tampering(text)
        fc = engine._detect_false_consensus(text)
        ec = engine._detect_tool_exfil_chain(text)
        new_hits = [n for n, r in (("公文篡改", dt), ("虚假共识", fc), ("外传链", ec)) if r[0] > 0]
        # memory 加权触发情况（写入∧高风险对象）
        mem = guard.check_before_write(text)
        mem_boost = mem.is_poisoned and mem.confidence >= 0.60 and any("P1-4" in e for e in mem.evidence)
        if new_hits or mem_boost:
            fp_new.append((s["id"], new_hits, mem_boost, text[:80]))

    # ---- 输出 ----
    print(f"== 目标漏报样本拦截（{len(MISSED_IDS)} 个）==")
    print(f"PASS {len(passed)} / {len(MISSED_IDS)}")
    for sid, src, detail in passed:
        print(f"  [OK] {sid} via {src}: {detail}")
    for sid, rule_d, mem_d in failed:
        print(f"  [MISS] {sid}: rule={rule_d}, {mem_d}")
    print(f"\n== 正常样本新检测器误报（应为 0）==")
    print(f"FP {len(fp_new)}")
    for sid, hits, mb, text in fp_new:
        print(f"  [FP] {sid} hits={hits} mem_boost={mb}: {text}")
    print(f"\nRESULT: {'ALL PASS' if not failed and not fp_new else 'HAS ISSUES'}")

if __name__ == "__main__":
    main()
