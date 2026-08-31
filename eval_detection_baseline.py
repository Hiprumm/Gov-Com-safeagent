"""检测能力基线评估 — 用335个标注样例测真实准确率/误报率/漏报率"""
import json
import time
import requests
from collections import defaultdict

BASE = "http://localhost:8080"

def main():
    with open("audit/attack_samples.json", "r", encoding="utf-8") as f:
        data = json.load(f)
    samples = data["samples"]

    stats = {
        "total": len(samples),
        "attacks": 0,
        "normals": 0,
        "tp": 0,  # 攻击→正确识别为攻击
        "fn": 0,  # 攻击→漏报（识别为正常）
        "fp": 0,  # 正常→误报（识别为攻击）
        "tn": 0,  # 正常→正确识别为正常
        "by_type": defaultdict(lambda: {"total": 0, "detected": 0, "missed": 0}),
    }

    print(f"开始评估 {len(samples)} 个样例...")
    start = time.time()

    for i, s in enumerate(samples):
        if i % 50 == 0:
            print(f"  进度: {i}/{len(samples)}")

        text = s["text"]
        source = s.get("source", "user_input")
        is_attack = s["is_attack"]
        expected_type = s.get("expected_attack_type", "")

        # 清理会话
        sid = f"eval-{i}"
        try:
            r = requests.post(f"{BASE}/api/security/detect_single",
                              params={"text": text, "source": source, "session_id": sid},
                              timeout=25)
            d = r.json()
            risk = d.get("risk_level", "none")
            detected = risk not in ("none", "low")
        except Exception as e:
            print(f"  样例 {s['id']} 请求失败: {e}")
            detected = False
            risk = "error"

        # 清理
        try:
            requests.post(f"{BASE}/api/security/session_risk/clear/{sid}", timeout=2)
            requests.post(f"{BASE}/api/security/cross_source/clear/{sid}", timeout=2)
        except Exception:
            pass

        if is_attack:
            stats["attacks"] += 1
            stats["by_type"][expected_type]["total"] += 1
            if detected:
                stats["tp"] += 1
                stats["by_type"][expected_type]["detected"] += 1
            else:
                stats["fn"] += 1
                stats["by_type"][expected_type]["missed"] += 1
        else:
            stats["normals"] += 1
            if detected:
                stats["fp"] += 1
            else:
                stats["tn"] += 1

    elapsed = time.time() - start

    # 计算指标
    tp, fn, fp, tn = stats["tp"], stats["fn"], stats["fp"], stats["tn"]
    accuracy = (tp + tn) / stats["total"] if stats["total"] else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0  # 漏报率的反面
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    miss_rate = fn / (tp + fn) if (tp + fn) else 0  # 漏报率
    fp_rate = fp / (fp + tn) if (fp + tn) else 0     # 误报率

    print("\n" + "=" * 60)
    print("检测能力基线评估结果")
    print("=" * 60)
    print(f"总样例: {stats['total']}  (攻击: {stats['attacks']}, 正常: {stats['normals']})")
    print(f"耗时: {elapsed:.1f}s  ({elapsed/len(samples)*1000:.0f}ms/样例)")
    print()
    print(f"准确率 (Accuracy):  {accuracy*100:.1f}%  ({tp+tn}/{stats['total']})")
    print(f"精确率 (Precision): {precision*100:.1f}%  (攻击判定中正确的比例)")
    print(f"召回率 (Recall):    {recall*100:.1f}%  (攻击被识别的比例)")
    print(f"F1 Score:           {f1*100:.1f}%")
    print(f"漏报率 (Miss Rate): {miss_rate*100:.1f}%  ({fn}个攻击漏报)")
    print(f"误报率 (FP Rate):    {fp_rate*100:.1f}%  ({fp}个正常误报)")
    print()
    print("按攻击类型分布:")
    for atype, s in sorted(stats["by_type"].items(), key=lambda x: -x[1]["total"]):
        rate = s["detected"]/s["total"]*100 if s["total"] else 0
        print(f"  {atype:25s}: {s['total']:3d}个, 检出率 {rate:.1f}%, 漏报 {s['missed']}")

    # 保存结果
    result = {
        "total": stats["total"],
        "attacks": stats["attacks"],
        "normals": stats["normals"],
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "miss_rate": round(miss_rate, 4),
        "fp_rate": round(fp_rate, 4),
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "avg_latency_ms": round(elapsed/len(samples)*1000, 1),
        "by_type": {k: dict(v) for k, v in stats["by_type"].items()},
    }
    with open("detection_baseline_result.json", "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"\n结果已保存: detection_baseline_result.json")

if __name__ == "__main__":
    main()
