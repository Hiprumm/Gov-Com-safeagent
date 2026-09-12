# 验证材料目录（evidence）

本目录存放面向比赛提交的**可复现验证与导出材料**，均为从系统真实运行产物中导出。

## 材料清单

| 文件 | 说明 |
|------|------|
| `audit_log_sample.json` | **审计日志样例**：从运行库 `ai_service/data/safeagent.db` 导出的 50 条真实审计日志（含等保 2.0 审计要素、哈希链 `log_hash`/`prev_hash`、分级签名 `graded_*` 字段），覆盖 none/low/medium/high/critical 五级风险 |
| `evaluation_results.md` | **评测结果导出**：335 条攻击样本评测汇总（Accuracy/Precision/Recall/F1/误报率/漏报率、27 类攻击分型检测率、误报与漏报明细） |
| `attack_samples_index.md` | **攻击样例库索引**：335 条样例（275 攻击 / 60 正常）按输入来源与攻击类型的分布统计，及关键攻击类型示例 ID |
| `export_evidence.py` | 本目录导出脚本，修改 `BASE` 路径后可直接复用（幂等，可重复运行） |

## 数据来源

- 审计日志：`ai_service/data/safeagent.db` → 表 `audit_logs`（当前 8370 行）
- 评测报告：`ai_service/audit/evaluation_report.json`（`python run_evaluation.py` 产物）
- 攻击样例：`ai_service/audit/attack_samples.json`（335 条，覆盖 OWASP ASI 风险与政企四大场景）

## 重新导出

```bash
cd evidence
python export_evidence.py
```

> 注：审计日志样例随运行库增长而变化，提交前建议在**最终演示/测试完成后**再执行一次导出，确保样例为最新真实数据。

## 与评测指标的对应关系

- README 概览中的检测基线（准确率 98.5% / 漏报 1.5%）为**启用 LLM 语义仲裁**（智谱 GLM-4-Flash）的基准结果；
- `run_evaluation.py` 离线复现默认不加载 LLM 仲裁（模型不可用时规则引擎 + AI 检测器兜底），因此离线实测值（当前 accuracy 94.33% / F1 96.45%）低于 LLM 仲裁基线；
- 关键攻击类型（prompt_injection / jailbreak / combined_attack / data_exfiltration）的 **100% 检出目标**由「LLM 语义仲裁 + 规则引擎协同」保障，离线基线下 prompt_injection、data_leakage、memory_poisoning 等类型已稳定 100% 检出。
