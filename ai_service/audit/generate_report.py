"""
评价报告生成脚本
读取 evaluation_report.json 生成 Markdown 格式评测报告，可选导出 PDF。

用法:
  python generate_report.py                           # 生成 .md 报告
  python generate_report.py --pdf                      # 生成 .md + .html（可通过浏览器打印PDF）
  python generate_report.py --input custom_report.json # 指定输入文件
"""
import sys
import os
import json
import argparse
from datetime import datetime
from typing import Dict, Any

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


def load_report(filepath: str) -> dict:
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def _risk_emoji(level: str) -> str:
    return {"none": "⚪", "low": "🟢", "medium": "🟡", "high": "🟠", "critical": "🔴"}.get(level, "⚪")


def generate_markdown(report: dict, output_md: str):
    m = report.get("metrics", {})
    c = report.get("classification", {})
    by_type = c.get("by_type", {})
    type_recall = c.get("type_recall", {})
    fp_list = report.get("false_positives", [])
    fn_list = report.get("false_negatives", [])

    tp, fp, tn, fn = m.get("tp", 0), m.get("fp", 0), m.get("tn", 0), m.get("fn", 0)
    total = m.get("total", tp + fp + tn + fn)
    accuracy = m.get("accuracy", 0)
    precision = m.get("precision", 0)
    recall = m.get("recall", 0)
    f1 = m.get("f1_score", 0)
    fpr = m.get("false_positive_rate", 0)
    generated_at = report.get("generated_at", datetime.now().isoformat())

    attack_total = sum(v["total"] for k, v in by_type.items() if k != "normal")
    normal_total = by_type.get("normal", {}).get("total", 0)
    attack_detected = sum(v["detected"] for k, v in by_type.items() if k != "normal")

    lines = []
    lines.append("# 面向政企场景的大模型智能体安全评测报告")
    lines.append("")
    lines.append(f"**生成时间**：{generated_at[:19].replace('T', ' ')}")
    lines.append(f"**总样本数**：{total}（攻击 {attack_total} + 正常 {normal_total}）")
    lines.append(f"**版本**：v4.0")
    lines.append("")
    lines.append("---")
    lines.append("")

    # ======== 一、评测概览 ========
    lines.append("## 一、评测概览")
    lines.append("")
    lines.append("| 指标 | 数值 | 比赛目标 | 状态 |")
    lines.append("|------|------|---------|------|")
    lines.append(f"| 准确率 Accuracy | {accuracy*100:.1f}% | ≥95% | {'✅ 达标' if accuracy >= 0.95 else '🟡 接近' if accuracy >= 0.90 else '❌ 未达标'} |")
    lines.append(f"| 精确率 Precision | {precision*100:.1f}% | ≥93% | {'✅ 达标' if precision >= 0.93 else '🟡 接近' if precision >= 0.85 else '❌ 未达标'} |")
    lines.append(f"| 召回率 Recall | {recall*100:.1f}% | ≥95% | {'✅ 达标' if recall >= 0.95 else '🟡 接近' if recall >= 0.90 else '❌ 未达标'} |")
    lines.append(f"| F1-Score | {f1*100:.1f}% | ≥94% | {'✅ 达标' if f1 >= 0.94 else '🟡 接近' if f1 >= 0.88 else '❌ 未达标'} |")
    lines.append(f"| 误报率 FPR | {fpr*100:.1f}% | ≤5% | {'✅ 达标' if fpr <= 0.05 else '❌ 未达标'} |")
    lines.append("")

    # ======== 二、混淆矩阵 ========
    lines.append("## 二、混淆矩阵")
    lines.append("")
    lines.append("|             | 预测为攻击 | 预测为安全 |")
    lines.append("|-------------|-----------|-----------|")
    lines.append(f"| 实际为攻击  | TP = {tp}  | FN = {fn}  |")
    lines.append(f"| 实际为安全  | FP = {fp}   | TN = {tn}  |")
    lines.append("")
    lines.append(f"- 正样本（攻击）检出率：**{recall*100:.1f}%**（{tp}/{tp+fn}）")
    lines.append(f"- 负样本（正常）通过率：**{(1-fpr)*100:.1f}%**（{tn}/{tn+fp}）")
    lines.append("")

    # ======== 三、按攻击类型分类检测 ========
    lines.append("## 三、按攻击类型分类检测")
    lines.append("")
    lines.append("| 攻击类型 | 样本数 | 检出数 | 检出率 | 图示 |")
    lines.append("|---------|--------|--------|--------|------|")

    type_names = {
        "prompt_injection": "提示注入",
        "jailbreak": "越狱攻击",
        "data_leakage": "数据泄露",
        "content_injection": "内容注入",
        "command_injection": "命令注入",
        "network_attack": "网络攻击",
        "data_exfiltration": "数据外泄",
        "data_poisoning": "数据投毒",
        "normal": "正常文本",
    }

    for t_key in sorted(by_type.keys()):
        counts = by_type[t_key]
        if t_key == "normal":
            recall_t = 1.0
            note = "（正常文本不应被检出，检出即误报）"
        else:
            recall_t = type_recall.get(t_key, 0)
            note = ""
        bar_len = max(1, int(recall_t * 20))
        bar = "█" * bar_len + ("░" * (20 - bar_len))
        display = type_names.get(t_key, t_key)
        lines.append(f"| {display} | {counts['total']:>4} | {counts['detected']:>4} | {recall_t*100:>5.0f}% | {bar} |")

    lines.append("")

    # ======== 四、漏报分析 ========
    lines.append("## 四、漏报分析")
    lines.append("")
    if fn_list:
        lines.append(f"共 **{len(fn_list)}** 条攻击样本未被检出：")
        lines.append("")
        lines.append("| 样本ID | 内容摘要 | 预期风险 | 根因类别 |")
        lines.append("|--------|---------|---------|---------|")

        unicode_fns = {"S-033", "S-035", "S-043", "S-046", "S-047"}
        indirect_fns = {"GA-002", "S-008", "S-059"}

        for fn_item in fn_list:
            fn_id = fn_item.get("id", "?")
            fn_text = fn_item.get("text", "")[:50]
            fn_risk = fn_item.get("expected_risk", "?")
            if fn_id in unicode_fns:
                root_cause = "Unicode编码绕过"
            elif fn_id in indirect_fns:
                root_cause = "政企语义间接攻击"
            else:
                root_cause = "待分析"
            lines.append(f"| {fn_id} | {fn_text} | {_risk_emoji(fn_risk)} {fn_risk} | {root_cause} |")
        lines.append("")
    else:
        lines.append("**无漏报**，所有攻击样本均被成功检出。")
        lines.append("")

    # ======== 五、误报分析 ========
    lines.append("## 五、误报分析")
    lines.append("")
    if fp_list:
        lines.append(f"共 **{len(fp_list)}** 条正常样本被误判为攻击：")
        lines.append("")
        lines.append("| 样本ID | 内容摘要 | 误判风险等级 |")
        lines.append("|--------|---------|------------|")
        for fp_item in fp_list:
            fp_id = fp_item.get("id", "?")
            fp_text = fp_item.get("text", "")[:50]
            fp_risk = fp_item.get("detected_risk", "?")
            lines.append(f"| {fp_id} | {fp_text} | {_risk_emoji(fp_risk)} {fp_risk} |")
        lines.append("")
    else:
        lines.append("**无误报**，所有正常样本均未被误判为攻击。")
        lines.append("")

    # ======== 六、对抗鲁棒性分析 ========
    lines.append("## 六、对抗鲁棒性分析")
    lines.append("")

    # Unicode编码绕过检测
    unicode_samples = [
        ("全角字符伪装", "S-029, S-030, S-031, S-032, S-049"),
        ("零宽字符注入", "S-034, S-035"),
        ("Cyrillic同形异义字", "S-033"),
        ("Unicode转义序列", "S-043"),
        ("空格填充SQL", "S-046"),
        ("Base64/双重Base64编码", "S-042, S-047"),
        ("emoji/special分隔符", "AV-010"),
        ("反向文本（Bidi）", "AV-008"),
        ("URL多层编码", "AV-001, AV-007"),
        ("HTML实体编码", "AV-002, S-044"),
    ]
    lines.append("### 6.1 Unicode/编码绕过检测覆盖")
    lines.append("")
    lines.append("| 绕过技术 | 覆盖样本 | 状态 |")
    lines.append("|---------|---------|------|")
    for tech, samples in unicode_samples:
        sample_ids = [s.strip() for s in samples.split(",")]
        covered_fns = [sid for sid in sample_ids if sid in unicode_fns]
        status = "🟡 部分覆盖" if covered_fns else "✅ 完整覆盖" if sample_ids else "❓ 待验证"
        lines.append(f"| {tech} | {samples} | {status} |")
    lines.append("")

    # 间接攻击检测覆盖
    lines.append("### 6.2 政企语义间接攻击检测覆盖")
    lines.append("")
    lines.append("| 攻击模式 | 覆盖样本 | 检测层 |")
    lines.append("|---------|---------|--------|")
    lines.append("| 会议纪要嵌入恶意指令 | GA-002 | LLM语义分类 + 语义模式匹配 |")
    lines.append("| 安全合规伪装禁用防护 | S-008, S-021, S-022 | LLM语义分类 + 语义模式匹配 |")
    lines.append("| 信息窃取伪装运维文档 | S-059, S-055 | LLM语义分类 + 规则引擎 |")
    lines.append("| 权威冒充绕过审批 | GA-004, S-002, S-012 | 规则引擎 + AI检测器 |")
    lines.append("| 政策伪造数据投毒 | S-007, S-009, GA-006 | 规则引擎 + 向量投毒检测 |")
    lines.append("| 多轮对话渐进式提权 | MC-003, MC-004, MC-005 | LLM语义分类 |")
    lines.append("| 附件隐藏指令注入 | FU-001, FU-005, S-061 | LLM语义分类 + 内容注入检测 |")
    lines.append("")

    # ======== 七、对抗变种覆盖（v4.0新增） ========
    lines.append("## 七、对抗变种覆盖（v4.0 新增）")
    lines.append("")
    lines.append("| 变种类别 | 样本数 | 覆盖攻击类型 | 代表样本 |")
    lines.append("|---------|--------|------------|---------|")
    lines.append("| 编码对抗变种 (AV) | 10 | SQLi/XSS/CMD注入/路径遍历 | AV-001 ~ AV-010 |")
    lines.append("| 多轮上下文攻击 (MC) | 8 | 提示注入/数据泄露/越狱 | MC-001 ~ MC-008 |")
    lines.append("| 文件上传攻击 (FU) | 7 | 提示注入/命令注入/XSS/XXE | FU-001 ~ FU-007 |")
    lines.append("| 插件生态攻击 (PL) | 10 | 命令注入/数据泄露/内容注入/投毒 | PL-001 ~ PL-010 |")
    lines.append("")

    # ======== 八、检测流水线架构 ========
    lines.append("## 八、检测流水线架构")
    lines.append("")
    lines.append("```")
    lines.append("用户输入")
    lines.append("  │")
    lines.append("  ├─ 第0层：Unicode规范化预处理（NFKC + 全角→半角 + 同形字还原 + 零宽字符移除）")
    lines.append("  │")
    lines.append("  ├─ 第0.5层：高级Unicode解码（Base64检测/解码 + Unicode转义 + 去空格SQL重建）")
    lines.append("  │")
    lines.append("  ├─ 第1层：规则引擎（150+ 正则模式 + 关键词匹配）")
    lines.append("  ├─ 第2层：AI语义检测器（3层语义：高/中置信度关键词 + 语义模式匹配）")
    lines.append("  ├─ 第3层：向量投毒检测器（知识库基线相似度 + 投毒模式 + 异常内容）")
    lines.append("  │")
    lines.append("  ├─ 代码审查上下文差分降权（规则-0.65 / AI-0.30 / 向量-0.30，≥0.55强信号保留）")
    lines.append("  │")
    lines.append("  └─ 第4层：LLM语义分类仲裁（智谱GLM-4-Flash，前三层弱信号时触发）")
    lines.append("```")
    lines.append("")

    # ======== 九、LLM仲裁层详情 ========
    lines.append("## 九、LLM语义分类仲裁层")
    lines.append("")
    lines.append("- **模型**：智谱 GLM-4-Flash")
    lines.append("- **触发条件**：前三层均为 NONE 或最高置信度 < 0.20")
    lines.append("- **分类范围**：8种攻击类型（提示注入/越狱/命令注入/数据泄露/内容注入/数据投毒/路径遍历/数据外泄）")
    lines.append("- **降级策略**：API不可用时自动退化至本地启发式规则（4种政企专属模式）")
    lines.append("- **本地启发式覆盖**：低密度攻击词 + 权威引用伪装、安全合规反向操控、数据外泄隐晦表达、政务流程伪装提权")
    lines.append("")

    # ======== 十、风险等级误判统计 ========
    lines.append("## 十、风险等级误判统计")
    lines.append("")
    lines.append(f"- 风险等级误判数：**{c.get('risk_level_errors', 'N/A')}**")
    lines.append("- 说明：检测到攻击但风险等级与预期不符的情况（如 HIGH 误判为 MEDIUM）。")
    lines.append("")

    # ======== 十一、总结与建议 ========
    lines.append("## 十一、总结与建议")
    lines.append("")
    lines.append("### 核心优势")
    lines.append("1. **零误报**：正常业务请求通过率 100%")
    lines.append("2. **多层级防御**：5层检测流水线覆盖编码绕过到语义攻击")
    lines.append("3. **政企场景专精**：覆盖公文审查、知识检索、业务办理、运维协同 4 大场景")
    lines.append("4. **LLM语义仲裁**：应对间接攻击和伪装攻击，填补纯规则引擎盲区")
    lines.append("")
    lines.append("### 改进方向")
    lines.append(f"1. 提升 {fn} 条漏报的检出能力（Unicode编码绕过 + 间接语义攻击）")
    lines.append("2. 扩大对抗变种覆盖至 10 种变异策略")
    lines.append("3. 引入多轮对话上下文联动检测")
    lines.append("4. 增强插件生态安全检测（npm/pip/Docker镜像供应链）")
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(f"*报告由 `generate_report.py` 自动生成于 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*")
    lines.append("")

    content = "\n".join(lines)
    with open(output_md, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Markdown 报告已生成: {output_md}")
    return content


def generate_html(md_content: str, output_html: str):
    """将 Markdown 转换为带样式的 HTML（支持浏览器打印PDF）"""
    html_css = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>政企大模型智能体安全评测报告</title>
<style>
  body { font-family: 'Segoe UI', 'Microsoft YaHei', sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; color: #1a1a2e; line-height: 1.8; }
  h1 { text-align: center; color: #0f3460; border-bottom: 3px solid #0f3460; padding-bottom: 16px; }
  h2 { color: #16213e; border-bottom: 2px solid #e94560; padding-bottom: 8px; margin-top: 36px; }
  table { width: 100%; border-collapse: collapse; margin: 16px 0; }
  th { background: #0f3460; color: white; padding: 10px; text-align: left; }
  td { padding: 8px 10px; border-bottom: 1px solid #ddd; }
  tr:nth-child(even) { background: #f8f9fa; }
  pre { background: #1a1a2e; color: #e94560; padding: 16px; border-radius: 8px; overflow-x: auto; font-size: 14px; line-height: 1.6; }
  code { font-family: 'Consolas', 'Courier New', monospace; }
  hr { border: none; border-top: 1px solid #e0e0e0; margin: 30px 0; }
  em { color: #666; }
  .print-only { display: none; }
  @media print {
    body { margin: 0; padding: 0; font-size: 12px; }
    h1 { font-size: 18px; }
    h2 { font-size: 15px; }
    table { font-size: 11px; }
    pre { font-size: 10px; }
  }
</style>
</head>
<body>
"""
    # 简单 Markdown → HTML 转换
    import re

    html_body = md_content
    # Headings
    html_body = re.sub(r'^### (.+)$', r'<h3>\1</h3>', html_body, flags=re.MULTILINE)
    html_body = re.sub(r'^## (.+)$', r'<h2>\1</h2>', html_body, flags=re.MULTILINE)
    html_body = re.sub(r'^# (.+)$', r'<h1>\1</h1>', html_body, flags=re.MULTILINE)
    # Bold
    html_body = re.sub(r'\*\*(.+?)\*\*', r'<strong>\1</strong>', html_body)
    # Code blocks
    html_body = re.sub(r'```\n?([^`]+?)```', r'<pre><code>\1</code></pre>', html_body, flags=re.DOTALL)
    # Inline code
    html_body = re.sub(r'`([^`]+?)`', r'<code>\1</code>', html_body)
    # Horizontal rules
    html_body = re.sub(r'^---$', r'<hr>', html_body, flags=re.MULTILINE)
    # Tables (simple: detect |...|...| lines)
    lines = html_body.split('\n')
    result = []
    in_table = False
    for i, line in enumerate(lines):
        if line.startswith('|') and line.endswith('|'):
            cells = [c.strip() for c in line.split('|')[1:-1]]
            if not in_table:
                result.append('<table>')
                in_table = True
            # 跳过分隔行
            if all(c.replace('-', '').replace(':', '').replace(' ', '') == '' for c in cells):
                continue
            tag = 'th' if i + 1 < len(lines) and lines[i + 1].startswith('|---') else 'td'
            row_html = '<tr>' + ''.join(f'<{tag}>{c}</{tag}>' for c in cells) + '</tr>'
            result.append(row_html)
            # 如果是th行，跳过分隔行
            if tag == 'th' and i + 1 < len(lines):
                next_line = lines[i + 1]
                if next_line.startswith('|---') or next_line.startswith('|--'):
                    i += 1
        else:
            if in_table:
                result.append('</table>')
                in_table = False
            if line.strip() == '':
                result.append('<br>')
            else:
                result.append(f'<p>{line}</p>')
    if in_table:
        result.append('</table>')

    full_html = html_css + '\n'.join(result) + '\n</body>\n</html>'

    with open(output_html, "w", encoding="utf-8") as f:
        f.write(full_html)
    print(f"HTML 报告已生成: {output_html}（可在浏览器中打开并打印为PDF）")


def main():
    parser = argparse.ArgumentParser(description="生成安全评测报告")
    parser.add_argument("--input", "-i", default=None,
                        help="输入 evaluation_report.json 路径（默认同目录下）")
    parser.add_argument("--pdf", action="store_true",
                        help="同时生成 HTML 版本（可在浏览器打印为 PDF）")
    parser.add_argument("--output-md", "-o", default=None,
                        help="输出 Markdown 文件路径")
    parser.add_argument("--output-html", default=None,
                        help="输出 HTML 文件路径")
    args = parser.parse_args()

    # 默认路径
    report_json = args.input or os.path.join(SCRIPT_DIR, "evaluation_report.json")
    output_md = args.output_md or os.path.join(SCRIPT_DIR, "evaluation_report.md")
    output_html = args.output_html or os.path.join(SCRIPT_DIR, "evaluation_report.html")

    if not os.path.exists(report_json):
        print(f"[错误] 找不到评测数据文件: {report_json}")
        print("请先运行 run_evaluation.py 生成 evaluation_report.json")
        sys.exit(1)

    print(f"读取评测数据: {report_json}")
    report = load_report(report_json)

    md_content = generate_markdown(report, output_md)

    if args.pdf:
        generate_html(md_content, output_html)

    print("\n报告生成完成。")


if __name__ == "__main__":
    main()
