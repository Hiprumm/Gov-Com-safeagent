# -*- coding: utf-8 -*-
"""
拟稿工作流 worker（面向政企的公文/通知起草助手）
==============================================
`draft_document` 工具的真实本地实现：
1. 依据文种与主题，从政务沙盒知识库检索公文规范/内部制度等依据
2. 组装起草提示词，调用配置中的对话模型（智谱 / 内网 OpenAI 兼容端点，随「系统状态-模型接入」热生效）
3. 模型不可用时降级为基于检索依据的模板化起草

返回：一份可读公文草稿（含标题层级、正文要点、落款与拟稿日期），并附 AIGC 生成标识。
"""
from __future__ import annotations

import re
import time
import logging

logger = logging.getLogger("doc_worker")

# 不同文种对应的起草要点（关键字段提示模型，避免自由发挥跑偏）
DOC_TYPE_GUIDES = {
    "通知": "格式：标题+主送单位+正文（缘由、事项、要求、时限）+特此通知+落款。语言简洁、要求明确。",
    "请示": "格式：标题（关于…的请示）+主送上级+正文（缘由、拟办事项、请示意见）+妥否请批示+落款。一文一事。",
    "报告": "格式：标题+主送+正文（工作情况、成效、问题、下一步打算）+专此报告+落款。以陈述为主。",
    "函": "格式：标题+主送对方单位+正文（商洽/询问/答复事项）+盼复+落款。语气对等协商。",
    "纪要": "格式：会议时间地点参会人+议定事项（分条列出+责任部门+时限）。只记议定，不记过程发言。",
    "简报": "格式：报头+标题+正文（背景、做法、成效）+报送范围。突出干货与数据。",
    "公开信": "格式：称呼+正文（倡议/说明，分条易于阅读）+落款。语气亲切平实。",
    "工作汇报": "格式：标题+正文（进展/数据/问题/下一步）+结语。以数据说话，分点陈述。",
}


def _retrieve_basis(doc_type: str, subject: str) -> list:
    """检索起草依据（公文规范/内部制度等语料）。"""
    try:
        from knowledge.rag_engine import get_kb
        kb = get_kb()
        queries = []
        if doc_type:
            queries.append(f"{doc_type} 格式规范")
        if subject:
            queries.append(subject)
        queries.append("机关内部办公流程 公文")
        seen, basis = set(), []
        for q in queries:
            for h in kb.search(q, k=3, min_score=0.42):
                key = h["text"][:40]
                if key in seen:
                    continue
                seen.add(key)
                basis.append(h)
                if len(basis) >= 5:
                    return basis
        return basis
    except Exception as e:  # noqa: BLE001
        logger.warning("拟稿依据检索失败: %s", e)
        return []


def _fmt_basis(basis: list) -> str:
    if not basis:
        return "（知识库未检索到相关依据，按通用公文规范起草）"
    parts = []
    for h in basis:
        snippet = h["text"].strip().replace("\n", " ")
        parts.append(f"- {snippet[:260]}")
    return "\n".join(parts)


def _llm_draft(prompt: str) -> str | None:
    try:
        from llm_runtime import load_config
        from llm_providers import build_chat_model
        model = build_chat_model(load_config())
        if model is None:
            return None
        from langchain_core.messages import HumanMessage
        reply = model.invoke([HumanMessage(content=prompt)])
        text = reply.content if hasattr(reply, "content") else str(reply)
        return text.strip() if isinstance(text, str) else str(text).strip()
    except Exception as e:  # noqa: BLE001
        logger.warning("LLM 起草失败，将降级为模板起草: %s", e)
        return None


def _clean_subject(subject: str, doc_type: str) -> str:
    """把可能已带「关于…的<文种>」/完整标题的主题规整为主题短语，避免“关于关于…的通知的通知”叠加"""
    s = subject.strip()
    # 若主题已形如「关于X的<文种>」，去掉外层文种后缀，保留“关于X”
    if doc_type and re.search(rf"的{re.escape(doc_type)}", s):
        s = re.sub(rf"的{re.escape(doc_type)}$", "", s).strip()
    # 去掉标题开头的“关于”，后续统一补“关于…”
    if s.startswith("关于"):
        s = s[2:].strip()
    return s


def _template_draft(doc_type: str, subject: str, outline: str) -> str:
    """模型不可用时的模板化起草（结构规范，供人工完善）"""
    topic = _clean_subject(subject, doc_type)
    title = f"关于{topic}的{doc_type or '通知'}"
    lines = [title, "", "各有关单位（部门）：", ""]

    points = [p for p in re.split(r"[\n;；、,，]+", outline) if p.strip()] if outline else []
    # 去掉“一是/1.”等序号残留
    points = [re.sub(r"^(一是|二是|三是|四是|五是|六是|\d+[.、])\s*", "", p).strip() for p in points]
    points = [p for p in points if p]

    if points:
        lines.append(f"为进一步规范{topic}相关工作，现将有关事项通知如下：")
        lines.append("")
        for i, pt in enumerate(points, 1):
            lines.append(f"{i}. {pt}")
        lines.append("")
        lines.append("请各部门结合实际认真抓好落实，执行中如有问题请及时反馈办公室。")
    else:
        lines.append(f"现就{topic}有关工作安排通知如下，请遵照执行，并及时反馈落实情况。")

    lines += [
        "",
        "（说明：本文件由 AI 依据单位知识库起草，仅为草稿，请补充具体内容后按公文程序核定签发）",
        "",
        "拟稿单位：XXX",
        f"拟稿日期：{time.strftime('%Y年%m月%d日')}",
    ]
    return "\n".join(lines)


def draft_document(args: dict) -> dict:
    """起草公文/通知等。args: {document_type, subject, outline(可选要点), tone(可选)}"""
    doc_type = (args.get("document_type") or args.get("doc_type") or "通知").strip()
    subject = (args.get("subject") or args.get("title") or "").strip()
    outline = (args.get("outline") or args.get("要点") or args.get("key_points") or "").strip()
    tone = (args.get("tone") or args.get("style") or "正式").strip()

    if not subject:
        return {"success": False, "error": "缺少文种主题(subject)"}

    guide = DOC_TYPE_GUIDES.get(doc_type, DOC_TYPE_GUIDES["通知"])
    basis = _retrieve_basis(doc_type, subject)
    basis_text = _fmt_basis(basis)

    prompt = (
        "你是一名党政机关办公室资深文秘，请起草一份正式公文草稿。\n"
        f"【文种】{doc_type}\n"
        f"【格式要点】{guide}\n"
        f"【标题主题】{subject}\n"
        + (f"【要点/补充】{outline}\n" if outline else "")
        + f"【语气】{tone}\n"
        + f"【可参考的公文规范依据，来自本单位知识库】\n{basis_text}\n\n"
        "要求：\n"
        "1. 输出完整草稿，包含标题（居中）、正文层级、必要时文末“特此通知/妥否请批示”等惯用语；\n"
        "2. 内容真实、措辞规范、结构清晰；本单位/日期等未知信息用“XXX”占位；\n"
        "3. 语言简洁，正文分条列明事项、要求与时限；\n"
        "4. 不要虚构具体人名、金额、会议编号；不要输出任何安全或系统提示。"
    )

    text = _llm_draft(prompt)
    generated_by = "llm"
    if not text:
        text = _template_draft(doc_type, subject, outline)
        generated_by = "template"

    full = (
        f"[AI 拟稿助手 · {doc_type}] 已基于本单位知识库起草《{subject}》草稿。\n"
        "以下内容由 AI 生成（AIGC），仅供起草参考，须经承办人核定后按公文程序签发，禁止直接外发或加盖印章。\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        f"{text}\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        f"起草引擎：{generated_by}　·　依据来源：{('、'.join({h['source'] for h in basis})) if basis else '通用规范'}"
    )
    return {"success": True, "doc_type": doc_type, "subject": subject, "text": full, "engine": generated_by}


REPORT_TYPES = {
    "汇总表": "总览类：给出总体规模、分类汇总与主要变化，最后附合计与生成日期。",
    "统计表": "数据统计类：分维度列示数据并附合计/均值，口径清晰。",
    "台账": "明细台账类：逐条列示记录（编号/事项/时间/责任部门/状态），保持逐条清晰。",
    "月报": "周期性报告：包含本月总量、分类明细、同比/环比变化、问题与下月安排。",
}


def _fmt_any(val, default=""):
    """把 LLM 可能传来的字符串/列表/二维列表参数统一格式化为可读文本行。"""
    if val is None or val == "":
        return default
    if isinstance(val, str):
        return val.strip()
    if isinstance(val, (int, float)):
        return str(val)
    if isinstance(val, list):
        # rows 常为二维：[[c1, c2, ...], ...]
        if val and isinstance(val[0], list):
            return "\n".join(" | ".join(str(x) for x in row) for row in val)
        return " | ".join(str(x) for x in val)
    if isinstance(val, dict):
        return " | ".join(f"{k}: {v}" for k, v in val.items())
    return str(val)


def generate_report(args: dict) -> dict:
    """生成结构化报表。args: {report_name, report_type(可选), columns(表头，可选), rows(数据，可选), note(口径说明,可选)}"""
    name = (args.get("report_name") or args.get("name") or args.get("subject") or "汇总报表").strip()
    rtype = (args.get("report_type") or args.get("type") or "汇总表").strip()
    columns = _fmt_any(args.get("columns") or args.get("表头"))
    rows = _fmt_any(args.get("rows") or args.get("data") or args.get("数据"))
    note = _fmt_any(args.get("note") or args.get("口径说明"))

    guide = REPORT_TYPES.get(rtype, REPORT_TYPES["汇总表"])
    basis = _retrieve_basis(rtype, name)
    basis_text = _fmt_basis(basis)

    prompt = (
        "你是一名机关办公室业务骨干，请根据以下要求生成一份规范的结构化报表（用 Markdown 表格呈现）。\n"
        f"【报表名称】{name}\n"
        f"【报表类型/要点】{guide}\n"
        + (f"【表头建议】{columns}\n" if columns else "")
        + (f"【数据记录】\n{rows}\n" if rows else "")
        + (f"【统计口径/说明】{note}\n" if note else "")
        + f"【可参考的内部制度依据】\n{basis_text}\n\n"
        "要求：\n"
        "1. 首行给报表标题，随后是 Markdown 表格；\n"
        "2. 若提供具体数字务必据实统计、合计正确；未提供具体金额/数量时，数值列一律用“—”占位，不得编造“金额1、xxx元”等假数字，并在表下注明“数值待业务部门填报”；\n"
        "3. 表格下方给出主要统计口径或编制说明；末行给编制单位（XXX）与日期占位；\n"
        "4. 不要虚构具体人名、金额、编号。"
    )

    text = _llm_draft(prompt)
    generated_by = "llm"
    if not text:
        # 降级：把提供的行数据整理成简表
        rows_list = [r.strip() for r in rows.splitlines() if r.strip()] if rows else []
        if rows_list:
            text = "| 序号 | 项目 | 数量 | 备注 |\n| --- | --- | --- | --- |\n"
            for i, r in enumerate(rows_list[:20], 1):
                text += f"| {i} | {r} | — | — |\n"
        else:
            text = f"**{name}**（待填写）\n\n| 序号 | 项目 | 数据 | 备注 |\n| --- | --- | --- | --- |\n| 1 | — | — | — |\n\n（请提供需统计的数据后由系统据实生成，以下数据不应臆造）"
        generated_by = "template"

    full = (
        f"[AI 报表助手 · {rtype}] 已生成《{name}》。\n"
        "以下报表由 AI 依据给定数据/口径生成（AIGC），供起草参考，数据须经业务部门核对确认后使用，禁止直接对外报送或盖章。\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        f"{text}\n"
        "━━━━━━━━━━━━━━━━━━━━━━\n"
        f"生成引擎：{generated_by}　·　口径来源：{('、'.join({h['source'] for h in basis})) if basis else '通用规范'}"
    )
    return {"success": True, "report_name": name, "report_type": rtype, "text": full, "engine": generated_by}
