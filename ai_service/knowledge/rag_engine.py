# -*- coding: utf-8 -*-
"""
本地政务沙盒知识库（RAG）引擎
================================
- 完全离线：基于缓存于本机的 BAAI/bge-small-zh-v1.5 中文 embedding（transformers 手动加载）
- 检索：numpy 余弦相似度暴力检索（语料规模小，足够快，零额外依赖、便于调试）
- 缓存：首次建索引导出 vecs.npy + chunks.json，后续直接读取，无需每次重建
- 设计贴合政企内网离线部署：不依赖任何外部 embedding API

用法：
    from knowledge.rag_engine import KnowledgeBase
    kb = KnowledgeBase()            # 自动加载/构建索引
    hits = kb.search("公租房怎么申请", k=4)
"""
from __future__ import annotations

import os
import re
import json
import glob
import logging
import threading

import numpy as np

logger = logging.getLogger("rag")

# embedding 所需的前缀（bge 官方推荐，用于增强检索）
_QUERY_PREFIX = "为这个句子生成表示以用于检索相关文章："

# 语料与缓存路径
_KB_DIR = os.path.dirname(os.path.abspath(__file__))
_DOC_DIR = os.path.join(_KB_DIR, "documents")
_CACHE_DIR = os.path.join(_KB_DIR, "cache")
_VEC_PATH = os.path.join(_CACHE_DIR, "kb_vecs.npy")
_CHUNK_PATH = os.path.join(_CACHE_DIR, "kb_chunks.json")
_META_PATH = os.path.join(_CACHE_DIR, "kb_meta.json")

# 切块控制
_MAX_CHUNK_CHARS = 260      # 单块最大字符数
_BLOCK_MIN_CHARS = 40       # 低于此长度的空块/标题段并入相邻块


class KnowledgeBase:
    """轻量本地语义知识库（单例加载模型，避免重复载入）。"""

    _model = None
    _tokenizer = None
    _lock = threading.Lock()

    def __init__(self, build_if_missing: bool = True):
        self.vecs: np.ndarray | None = None
        self.chunks: list[dict] = []
        self.meta: dict = {}
        self._load_or_build(build_if_missing)

    # ---------- 公共 API ----------

    def ready(self) -> bool:
        return self.vecs is not None and len(self.chunks) > 0

    def stats(self) -> dict:
        return {
            "ready": self.ready(),
            "doc_count": len(self.meta.get("docs", [])),
            "chunk_count": len(self.chunks),
            "embedding_dim": int(self.vecs.shape[1]) if self.vecs is not None else 0,
            "model": self.meta.get("model", ""),
            "built_at": self.meta.get("built_at", ""),
        }

    def search(self, query: str, k: int = 4, min_score: float = 0.40):
        """语义检索，返回 [{text, title, source, score, doc}]"""
        if not self.ready() or not query.strip():
            return []
        q = self._embed_texts([query])[0]
        # 已归一化 → 余弦 = 内积
        scores = self.vecs @ q
        order = np.argsort(-scores)[:k]
        hits = []
        for idx in order:
            sc = float(scores[idx])
            if sc < min_score:
                continue
            c = self.chunks[int(idx)]
            hits.append({
                "text": c["text"],
                "title": c.get("title", ""),
                "source": c.get("source", ""),
                "doc": c.get("doc", ""),
                "score": round(sc, 4),
            })
        return hits

    # ---------- 加载 / 构建 ----------

    def _load_or_build(self, build_if_missing: bool):
        # 缓存命中条件：文件齐全 且 语料签名一致（语料变更时自动重建，无需手动删缓存）
        if os.path.exists(_VEC_PATH) and os.path.exists(_CHUNK_PATH):
            try:
                self.vecs = np.load(_VEC_PATH)
                with open(_CHUNK_PATH, "r", encoding="utf-8") as f:
                    self.chunks = json.load(f)
                if os.path.exists(_META_PATH):
                    with open(_META_PATH, "r", encoding="utf-8") as f:
                        self.meta = json.load(f)
                sig = self._corpus_signature()
                if sig and self.meta.get("sig") == sig and self.meta.get("schema_version") == 2:
                    logger.info("知识库索引已加载：%d chunks, dim=%d", len(self.chunks), int(self.vecs.shape[1]))
                    return
                logger.info("知识库索引待更新（语料变更/版本升级），自动重建…")
            except Exception as e:  # noqa: BLE001
                logger.warning("加载缓存索引失败，将重建：%s", e)
        if build_if_missing:
            self.rebuild()

    @staticmethod
    def _corpus_signature() -> str:
        """基于语料文件清单生成签名（文件名 + 大小 + mtime），用于索引增量重建。"""
        import hashlib
        h = hashlib.md5()
        for path in sorted(glob.glob(os.path.join(_DOC_DIR, "*.md")) + glob.glob(os.path.join(_DOC_DIR, "*.txt"))):
            try:
                st = os.stat(path)
                h.update(f"{os.path.basename(path)}:{st.st_size}:{int(st.st_mtime)}".encode())
            except OSError:
                continue
        return h.hexdigest()

    def rebuild(self):
        """读取语料 → 切块 → 嵌入 → 落盘缓存。"""
        docs = self._collect_documents()
        if not docs:
            logger.warning("未找到知识库语料：%s", _DOC_DIR)
            return
        chunks = []
        for doc in docs:
            chunks.extend(self._split_doc(doc))
        if not chunks:
            return
        texts = [c["text"] for c in chunks]
        vecs = self._embed_texts(texts)
        self.chunks = chunks
        self.vecs = vecs
        import time
        self.meta = {
            "model": "BAAI/bge-small-zh-v1.5",
            "docs": [d["name"] for d in docs],
            "chunk_count": len(chunks),
            "schema_version": 2,
            "sig": self._corpus_signature(),
            "built_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        os.makedirs(_CACHE_DIR, exist_ok=True)
        np.save(_VEC_PATH, vecs)
        with open(_CHUNK_PATH, "w", encoding="utf-8") as f:
            json.dump(chunks, f, ensure_ascii=False, indent=1)
        with open(_META_PATH, "w", encoding="utf-8") as f:
            json.dump(self.meta, f, ensure_ascii=False, indent=1)
        logger.info("知识库索引已重建并缓存：%d docs, %d chunks", len(docs), len(chunks))

    # ---------- 语料读取 / 切块 ----------

    def _collect_documents(self):
        docs = []
        for path in sorted(glob.glob(os.path.join(_DOC_DIR, "*.md")) + glob.glob(os.path.join(_DOC_DIR, "*.txt"))):
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            docs.append({"path": path, "name": os.path.basename(path), "content": content})
        return docs

    def _split_doc(self, doc) -> list[dict]:
        """按标题(#/##/###)层级分节，再按空行切块并合并至 _MAX_CHUNK_CHARS 内。"""
        name = doc["name"]
        title = name.rsplit(".", 1)[0].replace("_", "")
        sections = self._split_by_heading(doc["content"])
        out = []
        for sec_path, body in sections:
            # 标题路径作为语义上下文，辅助检索
            if sec_path:
                body = f"【{sec_path}】\n{body}"
            for blk in self._coalesce(body):
                text = blk.strip()
                if len(text) < _BLOCK_MIN_CHARS:
                    continue
                out.append({
                    "text": text,
                    "title": f"{title}｜{sec_path}" if sec_path else title,
                    "source": name,
                    "doc": name,
                })
        return out

    @staticmethod
    def _split_by_heading(content: str):
        """按 1~3 级 markdown 标题切分，返回 [(标题路径, 正文)]。"""
        lines = content.splitlines()
        sections = []
        cur = []                       # 当前节累积的非标题行
        h2, h3 = None, None            # 当前层级标题
        def flush():
            txt = "\n".join(cur).strip()
            if txt:
                path = " / ".join(x for x in (h2, h3) if x) or ""
                sections.append((path, txt))
        for ln in lines:
            m1 = re.match(r"^#\s+(.+?)\s*$", ln)      # 文档主标题
            m2 = re.match(r"^##\s+(.+?)\s*$", ln)     # 一级栏目
            m3 = re.match(r"^###+\s+(.+?)\s*$", ln)   # 二级栏目/小节
            if m1:
                continue  # 主标题不进入正文
            if m2:
                flush(); cur = []
                h2, h3 = m2.group(1).strip(), None
            elif m3:
                flush(); cur = []
                h3 = m3.group(1).strip()
            else:
                cur.append(ln)
        flush()
        return sections

    @staticmethod
    def _coalesce(body: str):
        """按空行切块；过短段并入相邻块；单块超长按句拆开。"""
        paras = [p.strip() for p in re.split(r"\n\s*\n", body) if p.strip()]
        blocks = []
        cur = ""
        for p in paras:
            if len(cur) + len(p) <= _MAX_CHUNK_CHARS:
                cur = (cur + "\n" + p).strip()
            else:
                if cur:
                    blocks.append(cur)
                cur = p
        if cur:
            blocks.append(cur)
        return [b for b in blocks if len(b) >= _BLOCK_MIN_CHARS]

    # ---------- embedding ----------

    @classmethod
    def _ensure_model(cls):
        with cls._lock:
            if cls._model is None:
                import time
                t0 = time.time()
                from transformers import AutoModel, AutoTokenizer
                model_name = "BAAI/bge-small-zh-v1.5"
                cls._tokenizer = AutoTokenizer.from_pretrained(model_name)
                cls._model = AutoModel.from_pretrained(model_name)
                cls._model.eval()
                logger.info("embedding 模型已加载（%.1fs）", time.time() - t0)

    @classmethod
    def _embed_texts(cls, texts):
        cls._ensure_model()
        import torch
        tokenizer, model = cls._tokenizer, cls._model
        batch_size = 32
        all_vecs = []
        for i in range(0, len(texts), batch_size):
            batch = [_QUERY_PREFIX + t for t in texts[i:i + batch_size]]
            enc = tokenizer(
                batch, padding=True, truncation=True, max_length=384, return_tensors="pt"
            )
            with torch.no_grad():
                out = model(**enc)
            # last_hidden_state: (B, S, H)；attention_mask: (B, S)
            hidden = out.last_hidden_state
            attn = enc["attention_mask"].float()          # (B, S)
            # mask 掉 padding token 后对 S 维求和 → (B, H)
            summed = (hidden * attn.unsqueeze(-1)).sum(dim=1)
            num = attn.sum(dim=1, keepdim=True).clamp(min=1e-8)   # (B, 1)
            vec = summed / num
            vec = vec / (vec.norm(dim=1, keepdim=True).clamp(min=1e-8))
            all_vecs.append(vec.squeeze().detach().numpy())
        res = np.concatenate(all_vecs, axis=0)
        return res.reshape(len(texts), -1)


# 模块级单例
_kb: KnowledgeBase | None = None
_kb_lock = threading.Lock()


def get_kb(build_if_missing: bool = True) -> KnowledgeBase:
    global _kb
    if _kb is None:
        with _kb_lock:
            if _kb is None:
                _kb = KnowledgeBase(build_if_missing=build_if_missing)
    return _kb
