"""
持续优化闭环模块 (Optimization Loop)
====================================

T6 持续优化：实现"评测—防护—审计—运营"一体化闭环。

核心能力：
1. 误报/漏报反馈闭环
   - 检测结果人工标注接口（确认/驳回）
   - 基于标注数据的规则自动调优（生成关键词增删版本）
   - 关键词/模式库版本管理
2. 攻击趋势感知
   - 新型攻击模式自动聚类（字符n-gram相似度）
   - 威胁情报订阅接口（外部IOC导入）
   - 攻击样例库动态扩充
3. 效果回归测试
   - 规则更新后自动回归测试（真实检测流水线）
   - 检测效果趋势数据（供可视化）

数据持久化：复用 safeagent.db（SQLite），独立管理 opt_* 表。
"""

import sys
import os
import re
import json
import uuid
import sqlite3
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.schemas import RiskLevel, InputSource

DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "safeagent.db",
)


class OptimizationLoop:
    """持续优化闭环（SQLite 持久化）"""

    def __init__(self, db_path: str = DB_PATH):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._db_path = db_path
        self._init_tables()

    # ------------------------------------------------------------------
    # 表结构
    # ------------------------------------------------------------------

    def _get_conn(self):
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self):
        with self._get_conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS opt_feedback (
                    id TEXT PRIMARY KEY,
                    sample_text TEXT,
                    source TEXT,
                    predicted_label TEXT,
                    predicted_risk TEXT,
                    annotator_label TEXT,
                    annotator_comment TEXT,
                    status TEXT,
                    created_at TEXT
                );
                CREATE TABLE IF NOT EXISTS opt_versions (
                    id TEXT PRIMARY KEY,
                    version INTEGER,
                    change_type TEXT,
                    description TEXT,
                    keywords_added TEXT,
                    keywords_removed TEXT,
                    applied INTEGER DEFAULT 0,
                    applied_at TEXT,
                    created_at TEXT
                );
                CREATE TABLE IF NOT EXISTS opt_attack_samples (
                    id TEXT PRIMARY KEY,
                    content TEXT,
                    attack_type TEXT,
                    source TEXT,
                    created_at TEXT,
                    in_use INTEGER DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS opt_regression_runs (
                    id TEXT PRIMARY KEY,
                    run_at TEXT,
                    total INTEGER,
                    accuracy REAL,
                    false_positive_rate REAL,
                    false_negative_rate REAL,
                    detected_attacks INTEGER,
                    keyword_count INTEGER,
                    note TEXT
                );
                CREATE TABLE IF NOT EXISTS opt_threat_iocs (
                    id TEXT PRIMARY KEY,
                    indicator TEXT,
                    ioc_type TEXT,
                    source TEXT,
                    imported_at TEXT,
                    applied INTEGER DEFAULT 0
                );
            """)

    # ------------------------------------------------------------------
    # 1. 误报/漏报反馈闭环
    # ------------------------------------------------------------------

    def record_feedback(self, sample_text: str, predicted_label: str,
                        predicted_risk: str, annotator_label: str,
                        annotator_comment: str = "", source: str = "manual") -> Dict[str, Any]:
        """人工标注检测结果（确认/驳回）

        annotator_label: attack（真实攻击） | benign（正常内容）
        status: confirmed（与预测一致） | rejected（与预测不一致）
        """
        fid = uuid.uuid4().hex[:16]
        status = "confirmed" if predicted_label == annotator_label else "rejected"
        now = datetime.now().isoformat()
        with self._get_conn() as conn:
            conn.execute(
                """INSERT INTO opt_feedback
                   (id, sample_text, source, predicted_label, predicted_risk,
                    annotator_label, annotator_comment, status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (fid, sample_text, source, predicted_label, predicted_risk,
                 annotator_label, annotator_comment, status, now))
        return {
            "id": fid, "sample_text": sample_text[:100], "predicted_label": predicted_label,
            "annotator_label": annotator_label, "status": status, "created_at": now,
        }

    def list_feedback(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM opt_feedback ORDER BY created_at DESC LIMIT ?",
                (limit,)).fetchall()
        return [dict(r) for r in rows]

    def feedback_stats(self) -> Dict[str, Any]:
        """反馈统计：误报(FP)/漏报(FN)计数"""
        with self._get_conn() as conn:
            total = conn.execute("SELECT COUNT(*) FROM opt_feedback").fetchone()[0]
            # 漏报：预测为 benign 但人工标 attack
            fn = conn.execute(
                "SELECT COUNT(*) FROM opt_feedback WHERE predicted_label='benign' "
                "AND annotator_label='attack'").fetchone()[0]
            # 误报：预测为 attack 但人工标 benign
            fp = conn.execute(
                "SELECT COUNT(*) FROM opt_feedback WHERE predicted_label='attack' "
                "AND annotator_label='benign'").fetchone()[0]
        return {"total": total, "false_negatives": fn, "false_positives": fp}

    def auto_tune_from_feedback(self, min_samples: int = 1,
                                auto_apply: bool = True) -> Dict[str, Any]:
        """基于标注数据自动调优

        分析所有"驳回"（预测与标注不一致）的样本：
        - 漏报（benign→attack）：提取高频词作为新增高危关键词
        - 误报（attack→benign）：提取高频词作为建议移除关键词

        生成新版本，可选择直接应用（写入 RuleEngine 动态关键词）。
        """
        with self._get_conn() as conn:
            fn_rows = conn.execute(
                "SELECT sample_text FROM opt_feedback WHERE predicted_label='benign' "
                "AND annotator_label='attack'").fetchall()
            fp_rows = conn.execute(
                "SELECT sample_text FROM opt_feedback WHERE predicted_label='attack' "
                "AND annotator_label='benign'").fetchall()

        added = self._extract_high_freq_terms([r["sample_text"] for r in fn_rows], top_n=10)
        removed = self._extract_high_freq_terms([r["sample_text"] for r in fp_rows], top_n=10)

        if not added and not removed:
            return {"tuned": False, "message": "无足够标注数据，暂无可调优项"}

        version = self.create_version(
            change_type="auto_tune",
            description=f"基于{len(fn_rows)}条漏报+{len(fp_rows)}条误报标注自动调优",
            keywords_added=added, keywords_removed=removed,
        )
        if auto_apply and (added or removed):
            self.apply_version(version["id"], apply_to_detector=True)

        return {
            "tuned": True,
            "version": version,
            "keywords_added": added,
            "keywords_removed": removed,
        }

    @staticmethod
    def _extract_high_freq_terms(texts: List[str], top_n: int = 10,
                                 min_len: int = 2) -> List[str]:
        """从样本中提取高频词（中文按2-4字窗口，英文按词）"""
        freq: Dict[str, int] = {}
        for t in texts:
            if not t:
                continue
            # 中文片段：提取连续中文字符串，滑窗2-4字
            for seg in re.findall(r"[\u4e00-\u9fff]+", t):
                for wlen in (4, 3, 2):
                    for i in range(len(seg) - wlen + 1):
                        w = seg[i:i + wlen]
                        freq[w] = freq.get(w, 0) + 1
            # 英文单词
            for w in re.findall(r"[a-zA-Z][a-zA-Z0-9_\-]{2,}", t.lower()):
                freq[w] = freq.get(w, 0) + 1
        # 过滤常见停用词
        stopwords = {"我们", "你们", "他们", "这个", "那个", "什么", "怎么", "如何",
                     "可以", "需要", "一个", "一下", "还是", "或者", "以及", "因为",
                     "the", "and", "for", "with", "you", "your", "this", "that",
                     "are", "how", "what", "why", "can", "could", "please"}
        filtered = [(w, c) for w, c in freq.items()
                    if w not in stopwords and c >= 1]
        filtered.sort(key=lambda x: -x[1])
        return [w for w, _ in filtered[:top_n]]

    # ------------------------------------------------------------------
    # 关键词/模式库版本管理
    # ------------------------------------------------------------------

    def create_version(self, change_type: str, description: str,
                       keywords_added: List[str], keywords_removed: List[str]) -> Dict[str, Any]:
        with self._get_conn() as conn:
            last = conn.execute(
                "SELECT MAX(version) FROM opt_versions").fetchone()[0]
            version_no = (last or 0) + 1
            vid = uuid.uuid4().hex[:16]
            conn.execute(
                """INSERT INTO opt_versions
                   (id, version, change_type, description, keywords_added,
                    keywords_removed, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (vid, version_no, change_type, description,
                 json.dumps(keywords_added, ensure_ascii=False),
                 json.dumps(keywords_removed, ensure_ascii=False),
                 datetime.now().isoformat()))
        return {
            "id": vid, "version": version_no, "change_type": change_type,
            "description": description, "keywords_added": keywords_added,
            "keywords_removed": keywords_removed, "applied": False,
        }

    def list_versions(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM opt_versions ORDER BY version DESC LIMIT ?",
                (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["keywords_added"] = json.loads(d["keywords_added"] or "[]")
            d["keywords_removed"] = json.loads(d["keywords_removed"] or "[]")
            out.append(d)
        return out

    def apply_version(self, version_id: str, apply_to_detector: bool = True) -> Dict[str, Any]:
        """应用版本：将增删关键词写入 RuleEngine 动态关键词库"""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM opt_versions WHERE id=?", (version_id,)).fetchone()
            if not row:
                return {"ok": False, "message": "版本不存在"}
            added = json.loads(row["keywords_added"] or "[]")
            removed = json.loads(row["keywords_removed"] or "[]")
            applied = row["applied"]
            conn.execute(
                "UPDATE opt_versions SET applied=1, applied_at=? WHERE id=?",
                (datetime.now().isoformat(), version_id))
            conn.commit()

        detector_applied = 0
        if apply_to_detector and not applied:
            from security.input_detector import InputDetectionService
            svc = InputDetectionService()
            engine = svc.rule_engine
            detector_applied = engine.add_keywords(added, level="high")
            if removed:
                engine.remove_keywords(removed)
        return {
            "ok": True, "version_id": version_id,
            "keywords_added_count": len(added),
            "keywords_removed_count": len(removed),
            "detector_applied": detector_applied,
        }

    # ------------------------------------------------------------------
    # 2. 攻击趋势感知
    # ------------------------------------------------------------------

    def record_attack_sample(self, content: str, attack_type: str,
                             source: str = "manual") -> Dict[str, Any]:
        """攻击样例库动态扩充"""
        aid = uuid.uuid4().hex[:16]
        with self._get_conn() as conn:
            conn.execute(
                """INSERT INTO opt_attack_samples
                   (id, content, attack_type, source, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (aid, content, attack_type, source, datetime.now().isoformat()))
        return {"id": aid, "attack_type": attack_type, "source": source}

    def list_attack_samples(self, limit: int = 200) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM opt_attack_samples ORDER BY created_at DESC LIMIT ?",
                (limit,)).fetchall()
        return [dict(r) for r in rows]

    def cluster_attack_patterns(self, min_cluster: int = 2) -> Dict[str, Any]:
        """新型攻击模式自动聚类（字符trigram Jaccard相似度 + 并查集）

        对未被检测为攻击的样本 + 新增攻击样例做聚类，
        识别高相似度簇（同一类新型攻击）。
        """
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT id, content, attack_type, source FROM opt_attack_samples "
                "WHERE in_use=1").fetchall()
        samples = [dict(r) for r in rows]
        if len(samples) < 2:
            return {"clusters": [], "message": "样本不足，无法聚类"}

        def _bigrams(text: str) -> set:
            t = re.sub(r"\s+", "", (text or "").lower())
            return {t[i:i + 2] for i in range(len(t) - 1)} if len(t) >= 2 else {t}

        def _similarity(a: str, b: str) -> float:
            ta, tb = _bigrams(a), _bigrams(b)
            if not ta or not tb:
                return 0.0
            inter = len(ta & tb)
            # Dice 系数（对短文本更稳健）
            return 2 * inter / (len(ta) + len(tb))

        # 并查集
        parent = list(range(len(samples)))
        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x
        def union(a, b):
            ra, rb = find(a), find(b)
            if ra != rb:
                parent[ra] = rb

        for i in range(len(samples)):
            for j in range(i + 1, len(samples)):
                if _similarity(samples[i]["content"], samples[j]["content"]) >= 0.25:
                    union(i, j)

        groups: Dict[int, List[int]] = {}
        for i in range(len(samples)):
            groups.setdefault(find(i), []).append(i)

        clusters = []
        for idxs in groups.values():
            if len(idxs) < min_cluster:
                continue
            members = [samples[i] for i in idxs]
            clusters.append({
                "size": len(members),
                "attack_types": list({m["attack_type"] for m in members}),
                "sources": list({m["source"] for m in members}),
                "representative": members[0]["content"][:120],
                "sample_ids": [m["id"] for m in members],
            })
        clusters.sort(key=lambda c: -c["size"])
        return {"clusters": clusters, "total_samples": len(samples)}

    def import_threat_iocs(self, iocs: List[Dict[str, Any]],
                           source: str = "external") -> Dict[str, Any]:
        """威胁情报订阅接口：导入外部 IOC 指标

        iocs: [{"indicator": "evil.com" 或 "xxx恶意关键词", "type": "domain|ip|hash|keyword"}]
        返回导入数量；同时将 domain/ip 加入浏览器黑名单，keyword 加入检测库。
        """
        if not iocs:
            return {"imported": 0, "applied": 0, "skipped": 0}
        imported = 0
        applied = 0
        skipped = 0
        domains, ips, keywords = [], [], []
        now = datetime.now().isoformat()
        with self._get_conn() as conn:
            for ioc in iocs:
                indicator = str(ioc.get("indicator", "")).strip()
                ioc_type = str(ioc.get("type", "keyword")).lower()
                if not indicator or len(indicator) < 2:
                    skipped += 1
                    continue
                # 去重
                exists = conn.execute(
                    "SELECT id FROM opt_threat_iocs WHERE indicator=?",
                    (indicator,)).fetchone()
                if exists:
                    skipped += 1
                    continue
                conn.execute(
                    """INSERT INTO opt_threat_iocs
                       (id, indicator, ioc_type, source, imported_at)
                       VALUES (?, ?, ?, ?, ?)""",
                    (uuid.uuid4().hex[:16], indicator, ioc_type, source, now))
                imported += 1
                if ioc_type == "domain":
                    domains.append(indicator)
                elif ioc_type == "ip":
                    ips.append(indicator)
                else:
                    keywords.append(indicator)
            conn.commit()

        # 应用：域名/IP → 浏览器黑名单；关键词 → RuleEngine动态库
        from security.browser_access_control import BrowserAccessController
        from security.input_detector import InputDetectionService
        bc = BrowserAccessController()
        for d in domains:
            bc.add_to_blacklist(d)
        for ip in ips:
            bc.add_to_blacklist(ip)
        if keywords:
            svc = InputDetectionService()
            applied = svc.rule_engine.add_keywords(keywords, level="high")
        # 标记已应用
        with self._get_conn() as conn:
            conn.execute(
                "UPDATE opt_threat_iocs SET applied=1 WHERE source=? AND applied=0",
                (source,))
            conn.commit()

        return {
            "imported": imported, "applied": applied,
            "domains": len(domains), "ips": len(ips), "keywords": len(keywords),
            "skipped": skipped,
        }

    def list_threat_iocs(self, limit: int = 200) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM opt_threat_iocs ORDER BY imported_at DESC LIMIT ?",
                (limit,)).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # 3. 效果回归测试
    # ------------------------------------------------------------------

    def run_regression(self, samples: Optional[List[Dict[str, Any]]] = None,
                       note: str = "auto") -> Dict[str, Any]:
        """规则更新后自动回归测试

        samples: [{"content": "...", "is_attack": bool}, ...]
        使用真实输入检测流水线，计算准确率/误报率/漏报率。
        """
        from security.input_detector import InputDetectionService
        if samples is None:
            # 默认回归集：内置攻击样例 + 正常样本
            with self._get_conn() as conn:
                attack_rows = conn.execute(
                    "SELECT content FROM opt_attack_samples LIMIT 30").fetchall()
            samples = [{"content": r["content"], "is_attack": True} for r in attack_rows]
            samples += [
                {"content": "请介绍政务公开相关政策", "is_attack": False},
                {"content": "今天天气怎么样", "is_attack": False},
                {"content": "如何办理营业执照", "is_attack": False},
                {"content": "帮我查询一下文件", "is_attack": False},
            ]

        svc = InputDetectionService()
        tp = fp = tn = fn = 0
        details = []
        for s in samples:
            content = s.get("content", "")
            expected = s.get("is_attack", False)
            try:
                r = svc.detect_single_input(content, InputSource.USER_INPUT)
                # "被检出"= 风险被标记（MEDIUM及以上），用于衡量检测召回
                detected = r.risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH,
                                            RiskLevel.CRITICAL)
            except Exception:
                detected = False
            if expected and detected:
                tp += 1
            elif not expected and detected:
                fp += 1
            elif not expected and not detected:
                tn += 1
            else:
                fn += 1
            details.append({"content": content[:50], "expected": expected,
                            "detected": detected})

        total = tp + fp + tn + fn
        accuracy = (tp + tn) / total if total else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        fnr = fn / (fn + tp) if (fn + tp) else 0.0

        # 记录回归运行
        from security.rule_engine import RuleEngine
        kw_count = len(RuleEngine().high_risk_keywords) + \
            len(RuleEngine().medium_risk_keywords)
        run_id = uuid.uuid4().hex[:16]
        with self._get_conn() as conn:
            conn.execute(
                """INSERT INTO opt_regression_runs
                   (id, run_at, total, accuracy, false_positive_rate,
                    false_negative_rate, detected_attacks, keyword_count, note)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (run_id, datetime.now().isoformat(), total, round(accuracy, 4),
                 round(fpr, 4), round(fnr, 4), tp, kw_count, note))
            conn.commit()

        return {
            "run_id": run_id,
            "total": total, "accuracy": round(accuracy, 4),
            "false_positive_rate": round(fpr, 4),
            "false_negative_rate": round(fnr, 4),
            "detected_attacks": tp,
            "keyword_count": kw_count,
            "details": details,
        }

    def get_trend(self, limit: int = 30) -> Dict[str, Any]:
        """检测效果趋势数据（供可视化）"""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM opt_regression_runs ORDER BY run_at ASC LIMIT ?",
                (limit,)).fetchall()
        runs = [dict(r) for r in rows]
        return {
            "runs": runs,
            "labels": [r["run_at"][:16] for r in runs],
            "accuracy": [r["accuracy"] for r in runs],
            "false_positive_rate": [r["false_positive_rate"] for r in runs],
            "false_negative_rate": [r["false_negative_rate"] for r in runs],
            "keyword_counts": [r["keyword_count"] for r in runs],
        }

    def get_counts(self) -> Dict[str, int]:
        """各表总条数（供只读汇总端点使用）"""
        with self._get_conn() as conn:
            versions = conn.execute(
                "SELECT COUNT(*) FROM opt_versions").fetchone()[0]
            attack_samples = conn.execute(
                "SELECT COUNT(*) FROM opt_attack_samples").fetchone()[0]
            threat_iocs = conn.execute(
                "SELECT COUNT(*) FROM opt_threat_iocs").fetchone()[0]
            regression_runs = conn.execute(
                "SELECT COUNT(*) FROM opt_regression_runs").fetchone()[0]
        return {
            "versions": versions,
            "attack_samples": attack_samples,
            "threat_iocs": threat_iocs,
            "regression_runs": regression_runs,
        }

    # ------------------------------------------------------------------
    # 持久化恢复：服务重启后恢复已应用的调优关键词
    # ------------------------------------------------------------------

    def rehydrate_dynamic_keywords(self) -> int:
        """将已应用版本中的调优关键词恢复到检测库（进程重启后调用）"""
        from security.input_detector import InputDetectionService
        engine = InputDetectionService().rule_engine
        count = 0
        for v in self.list_versions():
            if v.get("applied"):
                count += engine.add_keywords(v.get("keywords_added", []), level="high")
        return count


_optimization_loop: Optional[OptimizationLoop] = None


def get_optimization_loop() -> OptimizationLoop:
    """获取优化闭环单例（同时恢复已应用的调优关键词）"""
    global _optimization_loop
    if _optimization_loop is None:
        _optimization_loop = OptimizationLoop()
        try:
            _optimization_loop.rehydrate_dynamic_keywords()
        except Exception:
            pass
    return _optimization_loop


if __name__ == "__main__":
    loop = get_optimization_loop()
    # 演示：标注→调优→应用→回归→趋势
    loop.record_feedback("新型钓鱼攻击手段 诱导 点击 链接 窃取", "benign", "none",
                         "attack", "漏报案例", source="demo")
    loop.record_feedback("普通业务咨询文件管理", "attack", "high",
                         "benign", "误报案例", source="demo")
    print("反馈统计:", loop.feedback_stats())
    tune = loop.auto_tune_from_feedback(auto_apply=True)
    print("自动调优:", json.dumps(tune, ensure_ascii=False)[:300])
    print("版本列表:", len(loop.list_versions()))
    reg = loop.run_regression()
    print(f"回归: 准确率 {reg['accuracy']:.1%} 误报率 {reg['false_positive_rate']:.1%} 漏报率 {reg['false_negative_rate']:.1%}")
    print("趋势:", json.dumps(loop.get_trend(), ensure_ascii=False)[:200])
