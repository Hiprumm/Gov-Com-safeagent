"""
攻击复现引擎 — AttackReplayEngine

面向"攻击复现、问题定位、效果验证和持续优化"的竞争需求，提供：
  1. attack_replays.json — JSON 文件持久化记录每次攻击会话的完整上下文
  2. Replay — 使用完全相同的输入重新运行检测器，对比原始结果与当前结果
  3. Batch replay — 一键复现所有已记录的攻击
  4. Replay report — 生成结构化报告，突出改进项与回归项

使用方式：
    from audit.attack_replay import AttackReplayEngine
    engine = AttackReplayEngine()
    record_id = engine.record(session_id="...", ...)
    result  = engine.replay(record_id)
    report  = engine.get_report()
"""

import sys
import os
import json
import uuid
import threading
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.schemas import (
    DetectionResult, RiskLevel, AttackType, InputSource,
)


# ---------------------------------------------------------------------------
# 数据类
# ---------------------------------------------------------------------------


@dataclass
class AttackRecord:
    """一条攻击记录的完整快照。"""
    session_id: str
    timestamp: str                                      # ISO 格式
    input_text: str
    source: str                                         # 对应 InputSource 的 value
    original_detection: Dict[str, Any] = field(default_factory=dict)
    agent_response: Optional[str] = None                # blocked / allowed
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    approval_status: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ReplayResult:
    """单次复现结果。"""
    record_id: str
    original_detection: Dict[str, Any]
    current_detection: Dict[str, Any]
    status: str = "unchanged"                           # detected | missed | regression | improvement | unchanged
    risk_level_changed: bool = False
    replayed_at: str = field(default_factory=lambda: datetime.now().isoformat())

    # 原始检测速查字段
    orig_risk: Optional[str] = None
    orig_attack_type: Optional[str] = None
    orig_confidence: Optional[float] = None

    # 当前检测速查字段
    curr_risk: Optional[str] = None
    curr_attack_type: Optional[str] = None
    curr_confidence: Optional[float] = None

    def __post_init__(self):
        self._populate_quick_fields()

    def _populate_quick_fields(self):
        """从嵌套 dict 中提取速查字段，减少调用方的解包负担。"""
        od = self.original_detection or {}
        cd = self.current_detection or {}
        self.orig_risk = od.get("risk_level")
        self.orig_attack_type = od.get("attack_type")
        self.orig_confidence = od.get("confidence")
        self.curr_risk = cd.get("risk_level")
        self.curr_attack_type = cd.get("attack_type")
        self.curr_confidence = cd.get("confidence")


# ---------------------------------------------------------------------------
# 存储后端（纯 JSON 文件）
# ---------------------------------------------------------------------------

_DEFAULT_STORAGE_PATH = Path(__file__).resolve().parent / "attack_replays.json"


class _ReplayStore:
    """线程安全的 JSON 文件读写助手。"""

    def __init__(self, path: Optional[Path] = None):
        self._path = Path(path) if path else _DEFAULT_STORAGE_PATH
        self._lock = threading.Lock()

    # ---- 读 ----
    def read_all(self) -> Dict[str, Dict[str, Any]]:
        if not self._path.exists():
            return {}
        try:
            raw = json.loads(self._path.read_text(encoding="utf-8"))
            if isinstance(raw, list):
                # 兼容旧格式（列表 → 字典）
                return self._list_to_dict(raw)
            return raw if isinstance(raw, dict) else {}
        except (json.JSONDecodeError, ValueError):
            return {}

    # ---- 写 ----
    def write_one(self, record_id: str, record_data: Dict[str, Any]):
        with self._lock:
            data = self.read_all()
            data[record_id] = record_data
            self._safe_write(data)

    def write_all(self, data: Dict[str, Dict[str, Any]]):
        with self._lock:
            self._safe_write(data)

    # ---- 辅助 ----
    def _safe_write(self, data: Dict[str, Dict[str, Any]]):
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = str(self._path) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2, default=str)
        os.replace(tmp, str(self._path))

    @staticmethod
    def _list_to_dict(lst: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        result: Dict[str, Dict[str, Any]] = {}
        for item in lst:
            rid = item.get("session_id") or str(uuid.uuid4())
            result[rid] = item
        return result


# ---------------------------------------------------------------------------
# 主引擎
# ---------------------------------------------------------------------------


class AttackReplayEngine:
    """攻击复现引擎。

    职责：
      - record()    — 记录一次攻击会话的完整上下文
      - replay()    — 使用当前检测器重新评估某条记录
      - replay_all()— 批量复现所有历史记录
      - get_report()— 生成对比报告（改进 / 回归 / 风险等级变化）
    """

    def __init__(self, storage_path: Optional[str] = None):
        self._store = _ReplayStore(Path(storage_path) if storage_path else None)
        # 延迟初始化检测服务（避免循环导入）
        self._detector = None

    # ------- 公共属性 -------
    @property
    def detector(self):
        """延迟加载 InputDetectionService，避免模块级循环导入。"""
        if self._detector is None:
            from security.input_detector import InputDetectionService
            self._detector = InputDetectionService()
        return self._detector

    # =======================================================================
    #  record  — 记录攻击会话
    # =======================================================================

    def record(
        self,
        session_id: str,
        input_text: str,
        source: str = "user_input",
        detection_result: Optional[DetectionResult] = None,
        agent_response: Optional[str] = None,
        tool_calls: Optional[List[Dict[str, Any]]] = None,
        approval_status: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """记录一次攻击会话，返回 record_id。

        参数
        ----
        session_id : str
            会话唯一标识。
        input_text : str
            用户输入原文。
        source : str
            输入来源，对应 InputSource。
        detection_result : DetectionResult or None
            当时的检测结果。
        agent_response : str or None
            智能体响应（如 "blocked" / "allowed"）。
        tool_calls : list[dict] or None
            触发或尝试的工具调用列表。
        approval_status : str or None
            审批结果。
        metadata : dict or None
            扩展元数据（任意键值对）。
        """
        record_id = str(uuid.uuid4())

        # 序列化 DetectionResult
        orig_det = {}
        if detection_result is not None:
            try:
                orig_det = detection_result.model_dump(mode="json")
            except AttributeError:
                orig_det = {
                    "risk_level": getattr(detection_result, "risk_level", None),
                    "attack_type": getattr(detection_result, "attack_type", None),
                    "confidence": getattr(detection_result, "confidence", None),
                    "evidence": getattr(detection_result, "evidence", []),
                }

        record_data: Dict[str, Any] = {
            "session_id": session_id,
            "timestamp": datetime.now().isoformat(),
            "input_text": input_text,
            "source": source,
            "original_detection": orig_det,
            "agent_response": agent_response,
            "tool_calls": tool_calls or [],
            "approval_status": approval_status,
            "metadata": metadata or {},
        }
        self._store.write_one(record_id, record_data)
        return record_id

    # =======================================================================
    #  replay  — 单条复现
    # =======================================================================

    def replay(self, record_id: str) -> Optional[ReplayResult]:
        """使用当前 InputDetectionService 重新检测一条记录，返回对比结果。

        返回 None 表示记录不存在。
        """
        data = self._store.read_all()
        if record_id not in data:
            return None

        record = data[record_id]
        input_text = record.get("input_text", "")
        source = record.get("source", "user_input")
        original_det = record.get("original_detection", {})

        # 当前检测
        try:
            current_result = self.detector.detect_single_input(input_text, source)
            current_det = current_result.model_dump(mode="json") if hasattr(current_result, "model_dump") else {}
        except Exception:
            current_det = {
                "risk_level": "none",
                "attack_type": None,
                "confidence": 0.0,
                "evidence": [],
                "error": "detection_failed",
            }

        # 判定状态
        status = self._classify(original_det, current_det)
        risk_level_changed = self._risk_level_different(original_det, current_det)

        result = ReplayResult(
            record_id=record_id,
            original_detection=original_det,
            current_detection=current_det,
            status=status,
            risk_level_changed=risk_level_changed,
        )
        return result

    # =======================================================================
    #  replay_all  — 批量复现
    # =======================================================================

    def replay_all(self) -> List[ReplayResult]:
        """复现所有已存储的攻击记录，返回 ReplayResult 列表。"""
        data = self._store.read_all()
        results: List[ReplayResult] = []
        for rid in data:
            rr = self.replay(rid)
            if rr is not None:
                results.append(rr)
        return results

    # =======================================================================
    #  get_report  — 生成复现报告
    # =======================================================================

    def get_report(self, include_details: bool = False) -> Dict[str, Any]:
        """运行 replay_all() 并生成结构化对比报告。

        返回字典包含：
          - summary       : 统计摘要
          - improvements  : 之前漏报、现在检出
          - regressions   : 之前检出、现在漏报
          - risk_changed  : 风险等级发生变化
          - details       : 全部 ReplayResult 详情（include_details=True 时才输出）
        """
        results = self.replay_all()

        summary = {
            "total_records": len(results),
            "improvements": 0,
            "regressions": 0,
            "risk_level_changed": 0,
            "unchanged": 0,
            "replayed_at": datetime.now().isoformat(),
        }
        improvements: List[Dict[str, Any]] = []
        regressions: List[Dict[str, Any]] = []
        risk_changed: List[Dict[str, Any]] = []

        for rr in results:
            if rr.status == "improvement":
                summary["improvements"] += 1
                improvements.append(self._result_summary(rr))
            elif rr.status == "regression":
                summary["regressions"] += 1
                regressions.append(self._result_summary(rr))
            elif rr.risk_level_changed:
                summary["risk_level_changed"] += 1
                risk_changed.append(self._result_summary(rr))
            else:
                summary["unchanged"] += 1

        report: Dict[str, Any] = {
            "summary": summary,
            "improvements": improvements,
            "regressions": regressions,
            "risk_level_changed": risk_changed,
        }
        if include_details:
            report["details"] = [self._result_summary(rr, verbose=True) for rr in results]

        return report

    # =======================================================================
    #  辅助方法
    # =======================================================================

    # ---------- 存储查询 ----------

    def get_record(self, record_id: str) -> Optional[Dict[str, Any]]:
        """按 record_id 获取原始记录字典。"""
        return self._store.read_all().get(record_id)

    def get_all_records(self) -> Dict[str, Dict[str, Any]]:
        """获取全部存储记录。"""
        return self._store.read_all()

    def count(self) -> int:
        """已存储的攻击记录数量。"""
        return len(self._store.read_all())

    def clear(self):
        """清空所有攻击记录（谨慎调用）。"""
        self._store.write_all({})

    # ---------- 分类逻辑 ----------

    @staticmethod
    def _classify(original: Dict[str, Any], current: Dict[str, Any]) -> str:
        """基于原始与当前检测结果，给出复现状态标签。"""
        orig_risk = (original or {}).get("risk_level", "none") or "none"
        curr_risk = (current or {}).get("risk_level", "none") or "none"

        orig_is_attack = orig_risk not in ("none", None, "")
        curr_is_attack = curr_risk not in ("none", None, "")

        if not orig_is_attack and curr_is_attack:
            return "improvement"          # 之前漏报 → 现在检出
        if orig_is_attack and not curr_is_attack:
            return "regression"           # 之前检出 → 现在漏报
        if orig_is_attack and curr_is_attack:
            return "detected"             # 两次都检出
        return "missed"                   # 两次都未检出

    @staticmethod
    def _risk_level_different(original: Dict[str, Any], current: Dict[str, Any]) -> bool:
        """风险等级是否不同（仅比较等级值，不关心是否攻击）。"""
        a = (original or {}).get("risk_level")
        b = (current or {}).get("risk_level")
        return a != b

    @staticmethod
    def _result_summary(rr: ReplayResult, verbose: bool = False) -> Dict[str, Any]:
        base = {
            "record_id": rr.record_id,
            "status": rr.status,
            "risk_level_changed": rr.risk_level_changed,
            "original_risk": rr.orig_risk,
            "current_risk": rr.curr_risk,
            "original_attack_type": rr.orig_attack_type,
            "current_attack_type": rr.curr_attack_type,
            "original_confidence": rr.orig_confidence,
            "current_confidence": rr.curr_confidence,
            "replayed_at": rr.replayed_at,
        }
        if verbose:
            base["original_detection"] = rr.original_detection
            base["current_detection"] = rr.current_detection
        return base
