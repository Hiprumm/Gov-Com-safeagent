# -*- coding: utf-8 -*-
"""可观测性指标采集（进程内单例）

- HTTP 请求计数：按路径前缀分类 + 状态类（2xx/4xx/5xx）
- 安全检测事件计数：按风险级 + 攻击类型
- LLM 调用统计：成功/失败/超时/切换 + 延迟（avg/p95）
- 24h 分钟滚动窗口（deque maxlen=1440）供趋势图
- 多 worker 下各进程独立计数：/api/metrics 返回 worker_pid，前端标注"当前 worker 视图"
"""
import os
import threading
import time
from collections import deque
from datetime import datetime

# 路径前缀 → 大盘统计分类（顺序匹配，覆盖主要业务接口）
PATH_CLASSES = [
    ("security.detect", "/api/security/"),
    ("agent", "/api/agent/"),
    ("audit", "/api/audit/"),
    ("dashboard", "/api/dashboard/"),
    ("auth", "/api/auth/"),
    ("compliance", "/api/compliance/"),
    ("governance", "/api/emergency/"),
    ("ecosystem", "/api/ecosystem/"),
    ("pipl", "/api/pipl/"),
    ("model", "/api/model/"),
]

WINDOW_MINUTES = 1440          # 24h 滚动窗口
MAX_LATENCY_SAMPLES = 1000     # LLM 延迟样本上限（近 1000 次）
BLOCKED_RISKS = ("medium", "high", "critical")


class MetricsCollector:
    """轻量进程内指标采集。所有方法线程安全。"""

    def __init__(self):
        self._start = time.time()
        self._lock = threading.Lock()
        self._buckets: deque = deque(maxlen=WINDOW_MINUTES)  # 每分钟一桶
        self._http_total = 0
        self._detect_total = 0
        self._llm_total = 0
        self._llm_ok = 0
        self._llm_fail = 0
        self._llm_timeout = 0
        self._llm_switch = 0
        self._llm_latencies: deque = deque(maxlen=MAX_LATENCY_SAMPLES)

    # --------------------------------------------------------------
    # 打点
    # --------------------------------------------------------------
    @staticmethod
    def _ts() -> str:
        return datetime.now().strftime("%Y-%m-%dT%H:%M")

    def _bucket(self) -> dict:
        ts = self._ts()
        if self._buckets and self._buckets[-1]["ts"] == ts:
            return self._buckets[-1]
        b = {"ts": ts, "http": {}, "detect": {}, "llm": {"total": 0, "ok": 0, "fail": 0, "timeout": 0}}
        self._buckets.append(b)
        return b

    @staticmethod
    def _classify_path(path: str) -> str:
        for name, prefix in PATH_CLASSES:
            if path.startswith(prefix):
                return name
        return "other"

    def record_http(self, path: str, status: int, latency_ms: float):
        """HTTP 请求打点（按路径前缀 + 状态类）"""
        cls = self._classify_path(path)
        status_cls = f"{status // 100}xx"
        with self._lock:
            self._http_total += 1
            b = self._bucket()
            key = f"{cls}:{status_cls}"
            b["http"][key] = b["http"].get(key, 0) + 1

    def record_detect(self, risk: str, attack_type: str):
        """安全检测事件打点（risk/attack_type 均为小写字符串）"""
        risk = (risk or "none").lower()
        attack = (attack_type or "none").lower()
        with self._lock:
            self._detect_total += 1
            b = self._bucket()
            key = f"{risk}:{attack}"
            b["detect"][key] = b["detect"].get(key, 0) + 1

    def record_llm(self, ok: bool, timeout: bool = False, switched: bool = False, ms: float = 0.0):
        """LLM 调用打点（主/备用调用都记录；switched=本次走备用）"""
        with self._lock:
            self._llm_total += 1
            if ok:
                self._llm_ok += 1
            elif timeout:
                self._llm_timeout += 1
            else:
                self._llm_fail += 1
            if switched:
                self._llm_switch += 1
            if ms > 0:
                self._llm_latencies.append(ms)
            b = self._bucket()
            b["llm"]["total"] += 1
            if ok:
                b["llm"]["ok"] += 1
            elif timeout:
                b["llm"]["timeout"] += 1
            else:
                b["llm"]["fail"] += 1

    # --------------------------------------------------------------
    # 快照
    # --------------------------------------------------------------
    def snapshot(self) -> dict:
        with self._lock:
            latencies = sorted(self._llm_latencies) if self._llm_latencies else []
            buckets = list(self._buckets)
            llm_total = self._llm_total
            llm_ok = self._llm_ok
            llm_fail = self._llm_fail
            llm_timeout = self._llm_timeout
            llm_switch = self._llm_switch

        avg_ms = round(sum(latencies) / len(latencies), 1) if latencies else 0
        p95_ms = round(latencies[int(len(latencies) * 0.95)], 1) if latencies else 0

        http_by_prefix: dict = {}
        http_trend: list = []
        detect_by_risk: dict = {}
        detect_trend: list = []
        llm_trend: list = []

        for b in buckets:
            # HTTP 桶
            h = {"ts": b["ts"], "total": 0, "2xx": 0, "4xx": 0, "5xx": 0}
            for key, v in b["http"].items():
                cls, sc = key.split(":", 1)
                http_by_prefix[cls] = http_by_prefix.get(cls, 0) + v
                h["total"] += v
                if sc == "2xx":
                    h["2xx"] += v
                elif sc == "4xx":
                    h["4xx"] += v
                elif sc == "5xx":
                    h["5xx"] += v
            http_trend.append(h)
            # 检测桶
            d = {"ts": b["ts"], "total": 0, "blocked": 0}
            for key, v in b["detect"].items():
                risk, _at = key.split(":", 1)
                detect_by_risk[risk] = detect_by_risk.get(risk, 0) + v
                d["total"] += v
                if risk in BLOCKED_RISKS:
                    d["blocked"] += v
            detect_trend.append(d)
            # LLM 桶
            lb = b["llm"]
            l = {"ts": b["ts"], "total": lb["total"], "ok": lb["ok"], "fail": lb["fail"], "timeout": lb["timeout"]}
            llm_trend.append(l)

        return {
            "uptime_s": int(time.time() - self._start),
            "worker_pid": os.getpid(),
            "http": {
                "total": self._http_total,
                "by_prefix": http_by_prefix,
                "trend": http_trend,
            },
            "detect": {
                "total": self._detect_total,
                "by_risk": detect_by_risk,
                "trend": detect_trend,
            },
            "llm": {
                "total": llm_total,
                "ok": llm_ok,
                "fail": llm_fail,
                "timeout": llm_timeout,
                "switch": llm_switch,
                "avg_ms": avg_ms,
                "p95_ms": p95_ms,
                "trend": llm_trend,
            },
        }


# 模块级单例（FastAPI 多 worker 下各进程独立实例）
_collector: MetricsCollector | None = None
_collector_lock = threading.Lock()


def get_metrics_collector() -> MetricsCollector:
    global _collector
    if _collector is None:
        with _collector_lock:
            if _collector is None:
                _collector = MetricsCollector()
    return _collector
