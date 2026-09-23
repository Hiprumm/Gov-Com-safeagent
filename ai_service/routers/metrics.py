# -*- coding: utf-8 -*-
"""Prometheus /metrics 端点（阶段7：可观测性）

桥接策略：metrics_collector（进程内单例）负责业务埋点（record_detect/record_llm/
record_http/record_routing），本模块在每次被抓取（scrape）时调用其 snapshot()
拿当前值，再推进 prometheus_client 的指标对象——计数类按差值 inc，瞬时值直接 set，
不重复埋点。

维度映射（以 metrics_collector 实际数据结构为准）：
- detect 快照按 risk 聚合（无 layer/rule 维度）→ safeagent_detect_requests_total{risk}
- http 快照 by_prefix 与状态类分属两处聚合，无法交叉 → 拆成
  safeagent_http_requests_total{path_prefix} + safeagent_http_status_total{status_class}
- LLM ok/fail/timeout → safeagent_llm_calls_total{status=success/fail/timeout}
- 审批队列长度：approval_engine.list_pending()（黑盒查询，非埋点）
- 审计链校验失败：audit_logger.verify_chain() 的 tampered 条数（黑盒查询，带 TTL 缓存）

暂无来源（保留指标位，待主流程补打点）：
- safeagent_detect_latency_ms：collector 暂无逐样本检测耗时
- safeagent_sandbox_executions_total：沙箱执行结果暂无计数来源
"""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import APIRouter
from fastapi.responses import Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

from metrics_collector import get_metrics_collector

router = APIRouter()

# ----------------------------------------------------------------------
# prometheus 指标定义（import 本模块即注册；METRICS_ENABLED=False 时
# main.py 不装配本 router，指标随之不暴露）
# ----------------------------------------------------------------------
# 检测（来源：snapshot().detect.by_risk，risk 维度）
DETECT_REQUESTS = Counter(
    "safeagent_detect_requests_total",
    "安全检测请求总数（按风险等级，桥接 metrics_collector）",
    ["risk"],
)
# 拦截（medium/high/critical 之和）
DETECT_BLOCKED = Counter(
    "safeagent_detect_blocked_total",
    "被拦截（medium/high/critical）的检测请求总数",
)
# P2-1 检测分流（plain=普通短文本三件套 / deep=深度检测）
DETECT_ROUTED = Counter(
    "safeagent_detect_routed_total",
    "检测分流计数（plain=三件套 / deep=深度检测）",
    ["route"],
)
# 检测耗时分布
# TODO(可观测性): metrics_collector 暂无逐样本检测耗时，接入后在此 observe 即可生效
DETECT_LATENCY = Histogram(
    "safeagent_detect_latency_ms",
    "检测耗时分布（毫秒）",
    buckets=(5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000),
)
# LLM 调用（ok→success / fail / timeout）
LLM_CALLS = Counter(
    "safeagent_llm_calls_total",
    "LLM 调用总数（status: success/fail/timeout）",
    ["status"],
)
LLM_SWITCH = Counter(
    "safeagent_llm_switch_total",
    "LLM 备用模型切换次数",
)
# LLM 延迟（快照仅提供聚合值 avg/p95，故用 Gauge 而非 Histogram）
LLM_LATENCY_AVG = Gauge(
    "safeagent_llm_latency_avg_ms",
    "LLM 调用平均耗时（毫秒，近 1000 次样本）",
)
LLM_LATENCY_P95 = Gauge(
    "safeagent_llm_latency_p95_ms",
    "LLM 调用耗时 P95（毫秒，近 1000 次样本）",
)
# HTTP（by_prefix 无状态类交叉维度，拆两个指标）
HTTP_REQUESTS = Counter(
    "safeagent_http_requests_total",
    "HTTP 请求总数（按路径前缀分类）",
    ["path_prefix"],
)
HTTP_STATUS = Counter(
    "safeagent_http_status_total",
    "HTTP 响应状态类计数（2xx/4xx/5xx）",
    ["status_class"],
)
# 审批队列长度（瞬时值）
APPROVAL_QUEUE = Gauge(
    "safeagent_approval_queue_length",
    "待审批队列长度（approval_engine.list_pending）",
)
# 审计链校验失败（黑盒读取 audit 模块，瞬时值）
AUDIT_VERIFY_FAILURES = Gauge(
    "safeagent_audit_verify_failures_total",
    "审计链校验失败记录数（verify_chain 的 tampered 条数；-1 表示采集异常）",
)
# 沙箱执行结果
# TODO(可观测性): 沙箱执行暂无计数来源（docker_executor 无统计、审计中
# tool_execution 的 status 硬编码为 success），主流程补 record_sandbox 打点后此指标生效
SANDBOX_EXECUTIONS = Counter(
    "safeagent_sandbox_executions_total",
    "沙箱执行计数（status: success/fail/rejected）",
    ["status"],
)
# 服务存活
UPTIME = Gauge(
    "safeagent_uptime_seconds",
    "服务存活时长（秒，当前 worker 进程）",
)

# ----------------------------------------------------------------------
# 快照 → prometheus 桥接
# ----------------------------------------------------------------------
# 上次快照基线：用于把"collector 累计值"转成"prometheus Counter 增量"。
# 注意 collector 的 by_risk/by_prefix 为 24h 滚动窗口聚合（分钟桶 deque），
# 窗口挤出旧桶时数值可能回退：Counter 只增不减，负增量直接跳过并重置基线，
# 代价是窗口滚动后增长速率可能被低估（24h 尺度，可接受）。
_last_snapshot: dict = {}
_snap_lock = threading.Lock()

# 审计校验缓存：verify_chain 全量重算哈希链，开销较大，限时缓存
_AUDIT_CACHE_TTL = 120
_audit_cache = {"ts": 0.0, "failures": 0}


def _advance(counter: Counter, key: str, value: int, **labels) -> None:
    """按差值把快照累计值推进到 prometheus Counter（需持有 _snap_lock）"""
    delta = value - _last_snapshot.get(key, 0)
    if delta > 0:
        if labels:
            counter.labels(**labels).inc(delta)
        else:
            counter.inc(delta)
    # 负增量（快照回退）时也重置基线，避免后续持续漏计
    _last_snapshot[key] = value


def _approval_queue_length() -> int:
    """待审批数量：黑盒查询 approval_engine（与 /api/system/status 同源）"""
    try:
        from app_deps import approval_engine
        return len(approval_engine.list_pending())
    except Exception:  # noqa: BLE001
        return 0


def _audit_verify_failures() -> int:
    """审计链校验失败数：黑盒读取 audit_logger.verify_chain()（TTL 缓存）"""
    now = time.time()
    if now - _audit_cache["ts"] < _AUDIT_CACHE_TTL:
        return _audit_cache["failures"]
    try:
        from app_deps import audit_logger
        result = audit_logger.verify_chain()
        failures = len(result.get("tampered") or [])
    except Exception:  # noqa: BLE001
        failures = -1  # 采集异常：-1 表示未知，便于告警侧区分
    _audit_cache["ts"] = now
    _audit_cache["failures"] = failures
    return failures


def _refresh_from_collector() -> None:
    """拉取 metrics_collector 快照，推进/刷新上述 prometheus 指标"""
    snap = get_metrics_collector().snapshot()

    with _snap_lock:
        # ---- 检测：按风险等级 + 拦截 + 分流 ----
        by_risk = snap["detect"].get("by_risk") or {}
        for risk, cnt in by_risk.items():
            _advance(DETECT_REQUESTS, f"detect:{risk}", int(cnt), risk=str(risk))
        blocked = sum(int(v) for k, v in by_risk.items() if k in ("medium", "high", "critical"))
        _advance(DETECT_BLOCKED, "detect:blocked", blocked)
        routing = snap.get("routing") or {}
        for route in ("plain", "deep"):
            _advance(DETECT_ROUTED, f"routed:{route}", int(routing.get(route, 0)), route=route)

        # ---- LLM：调用结果 / 切换 / 延迟聚合值 ----
        llm = snap["llm"]
        _advance(LLM_CALLS, "llm:success", int(llm["ok"]), status="success")
        _advance(LLM_CALLS, "llm:fail", int(llm["fail"]), status="fail")
        _advance(LLM_CALLS, "llm:timeout", int(llm["timeout"]), status="timeout")
        _advance(LLM_SWITCH, "llm:switch", int(llm["switch"]))
        LLM_LATENCY_AVG.set(llm["avg_ms"])
        LLM_LATENCY_P95.set(llm["p95_ms"])

        # ---- HTTP：路径前缀 / 状态类（两维无交叉，分别聚合） ----
        for prefix, cnt in (snap["http"].get("by_prefix") or {}).items():
            _advance(HTTP_REQUESTS, f"http:{prefix}", int(cnt), path_prefix=str(prefix))
        status_sum = {"2xx": 0, "4xx": 0, "5xx": 0}
        for bucket in snap["http"].get("trend") or []:
            for sc in status_sum:
                status_sum[sc] += int(bucket.get(sc, 0))
        for sc, cnt in status_sum.items():
            _advance(HTTP_STATUS, f"http_status:{sc}", cnt, status_class=sc)

        # ---- 存活时长 ----
        UPTIME.set(snap["uptime_s"])

    # ---- 瞬时值（锁外，黑盒查询） ----
    APPROVAL_QUEUE.set(_approval_queue_length())
    AUDIT_VERIFY_FAILURES.set(_audit_verify_failures())


@router.get("/metrics")
def prometheus_metrics():
    """Prometheus 抓取端点：先从 metrics_collector 取快照再输出（与
    既有 /api/metrics JSON 快照端点并存、互不影响）"""
    _refresh_from_collector()
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
