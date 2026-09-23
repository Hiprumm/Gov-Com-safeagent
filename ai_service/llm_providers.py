# -*- coding: utf-8 -*-
"""LLM 供应商适配（P2-6：多供应商接入对话主链）+ 多供应商容灾

- zhipu   : 智谱 GLM（langchain_community ChatZhipuAI）
- openai  : OpenAI 兼容端点（langchain_openai ChatOpenAI，支持内网 vLLM/Ollama/私有网关/国产模型）

依赖 llm_runtime 解析出的运行时配置（provider/api_key/base_url/model + backup_*），
返回 LangChain BaseChatModel 或 FailoverChatModel（与现有 LCEL 链 prompt_template | llm | parser 兼容）。

容灾策略：
- 主模型调用失败/超时 → 自动切换备用模型重试；
- 主模型连续失败 ≥ max_consecutive_failures 次 → 进入 cooldown 冷却期，期间直走备用
  （避免"每次都先撞主模型超时"拖慢整体延迟）；
- 两级都失败：由调用方按既有逻辑降级（gov_agent 规则回复 / llm_classifier 本地启发式）。
"""
import logging
import threading
import time

logger = logging.getLogger("llm_providers")


def _is_timeout(e: Exception) -> bool:
    """判定异常是否为超时类（用于指标统计 timeout 计数）"""
    from httpx import TimeoutException as HttpxTimeout
    if isinstance(e, (TimeoutError, HttpxTimeout)):
        return True
    import asyncio
    if isinstance(e, asyncio.TimeoutError):
        return True
    msg = str(e).lower()
    return "timeout" in msg or "timed out" in msg


# ----------------------------------------------------------------------
# 降级审计（P0-5）：熔断/切换事件写审计链，不静默降级。
# - circuit_open / failover_exhausted：状态迁移类，每次必写；
# - fallback_switch：每次切换都写会刷屏，按事件类 60s 节流；
# - 审计写入失败绝不影响主流程（可观测性不能反过来拖垮调用方）。
# ----------------------------------------------------------------------
_AUDIT_THROTTLE_SECONDS = 60.0
_audit_last_emit: dict = {}
_audit_lock = threading.Lock()


def _audit_degradation(event: str, detail: str, throttle: bool = False) -> None:
    """写一条 LLM 容灾降级审计事件（action_type=llm_degradation）。"""
    now = time.time()
    if throttle:
        with _audit_lock:
            last = _audit_last_emit.get(event, 0.0)
            if now - last < _AUDIT_THROTTLE_SECONDS:
                return
            _audit_last_emit[event] = now
    try:
        from audit.audit_logger import AuditLogger
        AuditLogger().create_log(
            user_id="system", user_role="system", agent_id="llm_failover",
            action_type="llm_degradation",
            action_details={"event": event, "detail": detail[:500]},
        )
    except Exception:  # noqa: BLE001
        logger.debug("降级审计写入失败（忽略）", exc_info=True)


class FailoverChatModel:
    """带主备故障切换的对话模型包装（薄包装，不继承 BaseChatModel）。

    只透传调用方实际使用的能力：invoke / stream / batch（同步）
    与 ainvoke / astream / abatch（异步），返回类型与底层模型一致。
    """

    def __init__(self, primary, backup, max_consecutive_failures: int = 3,
                 cooldown_seconds: int = 60):
        self.primary = primary
        self.backup = backup
        self.name = f"failover({getattr(primary, 'model_name', 'primary')}->{getattr(backup, 'model_name', 'backup')})"
        self._max_fails = max_consecutive_failures
        self._cooldown = cooldown_seconds
        self._fails = 0
        self._cooldown_until = 0.0
        self._lock = threading.Lock()

    # --------------------------------------------------------------
    # 状态机
    # --------------------------------------------------------------
    def _in_cooldown(self) -> bool:
        with self._lock:
            return time.time() < self._cooldown_until

    def _primary_ok(self):
        with self._lock:
            self._fails = 0

    def _primary_fail(self, reason: str = ""):
        circuit_opened = False
        with self._lock:
            self._fails += 1
            if self._fails >= self._max_fails:
                self._cooldown_until = time.time() + self._cooldown
                self._fails = 0
                circuit_opened = True
        if circuit_opened:
            logger.warning("主模型连续失败 %d 次，进入 %ds 冷却期（直走备用模型）",
                           self._max_fails, self._cooldown)
            _audit_degradation(
                "circuit_open",
                f"主模型连续失败 {self._max_fails} 次，进入 {self._cooldown}s 冷却期（期间直走备用模型）")
        # 切换事件（节流 60s）：主模型失败 → 本次调用改走备用
        _audit_degradation("fallback_switch",
                           f"主模型调用失败切换备用模型：{reason[:300]}", throttle=True)

    # --------------------------------------------------------------
    # 同步能力
    # --------------------------------------------------------------
    def invoke(self, input, config=None, **kwargs):
        from metrics_collector import get_metrics_collector
        mc = get_metrics_collector()
        start = time.perf_counter()
        switched = self._in_cooldown()
        if not switched:
            try:
                result = (self.primary.invoke(input, config=config, **kwargs)
                          if config is not None else self.primary.invoke(input, **kwargs))
                self._primary_ok()
                mc.record_llm(True, False, False, (time.perf_counter() - start) * 1000)
                return result
            except Exception as e:  # noqa: BLE001
                timeout = _is_timeout(e)
                self._primary_fail(str(e))
                mc.record_llm(False, timeout, False, (time.perf_counter() - start) * 1000)
                logger.warning("主模型调用失败（timeout=%s）：%s，切换备用模型", timeout, str(e)[:200])
                switched = True
        # 备用模型
        try:
            result = (self.backup.invoke(input, config=config, **kwargs)
                      if config is not None else self.backup.invoke(input, **kwargs))
            mc.record_llm(True, False, switched, (time.perf_counter() - start) * 1000)
            return result
        except Exception as e:  # noqa: BLE001
            timeout = _is_timeout(e)
            mc.record_llm(False, timeout, switched, (time.perf_counter() - start) * 1000)
            _audit_degradation("failover_exhausted",
                               f"主备模型均失败（invoke，timeout={timeout}）：{str(e)[:300]}",
                               throttle=True)
            raise

    def stream(self, input, config=None, **kwargs):
        from metrics_collector import get_metrics_collector
        mc = get_metrics_collector()
        start = time.perf_counter()
        switched = self._in_cooldown()
        if switched:
            # 冷却期：直走备用
            try:
                for chunk in (self.backup.stream(input, config=config, **kwargs)
                              if config is not None else self.backup.stream(input, **kwargs)):
                    yield chunk
                mc.record_llm(True, False, True, (time.perf_counter() - start) * 1000)
            except Exception as e:  # noqa: BLE001
                mc.record_llm(False, _is_timeout(e), True, (time.perf_counter() - start) * 1000)
                raise
            return
        # 主模型
        yielded_any = False
        try:
            for chunk in (self.primary.stream(input, config=config, **kwargs)
                          if config is not None else self.primary.stream(input, **kwargs)):
                yielded_any = True
                yield chunk
            self._primary_ok()
            mc.record_llm(True, False, False, (time.perf_counter() - start) * 1000)
        except Exception as e:  # noqa: BLE001
            timeout = _is_timeout(e)
            self._primary_fail(str(e))
            mc.record_llm(False, timeout, False, (time.perf_counter() - start) * 1000)
            if yielded_any:
                # 已产出部分 token：无法无损重放，交给调用方既有降级（规则回复/空结果回退）
                logger.warning("主模型流式中途失败（timeout=%s）：%s", timeout, str(e)[:200])
                raise
            # 尚未产出任何 token：切换备用模型完整重放
            logger.warning("主模型流式调用失败（timeout=%s）：%s，切换备用模型", timeout, str(e)[:200])
            try:
                for chunk in (self.backup.stream(input, config=config, **kwargs)
                              if config is not None else self.backup.stream(input, **kwargs)):
                    yield chunk
                mc.record_llm(True, False, True, (time.perf_counter() - start) * 1000)
            except Exception as e2:  # noqa: BLE001
                mc.record_llm(False, _is_timeout(e2), True, (time.perf_counter() - start) * 1000)
                _audit_degradation("failover_exhausted",
                                   f"主备模型均失败（stream，timeout={_is_timeout(e2)}）：{str(e2)[:300]}",
                                   throttle=True)
                raise

    def batch(self, inputs, config=None, **kwargs):
        return [self.invoke(i, config=config, **kwargs) for i in inputs]

    # --------------------------------------------------------------
    # 异步能力（LangChain Runnable 接口完整性；异步环境透传主备逻辑）
    # --------------------------------------------------------------
    async def ainvoke(self, input, config=None, **kwargs):
        from metrics_collector import get_metrics_collector
        mc = get_metrics_collector()
        start = time.perf_counter()
        switched = self._in_cooldown()
        if not switched:
            try:
                result = (await self.primary.ainvoke(input, config=config, **kwargs)
                          if config is not None else await self.primary.ainvoke(input, **kwargs))
                self._primary_ok()
                mc.record_llm(True, False, False, (time.perf_counter() - start) * 1000)
                return result
            except Exception as e:  # noqa: BLE001
                timeout = _is_timeout(e)
                self._primary_fail(str(e))
                mc.record_llm(False, timeout, False, (time.perf_counter() - start) * 1000)
                logger.warning("主模型异步调用失败（timeout=%s）：%s，切换备用模型", timeout, str(e)[:200])
                switched = True
        try:
            result = (await self.backup.ainvoke(input, config=config, **kwargs)
                      if config is not None else await self.backup.ainvoke(input, **kwargs))
            mc.record_llm(True, False, switched, (time.perf_counter() - start) * 1000)
            return result
        except Exception as e:  # noqa: BLE001
            timeout = _is_timeout(e)
            mc.record_llm(False, timeout, switched, (time.perf_counter() - start) * 1000)
            _audit_degradation("failover_exhausted",
                               f"主备模型均失败（ainvoke，timeout={timeout}）：{str(e)[:300]}",
                               throttle=True)
            raise

    async def astream(self, input, config=None, **kwargs):
        from metrics_collector import get_metrics_collector
        mc = get_metrics_collector()
        start = time.perf_counter()
        switched = self._in_cooldown()
        if switched:
            try:
                async for chunk in (self.backup.astream(input, config=config, **kwargs)
                                    if config is not None else self.backup.astream(input, **kwargs)):
                    yield chunk
                mc.record_llm(True, False, True, (time.perf_counter() - start) * 1000)
            except Exception as e:  # noqa: BLE001
                mc.record_llm(False, _is_timeout(e), True, (time.perf_counter() - start) * 1000)
                raise
            return
        yielded_any = False
        try:
            async for chunk in (self.primary.astream(input, config=config, **kwargs)
                                if config is not None else self.primary.astream(input, **kwargs)):
                yielded_any = True
                yield chunk
            self._primary_ok()
            mc.record_llm(True, False, False, (time.perf_counter() - start) * 1000)
        except Exception as e:  # noqa: BLE001
            timeout = _is_timeout(e)
            self._primary_fail(str(e))
            mc.record_llm(False, timeout, False, (time.perf_counter() - start) * 1000)
            if yielded_any:
                raise
            try:
                async for chunk in (self.backup.astream(input, config=config, **kwargs)
                                    if config is not None else self.backup.astream(input, **kwargs)):
                    yield chunk
                mc.record_llm(True, False, True, (time.perf_counter() - start) * 1000)
            except Exception as e2:  # noqa: BLE001
                mc.record_llm(False, _is_timeout(e2), True, (time.perf_counter() - start) * 1000)
                _audit_degradation("failover_exhausted",
                                   f"主备模型均失败（astream，timeout={_is_timeout(e2)}）：{str(e2)[:300]}",
                                   throttle=True)
                raise

    async def abatch(self, inputs, config=None, **kwargs):
        return [await self.ainvoke(i, config=config, **kwargs) for i in inputs]


def _build_single(cfg: dict, prefix: str = ""):
    """按配置构建单个 ChatModel；无法构建返回 None。

    prefix: "" 主模型 / "backup" 备用模型，对应 cfg 中的 backup_* 字段
    """
    key = "api_key" if not prefix else "backup_api_key"
    provider_key = "provider" if not prefix else "backup_provider"
    base_key = "base_url" if not prefix else "backup_base_url"
    model_key = "model" if not prefix else "backup_model"

    provider = (cfg or {}).get(provider_key, "zhipu")
    api_key = (cfg or {}).get(key, "")
    model = (cfg or {}).get(model_key) or ""
    base_url = ((cfg or {}).get(base_key) or "").rstrip("/")
    if not api_key:
        return None

    try:
        if provider == "openai":
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(
                model=model or "gpt-4o-mini",
                temperature=0,
                api_key=api_key,
                base_url=base_url or None,
                # 30s 超时：网络悬挂时快速失败（走容灾/规则降级），避免默认 60s+ 拖慢
                request_timeout=30,
            )
        # 默认：智谱 GLM
        from langchain_community.chat_models import ChatZhipuAI
        return ChatZhipuAI(
            model=model or "glm-4",
            temperature=0,
            zhipuai_api_key=api_key,
            # 说明：ChatZhipuAI 无超时字段，SDK 默认 60s；超时由 FailoverChatModel / 分类器兜底
        )
    except Exception as e:  # noqa: BLE001
        logger.warning("构建对话模型失败（provider=%s）: %s", provider, e)
        return None


def build_chat_model(cfg: dict):
    """按运行时配置构建对话主链模型；无法构建（未配 Key / 依赖缺失）返回 None。

    主 + 备用模型均可用时返回 FailoverChatModel（多供应商容灾）；
    仅主模型可用时返回单模型；均不可用返回 None（调用方降级处理）。
    """
    primary = _build_single(cfg, "")
    if primary is None:
        return None
    backup = _build_single(cfg, "backup")
    if backup is not None:
        logger.info("多供应商容灾已启用：主模型 %s，备用模型 %s",
                    getattr(primary, "model_name", primary.__class__.__name__),
                    getattr(backup, "model_name", backup.__class__.__name__))
        return FailoverChatModel(primary, backup)
    return primary
