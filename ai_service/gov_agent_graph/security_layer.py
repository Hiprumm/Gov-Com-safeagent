import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import Dict, Any, List
from models.state import AgentState
from models.schemas import RiskLevel, AttackType, DetectionResult, ToolRiskResult, InputSource
from security.input_detector import InputDetectionService
from security.tool_risk_evaluator import ToolRiskEvaluator
from security.approval_engine import ApprovalEngine
from security.chain_analyzer import ChainAnalyzer, ChainAlert
from security.cross_source_correlator import get_cross_source_correlator
from security.memory_guard import MemoryGuard
from security.operation_guard import get_operation_guard, OperationIntent
from security.capability_token import get_capability_token_manager
from security.runtime_monitor import get_runtime_monitor
from security.tool_permission_matrix import PermissionMatrix, PermissionLevel
from security.browser_access_control import BrowserAccessController
from audit.audit_logger import AuditLogger


class SecurityLayer:
    _RISK_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    def __init__(self):
        self.input_detector = InputDetectionService()
        self.tool_evaluator = ToolRiskEvaluator()
        self.approval_engine = ApprovalEngine()
        self.audit_logger = AuditLogger()
        self.chain_analyzer = ChainAnalyzer()
        self.cross_source_correlator = get_cross_source_correlator()
        self.memory_guard = MemoryGuard()
        self.operation_guard = get_operation_guard()
        # T4: 运行时工具调用控制
        self.runtime_monitor = get_runtime_monitor()
        self.permission_matrix = PermissionMatrix()
        self.browser_controller = BrowserAccessController()
        # 方向B-5：会话级审批解锁缓存（session_id -> {tool_name: 解锁时间戳}）
        # 一次审批通过后，同一会话内同类工具调用复用解锁，不再重复审批
        import threading
        self._session_unlocks: Dict[str, Dict[str, float]] = {}
        self._unlock_lock = threading.Lock()
        # 方向B-2：会话级能力令牌（默认最小权限，审批解锁后授予危险能力）
        self.capability_tokens = get_capability_token_manager()

    def detect_input(self, state: AgentState) -> AgentState:
        user_input = state["user_input"]
        input_source = state["input_source"]
        session_id = state.get("session_id", "")
        conversation_history = state.get("conversation_history", [])
        detection_results = []

        # ======== 历史记忆读取检测（修复"历史记忆"多源输入检测空白） ========
        # 对从历史会话读取的记忆做二次安全检测（check_before_read）
        memory_read_risk = RiskLevel.NONE
        if conversation_history:
            for msg in conversation_history[-20:]:  # 检测最近20条历史记忆
                content = msg.get("content", "")
                if not content:
                    continue
                read_result = self.memory_guard.check_before_read(
                    content,
                    session_id=session_id,
                    memory_key="conversation_history"
                )
                if read_result.is_poisoned:
                    memory_read_risk = max(
                        memory_read_risk,
                        read_result.risk_level,
                        key=lambda r: {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[r.value]
                    )
                    detection_results.append(DetectionResult(
                        risk_level=read_result.risk_level,
                        attack_type=read_result.attack_type or AttackType.MEMORY_POISONING,
                        confidence=read_result.confidence,
                        evidence=[f"[历史记忆读取拦截] {e}" for e in read_result.evidence],
                        source=InputSource.AGENT_MEMORY,
                        processed_text=content[:2000]
                    ))

            # ======== 跨会话异常检测（analyze_session_history） ========
            if len(conversation_history) >= 3:
                history_anomaly = self.memory_guard.analyze_session_history(
                    conversation_history, session_id=session_id
                )
                if history_anomaly.is_poisoned:
                    memory_read_risk = max(
                        memory_read_risk,
                        history_anomaly.risk_level,
                        key=lambda r: {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[r.value]
                    )
                    detection_results.append(DetectionResult(
                        risk_level=history_anomaly.risk_level,
                        attack_type=AttackType.MEMORY_POISONING,
                        confidence=history_anomaly.confidence,
                        evidence=history_anomaly.evidence,
                        source=InputSource.AGENT_MEMORY,
                        processed_text=""
                    ))

        # ======== 当前输入检测（原有逻辑，包含第6层 check_before_write） ========
        current_detection = self.input_detector.detect_single_input(
            user_input, input_source, session_id=session_id or "default"
        )
        detection_results.append(current_detection)

        # 合并风险等级：当前输入风险 vs 历史记忆风险
        all_risks = [current_detection.risk_level, memory_read_risk]
        final_risk = max(all_risks, key=lambda r: self._RISK_ORDER[r.value])

        # 拦截阈值由安全策略中心统一管控（medium/high/critical 热配置）
        try:
            from security.policy_manager import get_policy_manager
            _should_block = get_policy_manager().should_block(final_risk)
        except Exception:
            _should_block = final_risk in [RiskLevel.HIGH, RiskLevel.CRITICAL]

        # 审计日志
        self.audit_logger.create_log(
            user_id=state.get("user_id") or "user",
            user_role=state.get("user_role") or "user",
            agent_id="gov_agent",
            action_type="input_detection",
            action_details={
                "input": user_input[:100],
                "source": input_source,
                "history_size": len(conversation_history),
                "memory_read_risk": memory_read_risk.value
            },
            risk_level=final_risk,
            detection_result=current_detection,
            is_blocked=_should_block,
            blocking_reason=f"检测到{final_risk.value}风险，触发拦截阈值策略" if _should_block else None,
            session_id=session_id,
        )

        # 跨来源关联分析
        if final_risk != RiskLevel.NONE:
            correlated_threats = self.cross_source_correlator.record_event(
                session_id=session_id,
                source=input_source,
                risk_level=final_risk.value,
                attack_type=current_detection.attack_type.value if current_detection.attack_type else None,
                confidence=current_detection.confidence,
                content_preview=user_input[:200],
                evidence=current_detection.evidence[:5] if current_detection.evidence else [],
            )
            if correlated_threats:
                for threat in correlated_threats:
                    self.audit_logger.create_log(
                        user_id=state.get("user_id") or "user",
                        user_role=state.get("user_role") or "user",
                        agent_id="gov_agent",
                        action_type="cross_source_correlation",
                        action_details={
                            "pattern": threat.pattern.value,
                            "severity": threat.severity,
                            "sources": threat.involved_sources,
                            "attack_chain": threat.attack_chain,
                        },
                        risk_level=threat.severity,
                        is_blocked=threat.severity == "critical",
                        blocking_reason=f"检测到跨来源复合攻击: {threat.pattern.value}",
                    )

        return {
            **state,
            "detection_results": detection_results,
            "risk_level": final_risk,
            "can_proceed": not _should_block,
            "guard_results": [],
            "runtime_trace": [],
            "anomaly_alerts": [],
            "current_step": "input_detection_completed",
        }

    def _get_last_think_reasoning(self, session_id: str) -> str:
        """获取会话最近一次 Think 阶段的推理原文（用于审计不丢失推理内容）"""
        for s in reversed(self.runtime_monitor.get_session_trace(session_id)):
            if s.step_type == "think":
                return s.reasoning
        return ""

    def evaluate_tool_call(self, state: AgentState) -> AgentState:
        tool_calls = state["tool_calls"]
        risk_results = []
        approval_requests = []
        
        for tool_call in tool_calls:
            tool_name = tool_call.get("name", "")
            tool_args = tool_call.get("args", {})
            
            from models.schemas import ToolCallRequest
            request = ToolCallRequest(
                tool_name=tool_name,
                tool_args=tool_args,
                user_role=state.get("user_role") or "user",
                agent_id="gov_agent",
                context=state.get("user_input", "")
            )
            
            risk_result = self.tool_evaluator.evaluate(request)
            risk_results.append(risk_result)
            
            self.audit_logger.create_log(
                user_id=state.get("user_id") or "user",
                user_role=state.get("user_role") or "user",
                agent_id="gov_agent",
                action_type="tool_risk_evaluation",
                action_details={"tool_name": tool_name, "tool_args": tool_args},
                risk_level=risk_result.risk_level,
                tool_call_result=risk_result,
                approval_status="pending" if risk_result.requires_approval else "auto_approved",
                is_blocked=risk_result.risk_level == RiskLevel.CRITICAL,
                blocking_reason=(f"工具风险评估为严重风险: "
                                 f"{'; '.join(risk_result.risk_details[:3])}"
                                 if risk_result.risk_level == RiskLevel.CRITICAL else None),
                session_id=state.get("session_id", "default"),
                think_text=self._get_last_think_reasoning(state.get("session_id", "default")),
            )
            
            if risk_result.requires_approval:
                approval_request = self.approval_engine.create_request(
                    user_id=state.get("user_id") or "user",
                    user_role=state.get("user_role") or "user",
                    agent_id="gov_agent",
                    action_type=f"tool_call_{tool_name}",
                    action_details={
                        **tool_args,
                        "_session_id": state.get("session_id", "default"),
                        "_tool_name": tool_name,
                        "_department": state.get("department") or "",
                        "_actor_name": state.get("display_name") or state.get("user_id") or "user",
                    },
                    risk_level=risk_result.risk_level
                )
                approval_requests.append(approval_request.dict())
        
        max_risk = max(risk_results, key=lambda r: self._RISK_ORDER.get(r.risk_level.value, 0)).risk_level if risk_results else RiskLevel.NONE
        
        # 链路检测: 记录每次工具调用并检查异常行为链
        session_id = state.get("session_id", "default")
        chain_alerts = []
        for tool_call in tool_calls:
            tool_name = tool_call.get("name", "")
            chain_alert = self.chain_analyzer.record_call(
                session_id=session_id,
                tool_name=tool_name,
                params=tool_call.get("args", {}),
                risk_level=next(
                    (r.risk_level for r in risk_results
                     if f"tool_call_{r.tool_name}" == f"tool_call_{tool_name}"
                     or r.tool_name == tool_name),
                    RiskLevel.NONE
                )
            )
            if chain_alert:
                chain_alerts.append(chain_alert)

        # 链路告警升级风险等级
        chain_risk = RiskLevel.NONE
        if chain_alerts:
            # 取最高风险等级的告警
            highest_chain_alert = max(chain_alerts, key=lambda a: a.risk_level.value)
            chain_risk = highest_chain_alert.risk_level

            # 记录链路告警到审计日志
            self.audit_logger.create_log(
                user_id=state.get("user_id") or "user",
                user_role=state.get("user_role") or "user",
                agent_id="gov_agent",
                action_type="chain_detection",
                action_details={
                    "pattern": highest_chain_alert.pattern.value,
                    "description": highest_chain_alert.description,
                    "matched_tools": [r.tool_name for r in highest_chain_alert.matched_steps],
                },
                risk_level=chain_risk,
                is_blocked=chain_risk == RiskLevel.CRITICAL,
                blocking_reason=highest_chain_alert.description if chain_risk == RiskLevel.CRITICAL else None,
            )

        # 最终风险: 单次评估 vs 链路检测 取最高
        final_risk = max_risk if max_risk.value >= chain_risk.value else chain_risk

        # ======== 操作守卫层：动作执行前的最后一道防线 ========
        # 即使输入检测和工具风险评估通过，操作守卫仍可拦截高危动作
        # （工具黑名单/参数黑名单/审批前置/速率限制）
        guard_results = []
        guard_blocked = False
        for tool_call in tool_calls:
            tool_name = tool_call.get("name", "")
            tool_args = tool_call.get("args", {})
            session_id = state.get("session_id", "default")
            user_input = state.get("user_input", "")

            intent = OperationIntent(
                tool_name=tool_name,
                parameters=tool_args if isinstance(tool_args, dict) else {},
                session_id=session_id,
                user_input=user_input,
            )
            guard_result = self.operation_guard.check_intent(intent)

            guard_dict = {
                "tool_name": tool_name,
                "allowed": guard_result.allowed,
                "reason": guard_result.reason,
                "requires_approval": guard_result.requires_approval,
                "approval_reason": guard_result.approval_reason,
                "risk_level": guard_result.risk_level.value,
                "blocked_by": guard_result.blocked_by,
                "action_type": guard_result.action_type.value,
                "rate_limited": guard_result.rate_limited,
            }
            guard_results.append(guard_dict)

            # 守卫拦截 → 升级风险
            if not guard_result.allowed:
                guard_blocked = True
                if self._RISK_ORDER.get(guard_result.risk_level.value, 0) > self._RISK_ORDER.get(final_risk.value, 0):
                    final_risk = guard_result.risk_level

                self.audit_logger.create_log(
                    user_id=state.get("user_id") or "user",
                    user_role=state.get("user_role") or "user",
                    agent_id="gov_agent",
                    action_type="operation_guard_blocked",
                    action_details={
                        "tool_name": tool_name,
                        "blocked_by": guard_result.blocked_by,
                        "reason": guard_result.reason,
                    },
                    risk_level=guard_result.risk_level,
                    is_blocked=True,
                    blocking_reason=guard_result.reason,
                    session_id=session_id,
                    think_text=self._get_last_think_reasoning(session_id),
                )
            elif guard_result.requires_approval:
                # 守卫要求审批 → 补充审批请求
                if self._RISK_ORDER.get(guard_result.risk_level.value, 0) > self._RISK_ORDER.get(final_risk.value, 0):
                    final_risk = guard_result.risk_level
                approval_request = self.approval_engine.create_request(
                    user_id=state.get("user_id") or "user",
                    user_role=state.get("user_role") or "user",
                    agent_id="gov_agent",
                    action_type=f"guard_{tool_name}",
                    action_details={
                        "tool_name": tool_name,
                        "tool_args": tool_args,
                        "guard_reason": guard_result.approval_reason,
                        "_session_id": session_id,
                        "_department": state.get("department") or "",
                        "_actor_name": state.get("display_name") or state.get("user_id") or "user",
                    },
                    risk_level=guard_result.risk_level,
                )
                approval_requests.append(approval_request.dict())

                self.audit_logger.create_log(
                    user_id=state.get("user_id") or "user",
                    user_role=state.get("user_role") or "user",
                    agent_id="gov_agent",
                    action_type="operation_guard_approval",
                    action_details={
                        "tool_name": tool_name,
                        "approval_reason": guard_result.approval_reason,
                        "action_type": guard_result.action_type.value,
                    },
                    risk_level=guard_result.risk_level,
                    approval_status="pending",
                )

        # ======== T4: 细粒度权限约束 + 浏览器访问控制 + 运行时监控 ========
        permission_violations = []
        browser_alerts = []
        for tool_call in tool_calls:
            tool_name = tool_call.get("name", "")
            tool_args = tool_call.get("args", {})
            session_id = state.get("session_id", "default")

            # 1. 工具级权限检查（已注册工具才校验，未注册工具跳过权限矩阵检查）
            try:
                perm = self.permission_matrix.get_permission(tool_name)
                can_call, call_count = self.permission_matrix.check_call_limit(tool_name, session_id)
                if not can_call:
                    permission_violations.append({
                        "tool_name": tool_name,
                        "violation": f"调用次数超限({call_count}/{perm.max_calls_per_session})",
                        "risk": "high",
                    })
                    if self._RISK_ORDER.get("high", 0) > self._RISK_ORDER.get(final_risk.value, 0):
                        final_risk = RiskLevel.HIGH
            except KeyError:
                # 未注册工具：跳过权限矩阵检查（由操作守卫层负责拦截黑名单工具）
                pass

            # 2. 参数级校验（对所有工具均生效，不依赖注册）
            param_result = self.permission_matrix.validate_parameters(tool_name, tool_args)
            if not param_result.is_valid:
                permission_violations.append({
                    "tool_name": tool_name,
                    "violation": "; ".join(param_result.violations),
                    "risk": param_result.risk_level.value,
                })
                if self._RISK_ORDER.get(param_result.risk_level.value, 0) > self._RISK_ORDER.get(final_risk.value, 0):
                    final_risk = param_result.risk_level
                # 审计：参数校验拦截原因
                self.audit_logger.create_log(
                    user_id=state.get("user_id") or "user", user_role=state.get("user_role") or "user", agent_id="gov_agent",
                    action_type="parameter_validation",
                    action_details={"tool_name": tool_name, "tool_args": tool_args,
                                    "violations": param_result.violations},
                    risk_level=param_result.risk_level,
                    is_blocked=param_result.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL],
                    blocking_reason=(f"参数校验未通过({param_result.risk_level.value}): "
                                     f"{'; '.join(param_result.violations[:3])}"
                                     if param_result.violations else None),
                    session_id=session_id,
                    think_text=self._get_last_think_reasoning(session_id),
                )

            # 3. 浏览器访问控制（网络类工具）
            url_params = {k: v for k, v in tool_args.items()
                         if isinstance(v, str) and ("http" in v.lower() or "://" in v)}
            for param_name, url_value in url_params.items():
                url_result = self.browser_controller.check_request(
                    url=url_value, parameters=tool_args, session_id=session_id,
                )
                if not url_result.is_allowed:
                    browser_alerts.append({
                        "tool_name": tool_name,
                        "url": url_value[:200],
                        "reason": url_result.reason,
                        "risk": url_result.risk_level.value,
                    })
                    if self._RISK_ORDER.get(url_result.risk_level.value, 0) > self._RISK_ORDER.get(final_risk.value, 0):
                        final_risk = url_result.risk_level
                    # 审计：浏览器访问拦截原因
                    self.audit_logger.create_log(
                        user_id=state.get("user_id") or "user", user_role=state.get("user_role") or "user", agent_id="gov_agent",
                        action_type="browser_access_blocked",
                        action_details={"tool_name": tool_name, "url": url_value[:200],
                                        "param_name": param_name},
                        risk_level=url_result.risk_level,
                        is_blocked=True,
                        blocking_reason=url_result.reason,
                        session_id=session_id,
                        think_text=self._get_last_think_reasoning(session_id),
                    )

            # 4. 运行时监控：记录Act阶段
            self.runtime_monitor.record_act(
                session_id=session_id,
                tool_name=tool_name,
                parameters=tool_args,
            )
            try:
                self.permission_matrix.record_call(tool_name, session_id)
            except KeyError:
                pass

        # 5. 根据当前风险动态调整权限
        self.permission_matrix.adjust_for_risk(session_id, final_risk)

        # 6. 运行时异常检测
        anomaly_alerts = self.runtime_monitor.check_anomalies(session_id)
        for alert in anomaly_alerts:
            if self._RISK_ORDER.get(alert.severity.value, 0) > self._RISK_ORDER.get(final_risk.value, 0):
                final_risk = alert.severity

        # 7. 级联故障检测（ASI08）
        cascade = self.runtime_monitor.detect_cascade_failure(session_id)
        if cascade:
            if self._RISK_ORDER.get(cascade.severity.value, 0) > self._RISK_ORDER.get(final_risk.value, 0):
                final_risk = cascade.severity

        # 8. 一键终止检查
        should_term, term_reason = self.runtime_monitor.should_terminate(session_id)
        if should_term:
            final_risk = RiskLevel.CRITICAL
            guard_blocked = True
            self.audit_logger.create_log(
                user_id=state.get("user_id") or "user", user_role=state.get("user_role") or "user", agent_id="gov_agent",
                action_type="runtime_termination",
                action_details={"reason": term_reason},
                risk_level=RiskLevel.CRITICAL,
                is_blocked=True,
                blocking_reason=term_reason,
                session_id=session_id,
                think_text=self._get_last_think_reasoning(session_id),
            )

        # T4: 获取运行时轨迹（包含 Think + Act 记录，即使被拦截也能审计）
        runtime_trace = [
            {
                "step_id": s.step_id,
                "step_type": s.step_type,
                "tool_name": s.tool_name,
                "reasoning": s.reasoning[:200] if s.reasoning else "",
                "risk_level": s.risk_level.value,
                "timestamp": s.timestamp,
            }
            for s in self.runtime_monitor.get_session_trace(session_id)
        ]

        return {
            **state,
            "tool_risk_results": risk_results,
            "approval_requests": approval_requests,
            "risk_level": final_risk,
            "chain_alerts": [a.__dict__ for a in chain_alerts] if chain_alerts else [],
            "guard_results": guard_results,
            "anomaly_alerts": [{
                "alert_type": a.alert_type,
                "severity": a.severity.value,
                "description": a.description,
                "step_id": a.step_id,
                "evidence": a.evidence,
            } for a in anomaly_alerts],
            "runtime_trace": runtime_trace,
            "can_proceed": (final_risk not in [RiskLevel.HIGH, RiskLevel.CRITICAL]) and not guard_blocked,
            "current_step": "tool_evaluation_completed",
        }

    @staticmethod
    def _extract_tool_name(action_type: str) -> str:
        """从 action_type（如 tool_call_export_data / guard_write_file）提取工具名"""
        for prefix in ("tool_call_", "guard_"):
            if action_type.startswith(prefix):
                return action_type[len(prefix):]
        return action_type

    def is_session_unlocked(self, session_id: str, tool_name: str) -> bool:
        """方向B-5：检查会话内是否已解锁该工具（一次审批、N 次复用）"""
        with self._unlock_lock:
            unlocks = self._session_unlocks.get(session_id, {})
            return tool_name in unlocks

    def record_session_unlock(self, session_id: str, tool_name: str) -> None:
        """方向B-5：审批通过后记录会话级解锁，后续同类工具复用"""
        import time
        with self._unlock_lock:
            self._session_unlocks.setdefault(session_id, {})[tool_name] = time.time()

    def check_approval(self, state: AgentState) -> AgentState:
        """异步审批检查：已批准/已解锁/低风险立即放行；仍待审的立即返回"待人工审批"。

        设计变更（原 30 秒同步轮询 → 异步）：
        - 原设计：同步阻塞 30 秒/请求等待人工点击，超时自动拒绝。管理员实际上
          不可能在 30 秒内完成"看到→打开面板→审查→批准"，导致人工审批流
          在同步轮询下永远无法成功（HTTP 请求挂起 60 秒+后全部超时拒绝）。
        - 新设计：需要人工审批的请求持久 pending（不拒绝），立即返回提示；
          管理员任意时间在审批面板批准（approve 端点同步授予能力+解锁会话）；
          用户重试时命中会话解锁（B-5）自动放行。
        """
        approval_requests = state["approval_requests"]
        approval_status = {}
        session_id = state.get("session_id", "default")
        pending_human = []  # 待人工审批的 (request_id, tool_name, risk)

        for request in approval_requests:
            request_id = request.get("request_id", "")
            action_type = request.get("action_type", "")
            tool_name = self._extract_tool_name(action_type)

            # 方向B-5：会话内已解锁该工具（此前人工审批过）→ 直接放行
            # 能力令牌已在此前审批通过时授予，无需重复
            if self.is_session_unlocked(session_id, tool_name):
                # 系统代批用 super_admin 角色（approve_request 的角色层级检查
                # 会拒绝低层级代批，导致审批单永远停留在 pending）
                self.approval_engine.approve_request(
                    request_id, "system", "super_admin",
                    "session unlock (B-5: 一次审批 N 次复用)"
                )
                approval_status[request_id] = "auto_approved"
                continue

            # 风险低 → 自动审批通过（无需人工）
            risk = request.get("risk_level", "none")
            risk_str = risk.value if hasattr(risk, "value") else str(risk)
            if risk_str in ("none", "low"):
                self.approval_engine.approve_request(
                    request_id, "system", "super_admin", "auto: low risk"
                )
                approval_status[request_id] = "auto_approved"
                # 方向B-2：注意——"低风险自动通过"不授予能力令牌。
                # 能力治理只信任人工审批（或其会话解锁），不信任风险分级：
                # 风险误判为 low 的危险工具在 tool_execution 仍会被令牌默认 deny。
                continue

            # 查询当前状态：管理员可能已批准（用户重试场景）
            request_data = self.approval_engine.get_request(request_id)
            if request_data is not None:
                if request_data.status == "approved":
                    approval_status[request_id] = "approved"
                    # 方向B-5：审批通过后记录会话级解锁
                    self.record_session_unlock(session_id, tool_name)
                    # 方向B-2：人工审批通过 → 授予该工具所需能力（限定范围）
                    self.capability_tokens.grant_for_tool(session_id, tool_name)
                    continue
                if request_data.status == "auto_approved":
                    approval_status[request_id] = "auto_approved"
                    self.capability_tokens.grant_for_tool(session_id, tool_name)
                    self.record_session_unlock(session_id, tool_name)
                    continue
                if request_data.status == "rejected":
                    approval_status[request_id] = "rejected"
                    continue

            # 仍 pending → 人工审批流（异步）：不阻塞、不拒绝，持久等待管理员处理
            approval_status[request_id] = "pending"
            pending_human.append({
                "request_id": request_id,
                "tool_name": tool_name,
                "risk_level": risk_str,
            })

        all_approved = all(
            status in ("approved", "auto_approved") for status in approval_status.values()
        )
        any_rejected = any(status == "rejected" for status in approval_status.values())

        return {
            **state,
            "approval_status": approval_status,
            "can_proceed": all_approved and not any_rejected and not pending_human,
            "pending_human_approval": pending_human,
            "current_step": "approval_check_completed",
        }