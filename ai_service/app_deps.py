# -*- coding: utf-8 -*-
"""应用级共享单例（P1-1 路由拆分收敛）

原 main.py 中的模块级检测/存储单例与策略热应用函数收敛于此。
main.py 与 routers/* 均从此处导入**同一实例**，保证各路由域共享同一状态
（如检测分类层开关、审计日志器、智能体实例、策略/权限中枢），避免重复初始化。
"""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from security.input_detector import InputDetectionService
from security.tool_risk_evaluator import ToolRiskEvaluator
from security.approval_engine import ApprovalEngine
from security.kb_poisoning_detector import KBPoisoningDetector
from security.cross_source_correlator import get_cross_source_correlator
from security.adversarial_mutator import BypassTester
from plugins.plugin_scanner import PluginScanner
from security.mcp_scanner import MCPScanner
from security.skill_analyzer import SkillAnalyzer
from security.mcp_combination_detector import MCPCombinationDetector
from security.operation_guard import get_operation_guard
from audit.audit_logger import AuditLogger
from audit.evaluation_metrics import EvaluationMetricsCalculator
from gov_agent_graph.gov_agent import GovAgent
from security.policy_manager import get_policy_manager
from security.permission_engine import get_permission_engine

input_detector = InputDetectionService()
tool_evaluator = ToolRiskEvaluator()
approval_engine = ApprovalEngine()
kb_poisoning_detector = KBPoisoningDetector()
# 复用模块级单例，与 correlation_analyzer 内部的 accumulator 保持一致（否则累积与查询实例不一致）
cross_source_correlator = get_cross_source_correlator()
# BypassTester 用 input_detector 的 detect_single_input 作为检测函数
bypass_tester = BypassTester(
    detector_func=lambda text, src: input_detector.detect_single_input(text, src)
)
plugin_scanner = PluginScanner()
mcp_scanner = MCPScanner()
skill_analyzer = SkillAnalyzer()
combination_detector = MCPCombinationDetector()
operation_guard = get_operation_guard()
audit_logger = AuditLogger()
metrics_calculator = EvaluationMetricsCalculator()
gov_agent = GovAgent()
# 安全策略中枢（管控台在线配置，热生效）
policy_manager = get_policy_manager()
# 统一权限决策引擎（RBAC + ABAC 单一事实来源）
permission_engine = get_permission_engine()


def _apply_policy_hot():
    """将策略热应用到模块级检测实例（LLM 分类层开关等）"""
    try:
        llm_available = bool(getattr(input_detector.llm_classifier, "api_key", ""))
        input_detector.llm_classifier.enabled = (
            policy_manager.llm_classifier_enabled and llm_available
        )
    except Exception as e:
        print(f"[POLICY] LLM 开关热应用失败: {e}")
