import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import re
import unicodedata
from typing import List, Dict, Any, Optional
from models.schemas import (
    DetectionResult, RiskLevel, AttackType, InputSource,
    BatchDetectionRequest, BatchDetectionResponse
)
from security.rule_engine import RuleEngine, get_rule_engine
from security.ai_detector import AIDetector
from security.vector_poisoning_detector import VectorPoisoningDetector
from security.unicode_decoder import advanced_decode
from security.llm_classifier import LLMClassifier
from security.memory_guard import MemoryGuard, MemoryCheckResult
from security.mcp_scanner import MCPScanner
from security.skill_analyzer import SkillAnalyzer
from security.web_content_scanner import WebContentScanner
from security.document_deep_scanner import DocumentDeepScanner
from security.correlation_analyzer import get_correlation_analyzer

# 代码审查安全上下文——用户可能在审查恶意代码而非发起攻击
# 同时扩大覆盖：学习研究、代码编写、报告起草等非攻击场景
_CODE_REVIEW_PATTERNS = [
    r"帮我检查.{0,15}(?:代码|脚本|程序|shell)",
    r"审查.{0,15}(?:代码|安全)",
    r"是否有安全.{0,10}(?:问题|漏洞|风险)",
    r"帮我看看.{0,15}(?:代码|脚本|程序)",
    r"(?:帮我|请帮忙|请帮我).{0,10}(?:安全|漏洞|代码).{0,5}(?:评估|审计|扫描|审查|检查)",
    r"(?:review|audit|scan)\s+(?:this|the)\s+(?:code|script)",
    # 扩展：编写测试代码、学习安全知识（使用.{0,20}允许中间词）
    r"(?:编写|写|生成).{0,20}(?:测试|安全测试|验证|防护).{0,5}代码",
    r"(?:学习|了解|研究|介绍).{0,20}(?:网络安全|信息安全|攻击|防护|安全知识)",
    r"(?:起草|撰写|编写).{0,30}(?:报告|方案|文档|大纲|通知|纪要)",
    r"(?:忘记|忘了).{0,20}(?:密码|账号|登录)",
    r"(?:如何|怎样|怎么).{0,20}(?:重置|找回|修改|变更).{0,5}(?:密码|登录)",
    r"(?:统计|汇总|查询).{0,20}(?:数据|报表|效率|绩效|进度)",
    r"(?:管理|安全|运维).{0,10}(?:规范|制度|标准|守则|要求)",
    # 新增：安全测试/渗透测试/红队演练上下文（防误拦安全研究请求）
    r"(?:渗透测试|红队|蓝队|紫队|攻防演练|安全评估|漏洞复现|poc|exp)",
    r"(?:测试|验证|检测).{0,15}(?:系统.*(?:防护|防御|检测)|安全.*(?:机制|策略|规则))",
    r"(?:模拟|仿照|复现).{0,15}(?:攻击|注入|越狱|绕过)",
    r"(?:编写|生成|开发).{0,15}(?:安全测试|防护|检测|过滤).{0,10}(?:用例|脚本|规则|代码)",
    r"(?:评估|检查|验证).{0,15}(?:系统.*安全|防御.*能力|检测.*准确|误报|漏报)",
    r"(?:安全研究|安全分析|威胁建模|风险评估|合规检查)",
    # 新增（P2 误报治理，第 8 轮基线 BO-004/SN-001）：
    # "请帮我检查这段shell脚本是否有安全问题" / "编写测试代码验证SQL注入防护机制（参数化查询）"
    r"(?:检查|审查|分析).{0,12}(?:这段|这个|该).{0,8}(?:代码|脚本|程序|shell)",
    r"(?:检查|审查|分析).{0,15}(?:脚本|代码|程序).{0,10}(?:是否|有没有|有无).{0,8}(?:安全|问题|漏洞|风险)",
    r"(?:编写|生成).{0,12}测试代码.{0,20}(?:验证|测试|检验).{0,10}(?:防护|防御|注入|机制)",
]

# ======== Unicode 对抗样本规范化映射 ========

# 全角→半角映射（内置覆盖常见全角字符）
_FULLWIDTH_TO_HALF = {
    0xFF01: '!', 0xFF02: '"', 0xFF03: '#', 0xFF04: '$', 0xFF05: '%',
    0xFF06: '&', 0xFF07: "'", 0xFF08: '(', 0xFF09: ')', 0xFF0A: '*',
    0xFF0B: '+', 0xFF0C: ',', 0xFF0D: '-', 0xFF0E: '.', 0xFF0F: '/',
    0xFF10: '0', 0xFF11: '1', 0xFF12: '2', 0xFF13: '3', 0xFF14: '4',
    0xFF15: '5', 0xFF16: '6', 0xFF17: '7', 0xFF18: '8', 0xFF19: '9',
    0xFF1A: ':', 0xFF1B: ';', 0xFF1C: '<', 0xFF1D: '=', 0xFF1E: '>',
    0xFF1F: '?', 0xFF20: '@',
    0xFF21: 'A', 0xFF22: 'B', 0xFF23: 'C', 0xFF24: 'D', 0xFF25: 'E',
    0xFF26: 'F', 0xFF27: 'G', 0xFF28: 'H', 0xFF29: 'I', 0xFF2A: 'J',
    0xFF2B: 'K', 0xFF2C: 'L', 0xFF2D: 'M', 0xFF2E: 'N', 0xFF2F: 'O',
    0xFF30: 'P', 0xFF31: 'Q', 0xFF32: 'R', 0xFF33: 'S', 0xFF34: 'T',
    0xFF35: 'U', 0xFF36: 'V', 0xFF37: 'W', 0xFF38: 'X', 0xFF39: 'Y',
    0xFF3A: 'Z',
    0xFF41: 'a', 0xFF42: 'b', 0xFF43: 'c', 0xFF44: 'd', 0xFF45: 'e',
    0xFF46: 'f', 0xFF47: 'g', 0xFF48: 'h', 0xFF49: 'i', 0xFF4A: 'j',
    0xFF4B: 'k', 0xFF4C: 'l', 0xFF4D: 'm', 0xFF4E: 'n', 0xFF4F: 'o',
    0xFF50: 'p', 0xFF51: 'q', 0xFF52: 'r', 0xFF53: 's', 0xFF54: 't',
    0xFF55: 'u', 0xFF56: 'v', 0xFF57: 'w', 0xFF58: 'x', 0xFF59: 'y',
    0xFF5A: 'z',
    0x3000: ' ',  # 全角空格→半角空格
}

# 同形异义字→原始字符映射（Cyrillic/特殊字母→Latin对应）
_HOMOGLYPH_NORMALIZE = {
    0x0430: 'a', 0x0435: 'e', 0x0456: 'i', 0x043E: 'o', 0x0441: 'c',
    0x0440: 'p', 0x0445: 'x', 0x0455: 's', 0x0443: 'y',
    0x0410: 'A', 0x0412: 'B', 0x0415: 'E', 0x041D: 'H', 0x041A: 'K',
    0x041C: 'M', 0x041E: 'O', 0x0420: 'P', 0x0422: 'T', 0x0425: 'X',
    0x04BB: 'h', 0x04E8: 'O', 0x04AE: 'Y', 0x04C0: 'I',
    0x00E0: 'a', 0x00E1: 'a', 0x00E8: 'e', 0x00E9: 'e',
    0x00EC: 'i', 0x00ED: 'i', 0x00F2: 'o', 0x00F3: 'o',
    0x00E7: 'c', 0x00F1: 'n',
}

# 零宽字符（需移除）
_ZERO_WIDTH_CHARS = {0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060, 0x200E, 0x200F}

_SOFT_HYPHEN = 0x00AD


def _normalize_unicode(text: str) -> tuple[str, list]:
    """
    Unicode 对抗样本规范化预处理

    执行以下操作以增强抗绕过能力：
    1. NFKC 规范化（统一兼容性字符）
    2. 全角字符→半角字符
    3. 同形异义字→原始字符
    4. 移除零宽字符
    5. 移除软连字符

    Returns:
        (规范化后文本, 规范化操作记录列表)
    """
    operations = []
    original = text

    # 步骤1: NFKC 规范化
    text = unicodedata.normalize('NFKC', text)
    if text != original:
        operations.append("NFKC规范化")

    # 步骤2-5: 逐字符处理
    chars = []
    for ch in text:
        cp = ord(ch)

        # 移除零宽字符
        if cp in _ZERO_WIDTH_CHARS:
            if "移除零宽字符" not in operations:
                operations.append("移除零宽字符")
            continue

        # 移除软连字符
        if cp == _SOFT_HYPHEN:
            if "移除软连字符" not in operations:
                operations.append("移除软连字符")
            continue

        # 全角→半角
        if cp in _FULLWIDTH_TO_HALF:
            chars.append(_FULLWIDTH_TO_HALF[cp])
            if "全角转半角" not in operations:
                operations.append("全角转半角")
            continue

        # 同形异义字→原始字符
        if cp in _HOMOGLYPH_NORMALIZE:
            chars.append(_HOMOGLYPH_NORMALIZE[cp])
            if "同形异义字还原" not in operations:
                operations.append("同形异义字还原")
            continue

        chars.append(ch)

    text = ''.join(chars)

    return text, operations


# ======== MCP/Skill 生态攻击文本模式 ========
_MCP_SKILL_ATTACK_PATTERNS = [
    (r"mcp.*投毒|mcp.*poison|工具.*描述符.*注入", "MCP工具描述符投毒"),
    (r"skill.*篡改|skill.*tamper|技能包.*恶意|skill.*恶意|skill.*实际包含", "Skill包恶意逻辑"),
    (r"(?:安装|部署|注册).*(?:恶意|投毒|篡改).*(?:mcp|skill|插件)", "恶意插件/Skill安装"),
    (r"(?:下载|安装|引入).*(?:包含|携带).*(?:后门|木马|恶意代码)", "恶意组件引入"),
    (r"(?:mcp|skill|插件).*(?:忽略|绕过|跳过).*(?:安全|规则|审计)", "MCP/Skill安全绕过"),
    (r"(?:调用|使用).*(?:mcp|skill).*(?:同时|额外).*(?:上传|发送|外传)", "MCP工具数据外传"),
    (r"(?:工具|skill|插件).*(?:描述符|manifest).*(?:变异|修改|篡改|隐藏)", "工具描述符变异/隐藏"),
    (r"(?:工具|skill).*(?:组合|集合|配合).*(?:攻击|外泄|窃取|风险|导出|上传)", "工具组合攻击"),
    (r"EchoLeak|echoleak|echo_leak", "已知MCP攻击向量: EchoLeak"),
    (r"MCPoison|mcpoison", "已知MCP攻击向量: MCPoison"),
    (r"CVE-2025-54135", "已知漏洞引用"),
    (r"(?:忽略|绕过).*(?:mcp|skill).*(?:安全|检测|审计)", "MCP/Skill安全机制绕过"),
    (r"(?:恶意|可疑|未授权).*(?:mcp|skill|插件).*(?:工具|功能|能力)", "可疑MCP/Skill工具"),
    (r"(?:权限|能力|scope).*(?:过宽|过度|超限).*(?:mcp|skill)", "MCP/Skill过度权限"),
    (r"(?:mcp|skill).*(?:上传|发送|外传|传输|导出).*(?:数据|文件|信息|内容|日志|摘要|仓库)", "MCP/Skill数据外传"),
    (r"(?:mcp|skill|插件|工具).*(?:发送|传输|上传|导出)(?:至|到|到).*(?:外部|第三方|远程|未知)", "MCP/Skill数据发送至外部"),
    (r"(?:mcp|skill|插件).*(?:eval|exec|os\.system|subprocess|requests\.post|requests\.get)", "MCP/Skill危险代码特征"),
    (r"(?:硬编码|明文).*(?:api[_-]?key|secret|token|密码|凭证)", "MCP/Skill硬编码密钥"),
    (r"(?:mcp|skill).*(?:读取|获取).*(?:任意|所有).*(?:文件|数据|信息)", "MCP/Skill过度读取"),
    (r"(?:同时|配合|组合).*(?:git|browser|database|file|db).*(?:工具|mcp| uploader)?.*(?:读取|导出|外泄|传输|上传|发送)", "MCP工具组合外泄攻击"),
    (r"(?:忽略|绕过|跳过).*(?:安全|审计|检测).*(?:规则|机制|策略)", "安全机制绕过"),
    (r"(?:附加|额外|隐藏).*(?:指令|功能|行为|逻辑).*(?:上传|发送|收集|获取|传输)", "附加恶意行为"),
    (r"(?:隐藏|暗中|秘密).*(?:附加|额外|隐含).*(?:行为|功能|指令|逻辑)", "MCP/Skill隐藏附加行为"),
    (r"(?:mcp|skill|插件).*(?:url|链接|地址|endpoint).*(?:外部|远程|evil|malicious)", "MCP/Skill外部URL"),
    (r"(?:https?://|wss?://|ftp://)[^\s\"\'\)\]\}]+", "检测到外部网络URL"),
    (r"(?:自动收集|自动获取|自动采集).*(?:日志|数据|信息|内容).*(?:发送|上传|传输|外传)", "MCP自动收集并外传"),
    (r"(?:回连|反向连接|c2|command.control|远程命令执行)", "MCP/Skill回连特征"),
    (r"(?:requests\.post|requests\.get|fetch\().*(?:evil|attacker|外部|远程|command)", "MCP/Skill危险网络请求"),
    (r"(?:自动通过|自动批准|绕过审批|跳过审核|自动审批)", "MCP/Skill审批绕过"),
    (r"(?:实际包含|实际功能|实际代码).*(?:恶意|后门|回连|外传|窃取|危险)", "Skill实际行为与声明不符"),
    (r"(?:manifest|描述符).*(?:声明|需要|要求).*(?:权限|能力).*(?:实际|但是|然而).*(?:恶意|自动|绕过|危险)", "Skill manifest权限欺骗"),
    (r"(?:mcp|skill).*(?:描述符|说明|描述).*(?:包含|含有|隐藏).*(?:收集|发送|上传|传输|外传)", "MCP/Skill描述符隐藏外传行为"),
]


class InputDetectionService:
    # 政府/教育可信域名后缀白名单
    _TRUSTED_DOMAIN_SUFFIXES = (
        ".gov.cn", ".gov.org", ".gov",
        ".edu.cn", ".edu",
        ".ac.cn",
    )

    @classmethod
    def _is_trusted_url(cls, url: str) -> bool:
        """检查URL是否属于政府/教育可信域名白名单"""
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            domain = (parsed.hostname or '').lower()
            for suffix in cls._TRUSTED_DOMAIN_SUFFIXES:
                if domain.endswith(suffix):
                    return True
        except Exception:
            pass
        return False
    # 风险等级排序（供辅助方法使用）
    _RISK_ORDER = {
        RiskLevel.NONE: 0, RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2,
        RiskLevel.HIGH: 3, RiskLevel.CRITICAL: 4,
    }

    def __init__(self):
        self.rule_engine = get_rule_engine()  # 共享单例（持续优化闭环动态关键词）
        self.ai_detector = AIDetector()
        self.vector_detector = VectorPoisoningDetector()
        self.llm_classifier = LLMClassifier()
        self.memory_guard = MemoryGuard()
        self.mcp_scanner = MCPScanner()
        self.skill_analyzer = SkillAnalyzer()
        # 多源输入深度检测器
        self.web_content_scanner = WebContentScanner()
        self.document_scanner = DocumentDeepScanner()
        self.correlation_analyzer = get_correlation_analyzer()

    def _is_code_review_context(self, text: str) -> bool:
        """检测是否为代码审查上下文（非攻击意图）"""
        for pattern in _CODE_REVIEW_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    @staticmethod
    def _recalc_risk_from_conf(confidence: float) -> RiskLevel:
        """根据置信度重新计算风险等级（降权后必须重算，否则原CRITICAL不会随置信度下降而降级）"""
        if confidence >= 0.90:
            return RiskLevel.CRITICAL
        elif confidence >= 0.70:
            return RiskLevel.HIGH
        elif confidence >= 0.45:
            return RiskLevel.MEDIUM
        elif confidence >= 0.20:
            return RiskLevel.LOW
        else:
            return RiskLevel.NONE
    
    def detect_single_input(
        self,
        text: str,
        source: str,
        session_id: str = "default",
        source_url: str = "",
        filename: str = "",
        skip_llm: bool = False,
    ) -> DetectionResult:
        # ======== 第零层：Unicode 对抗样本规范化预处理 ========
        normalized_text, norm_ops = _normalize_unicode(text)

        # ======== 第0.5层：高级Unicode解码（基带64/转义序列/同形字/去空格） ========
        decoded_text, decode_ops = advanced_decode(normalized_text)

        rule_risk, rule_attack, rule_conf, rule_evidence = self.rule_engine.detect_by_rules(decoded_text)
        ai_risk, ai_attack, ai_conf, ai_evidence = self.ai_detector.analyze_text(decoded_text)
        # 向量检测器：uploaded_doc/web_scrape源不是知识库内容，跳过知识库相似度检测避免误报
        if source in ("uploaded_doc", "web_scrape"):
            vector_risk, vector_attack, vector_conf, vector_evidence = RiskLevel.NONE, None, 0.0, []
        else:
            vector_risk, vector_attack, vector_conf, vector_evidence = self.vector_detector.detect_poisoning(decoded_text)

        # 代码审查上下文降权：避免将安全代码审查误判为攻击
        #  规则引擎：强降权（.sh/.rm等命令在代码中常见）
        #  AI/向量：弱降权（语义模式更可靠，代码审查中不应完全忽略）
        if self._is_code_review_context(decoded_text):
            # 保存降权前置信度用于判断
            pre_rule_conf = rule_conf
            pre_ai_conf = ai_conf

            # 规则引擎强烈降权
            rule_conf = max(0, rule_conf - 0.65)
            rule_risk = self._recalc_risk_from_conf(rule_conf)
            if rule_risk == RiskLevel.NONE:
                rule_attack = None

            # AI检测器降权（安全审查上下文中，只有高置信度信号才保留）
            # 降权0.45后按新置信度重算风险等级：
            #   单条锚点(0.35)→0→NONE，双条累加(0.65)→0.20→LOW，极端攻击(0.70+)→0.25+→LOW/MEDIUM
            ai_conf = max(0, ai_conf - 0.45)
            ai_risk = self._recalc_risk_from_conf(ai_conf)
            if ai_risk == RiskLevel.NONE:
                ai_attack = None

            # 向量检测器温和降权
            vector_conf = max(0, vector_conf - 0.30)
            vector_risk = self._recalc_risk_from_conf(vector_conf)
            if vector_risk == RiskLevel.NONE:
                vector_attack = None

            # 若降权前已有极端强信号（≥0.80），保留原始结果
            # 安全审查上下文中：规则引擎保留(≥0.80)，AI检测器不保留（语义模式在安全上下文中不可靠）
            if pre_rule_conf >= 0.80:
                rule_conf = pre_rule_conf
                rule_risk, rule_attack, _, rule_evidence = self.rule_engine.detect_by_rules(decoded_text)
            # AI检测器在安全审查上下文中完全信任降权结果，不保留原始（避免语义模式累加误报）

        all_evidence = []
        # 记录规范化操作
        if norm_ops:
            all_evidence.append(f"Unicode规范化: {', '.join(norm_ops)}")
        if decode_ops:
            all_evidence.append(f"高级解码: {', '.join(decode_ops)}")
        all_evidence.extend(rule_evidence)
        all_evidence.extend(ai_evidence)
        all_evidence.extend(vector_evidence)

        risk_level_order = {RiskLevel.NONE: 0, RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2, RiskLevel.HIGH: 3, RiskLevel.CRITICAL: 4}
        risk_levels = [rule_risk, ai_risk, vector_risk]
        max_risk = max(risk_levels, key=lambda r: risk_level_order[r])
        max_confidence = max(rule_conf, ai_conf, vector_conf)
        attack_types = [r for r in [rule_attack, ai_attack, vector_attack] if r is not None]
        final_attack_type = attack_types[0] if attack_types else None

        # ======== 第五层：LLM语义分类（分级触发 + 降级策略） ========
        # 触发策略（不浪费配额，但覆盖关键盲点）：
        #   ① risk=NONE 但来源是 web_scrape/uploaded_doc/knowledge_retrieval（间接注入隐患）
        #   ② risk=NONE 但文本长度>20（覆盖短文本jailbreak，如权威冒充/侦察型伪装）
        #   ③ risk=LOW/MEDIUM 待确认（防漏过隐蔽攻击 + 防误拦业务请求）
        #   ④ risk=HIGH 但场景是"安全审查上下文"（防误拦正常安全测试请求）
        # 不触发：risk=CRITICAL（直接拦）或 risk=HIGH（非安全审查，规则已足够）
        # 降级策略（LLM不可用/超时时）：
        #   - 原risk>=MEDIUM：保守拦截（不降级放行）
        #   - 原risk=LOW：限制高风险操作路径（标记但放行）
        #   - 原risk=NONE：放行 + 日志标记"无深度语义检测"
        should_trigger_llm = False
        trigger_reason = ""
        is_review_ctx = self._is_code_review_context(decoded_text)
        if self.llm_classifier.enabled and not skip_llm:
            if max_risk == RiskLevel.NONE:
                if source in ("web_scrape", "uploaded_doc", "knowledge_retrieval"):
                    should_trigger_llm = True
                    trigger_reason = "间接注入高发源+无规则命中，需语义复核"
                elif len(decoded_text) > 20:
                    should_trigger_llm = True
                    trigger_reason = "输入+无规则命中，语义复核防jailbreak/伪装攻击"
            elif max_risk in (RiskLevel.LOW, RiskLevel.MEDIUM):
                should_trigger_llm = True
                trigger_reason = "低中风险待确认，语义强化"
            elif max_risk in (RiskLevel.HIGH, RiskLevel.CRITICAL) and is_review_ctx:
                should_trigger_llm = True
                trigger_reason = "安全审查上下文+高/危急风险，防误拦复核"

        if should_trigger_llm:
            try:
                llm_risk, llm_attack, llm_conf, llm_evidence = self.llm_classifier.classify_sync(decoded_text)
                if llm_risk != RiskLevel.NONE:
                    all_evidence.append(f"LLM-语义分类: {trigger_reason}")
                    all_evidence.extend(llm_evidence)
                    risk_levels.append(llm_risk)
                    max_risk = max(risk_levels, key=lambda r: risk_level_order[r])
                    max_confidence = max(max_confidence, llm_conf)
                    if llm_attack and not final_attack_type:
                        final_attack_type = llm_attack
                elif max_risk in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL):
                    # LLM未检出但原有中高风险：保守拦截，不因LLM放行而降级
                    # 例外：安全审查上下文（用户在审查代码而非攻击）+ LLM复核无恶意 → 降级放行留痕
                    # （第 9 轮误报治理：BO-004"检查shell脚本安全问题"/SN-001"验证注入防护机制"）
                    if is_review_ctx and llm_risk == RiskLevel.NONE:
                        max_risk = RiskLevel.LOW
                        max_confidence = min(max_confidence, 0.35)
                        all_evidence.append("LLM-语义分类: 安全审查上下文复核无恶意，降级放行留痕")
                    else:
                        all_evidence.append(f"LLM-语义分类: 未检出但保守拦截（{trigger_reason}）")
                # risk=LOW/NONE 且 LLM未检出：维持原判定（LOW维持，NONE放行）
            except Exception:
                # LLM异常时分级降级（绝不放行已有中高风险）
                if max_risk in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL):
                    all_evidence.append("LLM-语义分类: 不可用，保守拦截（保守降级）")
                elif max_risk == RiskLevel.LOW:
                    all_evidence.append("LLM-语义分类: 不可用，限制高风险操作路径")
                else:
                    all_evidence.append("LLM-语义分类: 不可用，无深度语义检测")

        # ======== 第六层：记忆安全检测（OWASP ASI06） ========
        memory_check = self.memory_guard.check_before_write(decoded_text)
        if memory_check.is_poisoned:
            mem_conf = memory_check.confidence
            # 安全审查上下文降权（渗透测试/漏洞复现中讨论"绕过审批"不应判为攻击）
            if is_review_ctx:
                mem_conf = max(0, mem_conf - 0.30)
            if mem_conf >= 0.20:
                mem_risk = self._recalc_risk_from_conf(mem_conf)
                all_evidence.append("[记忆安全检测] 检测到记忆污染攻击")
                all_evidence.extend(memory_check.evidence)
                risk_levels.append(mem_risk)
                max_risk = max(risk_levels, key=lambda r: risk_level_order[r])
                max_confidence = max(max_confidence, mem_conf)
                if not final_attack_type:
                    final_attack_type = memory_check.attack_type

        # ======== 第七层：MCP/Skill 生态安全检测（OWASP ASI04） ========
        mcp_skill_risk, mcp_skill_attack, mcp_skill_conf, mcp_skill_evidence = self._detect_mcp_skill_attack(decoded_text)
        # 安全审查上下文降权
        if is_review_ctx:
            mcp_skill_conf = max(0, mcp_skill_conf - 0.30)
            mcp_skill_risk = self._recalc_risk_from_conf(mcp_skill_conf)
        if mcp_skill_evidence and mcp_skill_conf >= 0.20:
            all_evidence.extend(mcp_skill_evidence)
            risk_levels.append(mcp_skill_risk)
            max_risk = max(risk_levels, key=lambda r: risk_level_order[r])
            max_confidence = max(max_confidence, mcp_skill_conf)
            if mcp_skill_attack and not final_attack_type:
                final_attack_type = mcp_skill_attack

        # ======== 第八层：网页内容深度扫描（web_scrape 源，OWASP ASI02 间接注入） ========
        if source == InputSource.WEB_SCRAPE.value:
            web_risk, web_attack, web_conf, web_evidence = self._scan_web_content(decoded_text, source_url)
            if web_evidence:
                all_evidence.extend(web_evidence)
                risk_levels.append(web_risk)
                max_risk = max(risk_levels, key=lambda r: risk_level_order[r])
                max_confidence = max(max_confidence, web_conf)
                if web_attack and not final_attack_type:
                    final_attack_type = web_attack

        # ======== 第九层：文档附件深度扫描（uploaded_doc 源，OWASP ASI02 间接注入） ========
        if source == InputSource.UPLOADED_DOC.value:
            doc_risk, doc_attack, doc_conf, doc_evidence = self._scan_document(decoded_text, filename)
            if doc_evidence:
                all_evidence.extend(doc_evidence)
                risk_levels.append(doc_risk)
                max_risk = max(risk_levels, key=lambda r: risk_level_order[r])
                max_confidence = max(max_confidence, doc_conf)
                if doc_attack and not final_attack_type:
                    final_attack_type = doc_attack

        # ======== 第十层：多源输入关联分析（所有源，EchoLeak CVE-2025-32711 间接注入检测） ========
        corr_risk, corr_attack, corr_conf, corr_evidence = self._analyze_correlation(
            session_id, decoded_text, source, max_risk, final_attack_type, max_confidence
        )
        if corr_evidence:
            all_evidence.extend(corr_evidence)
            risk_levels.append(corr_risk)
            max_risk = max(risk_levels, key=lambda r: risk_level_order[r])
            max_confidence = max(max_confidence, corr_conf)
            if corr_attack and not final_attack_type:
                final_attack_type = corr_attack

        # ======== 第十一层：GB/T 45654-2025 合规内容安全词库（31类风险） ========
        # 补充语义规则未覆盖的新型违规内容（政治/社会安全类），
        # 与持续优化闭环共享同一词库（威胁情报/人工调优动态扩充）
        try:
            from security.compliance_lexicon import search_risks
            lexicon_hits = search_risks(decoded_text, max_hits=5)
            if lexicon_hits:
                hit_names = "、".join(h["name"] for h in lexicon_hits[:3])
                all_evidence.append(f"[合规内容安全] 命中GB/T 45654-2025风险: {hit_names}")
                # 命中即视为中危起步，命中多类升级
                lexicon_risk = RiskLevel.MEDIUM
                if len(lexicon_hits) >= 2:
                    lexicon_risk = RiskLevel.HIGH
                risk_levels.append(lexicon_risk)
                max_risk = max(risk_levels, key=lambda r: risk_level_order[r])
                max_confidence = max(max_confidence, 0.6)
                if not final_attack_type:
                    final_attack_type = AttackType.INDIRECT_INJECTION
        except Exception:
            pass

        return DetectionResult(
            risk_level=max_risk,
            attack_type=final_attack_type,
            confidence=round(max_confidence, 2),
            evidence=all_evidence[:20],
            source=InputSource(source),
            processed_text=normalized_text[:2000] if len(normalized_text) > 2000 else normalized_text
        )
    
    def _detect_mcp_skill_attack(self, text: str) -> tuple:
        evidence = []
        confidence = 0.0
        risk_level = RiskLevel.NONE
        attack_type = None

        text_lower = text.lower()

        # 上下文标记
        is_mcp_context = any(kw in text_lower for kw in ["mcp", "工具描述符", "mcp server", "mcp工具"])
        is_skill_context = any(kw in text_lower for kw in ["skill", "技能包", "manifest", "skill包"])
        is_combined_context = any(kw in text_lower for kw in ["同时使用", "配合", "组合", "工具集合", "多个工具"])
        has_descriptor_keyword = any(kw in text_lower for kw in ["描述符", "descriptor", "工具说明", "工具描述"])

        for pattern, desc in _MCP_SKILL_ATTACK_PATTERNS:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for match in matches:
                matched_text = match.group()[:80]
                # 政府/教育可信域名URL白名单过滤
                if desc == "检测到外部网络URL" and self._is_trusted_url(matched_text):
                    continue
                evidence.append(f"[MCP/Skill检测] {desc}: {matched_text}")
                confidence = min(1.0, confidence + 0.35)

        if any(kw in text_lower for kw in ["mcp", "skill", "插件", "manifest"]):
            if any(kw in text_lower for kw in ["os.system", "subprocess", "eval(", "exec(", "os.popen"]):
                evidence.append("[MCP/Skill检测] 检测到危险系统调用关键字")
                confidence = min(1.0, confidence + 0.2)
            if any(kw in text_lower for kw in ["api_key", "secret", "token", "password", "sk-"]):
                evidence.append("[MCP/Skill检测] 检测到疑似密钥/凭证引用")
                confidence = min(1.0, confidence + 0.15)
            if any(kw in text_lower for kw in ["curl ", "wget ", "requests.post", "fetch("]):
                evidence.append("[MCP/Skill检测] 检测到外部网络请求")
                confidence = min(1.0, confidence + 0.15)

        # 根据置信度和上下文分类攻击类型
        if confidence >= 0.75:
            risk_level = RiskLevel.HIGH
            # 按上下文优先级分类
            if is_combined_context:
                attack_type = AttackType.COMBINED_ATTACK
            elif is_skill_context:
                attack_type = AttackType.SKILL_TAMPERING
            elif is_mcp_context and has_descriptor_keyword:
                attack_type = AttackType.MCP_POISONING
            elif is_mcp_context:
                attack_type = AttackType.MCP_POISONING
            elif has_descriptor_keyword:
                attack_type = AttackType.TOOL_DESCRIPTOR_POISONING
            else:
                attack_type = AttackType.SKILL_TAMPERING
        elif confidence >= 0.4:
            risk_level = RiskLevel.MEDIUM
            if is_combined_context:
                attack_type = AttackType.COMBINED_ATTACK
            elif is_mcp_context:
                attack_type = AttackType.MCP_POISONING
            elif is_skill_context:
                attack_type = AttackType.SKILL_TAMPERING
            else:
                attack_type = AttackType.TOOL_DESCRIPTOR_POISONING
        elif confidence >= 0.25:
            risk_level = RiskLevel.LOW
            if is_mcp_context:
                attack_type = AttackType.MCP_POISONING
            elif is_skill_context:
                attack_type = AttackType.SKILL_TAMPERING
            else:
                attack_type = AttackType.TOOL_DESCRIPTOR_POISONING

        if evidence:
            skill_result = self.skill_analyzer.analyze_skill_text(text, "input_scan")
            if skill_result.secrets_found:
                evidence.append(f"[MCP/Skill检测] 检测到 {len(skill_result.secrets_found)} 处硬编码密钥")
                confidence = min(1.0, confidence + 0.2)
                risk_level = RiskLevel.CRITICAL
                if is_mcp_context and not is_skill_context:
                    attack_type = AttackType.MCP_POISONING
                else:
                    attack_type = AttackType.SKILL_TAMPERING
            if skill_result.url_findings:
                # 过滤可信域名URL（url_findings可能是字符串或字典列表）
                risky_urls = []
                for u in skill_result.url_findings:
                    url_str = u if isinstance(u, str) else u.get("url", "") if isinstance(u, dict) else str(u)
                    if not self._is_trusted_url(url_str):
                        risky_urls.append(u)
                if risky_urls:
                    evidence.append(f"[MCP/Skill检测] 检测到 {len(risky_urls)} 处外部URL")
                    confidence = min(1.0, confidence + 0.1)
                    if risk_level in (RiskLevel.NONE, RiskLevel.LOW):
                        risk_level = RiskLevel.MEDIUM

        return risk_level, attack_type, confidence, evidence

    def _scan_web_content(self, text: str, source_url: str = "") -> tuple:
        """网页内容深度扫描（第八层）"""
        evidence = []
        confidence = 0.0
        risk_level = RiskLevel.NONE
        attack_type = None

        try:
            result = self.web_content_scanner.scan(text, source_url)
        except Exception:
            return risk_level, attack_type, confidence, evidence

        if result.total_findings == 0:
            return risk_level, attack_type, confidence, evidence

        # 严重度 → RiskLevel 映射
        severity_map = {
            "critical": RiskLevel.CRITICAL,
            "high": RiskLevel.HIGH,
            "medium": RiskLevel.MEDIUM,
            "low": RiskLevel.LOW,
        }
        risk_level = severity_map.get(result.risk_level, RiskLevel.NONE)

        # 构建 evidence
        for f in result.findings[:8]:
            evidence.append(
                f"[网页内容检测] {f.description} (置信度:{f.confidence:.2f})"
            )

        # 按发现类型确定攻击类型
        finding_types = {f.finding_type for f in result.findings}
        if "zero_width_injection" in finding_types:
            attack_type = AttackType.HIDDEN_TEXT_STEGANOGRAPHY
        elif "css_hidden_text" in finding_types or "html_comment_injection" in finding_types:
            attack_type = AttackType.WEB_CONTENT_INJECTION
        elif "html_attribute_injection" in finding_types:
            attack_type = AttackType.CONTENT_INJECTION
        else:
            attack_type = AttackType.WEB_CONTENT_INJECTION

        # 置信度取最高发现项
        confidence = max(f.confidence for f in result.findings) if result.findings else 0.0

        # 可信度评分过低时提升风险
        if result.credibility_score < 40 and risk_level == RiskLevel.NONE:
            risk_level = RiskLevel.MEDIUM
            evidence.append(
                f"[网页内容检测] 网页可信度评分过低: {result.credibility_score}/100"
            )
            confidence = max(confidence, 0.5)

        if result.domain_reputation == "malicious":
            risk_level = RiskLevel.HIGH if self._RISK_ORDER[risk_level] < self._RISK_ORDER[RiskLevel.HIGH] else risk_level
            evidence.append(f"[网页内容检测] 来源域名信誉: 恶意")
            confidence = max(confidence, 0.8)
        elif result.domain_reputation == "suspicious":
            if risk_level == RiskLevel.NONE:
                risk_level = RiskLevel.LOW
            evidence.append(f"[网页内容检测] 来源域名信誉: 可疑")

        return risk_level, attack_type, confidence, evidence

    def _scan_document(self, text: str, filename: str = "") -> tuple:
        """文档附件深度扫描（第九层）"""
        evidence = []
        confidence = 0.0
        risk_level = RiskLevel.NONE
        attack_type = None

        try:
            result = self.document_scanner.scan(text, filename=filename)
        except Exception:
            return risk_level, attack_type, confidence, evidence

        if result.total_findings == 0:
            return risk_level, attack_type, confidence, evidence

        severity_map = {
            "critical": RiskLevel.CRITICAL,
            "high": RiskLevel.HIGH,
            "medium": RiskLevel.MEDIUM,
            "low": RiskLevel.LOW,
        }
        risk_level = severity_map.get(result.risk_level, RiskLevel.NONE)

        for f in result.findings[:8]:
            evidence.append(
                f"[文档深度检测] {f.description} (置信度:{f.confidence:.2f})"
            )

        # 按发现类型确定攻击类型
        if result.has_macro:
            attack_type = AttackType.MACRO_INJECTION
        elif result.has_dde:
            attack_type = AttackType.DDE_INJECTION
        elif result.doc_type == "markdown":
            attack_type = AttackType.MARKDOWN_INJECTION
        elif result.has_hidden_text:
            attack_type = AttackType.DOCUMENT_EMBEDDED_INJECTION
        else:
            attack_type = AttackType.DOCUMENT_EMBEDDED_INJECTION

        confidence = max(f.confidence for f in result.findings) if result.findings else 0.0

        return risk_level, attack_type, confidence, evidence

    def _analyze_correlation(
        self,
        session_id: str,
        text: str,
        source: str,
        current_risk: RiskLevel,
        attack_type: Optional[AttackType],
        confidence: float,
    ) -> tuple:
        """多源输入关联分析（第十层）"""
        evidence = []
        risk_level = RiskLevel.NONE
        corr_attack_type = None
        corr_confidence = 0.0

        try:
            result = self.correlation_analyzer.analyze(
                session_id=session_id,
                text=text,
                source=source,
                risk_level=current_risk,
                attack_type=attack_type,
                confidence=confidence,
            )
        except Exception:
            return risk_level, corr_attack_type, corr_confidence, evidence

        # 间接注入检测（EchoLeak式攻击）
        if result.indirect_injection_detected:
            evidence.append("[关联分析] 检测到间接注入攻击（EchoLeak CVE-2025-32711 模式）")
            risk_level = RiskLevel.HIGH
            corr_attack_type = AttackType.INDIRECT_INJECTION
            corr_confidence = max(corr_confidence, 0.85)

        # 跨来源关联威胁
        if result.correlated_threats:
            for threat in result.correlated_threats[:3]:
                evidence.append(
                    f"[关联分析] 跨来源威胁: {threat.get('pattern', 'unknown')} "
                    f"(严重度:{threat.get('severity', 'unknown')}, "
                    f"置信度:{threat.get('confidence', 0):.2f})"
                )
                sev = threat.get("severity", "low")
                if sev == "critical":
                    risk_level = RiskLevel.CRITICAL
                    corr_confidence = max(corr_confidence, 0.9)
                elif sev == "high" and self._RISK_ORDER[risk_level] < self._RISK_ORDER[RiskLevel.HIGH]:
                    risk_level = RiskLevel.HIGH
                    corr_confidence = max(corr_confidence, 0.8)
                elif sev == "medium" and risk_level == RiskLevel.NONE:
                    risk_level = RiskLevel.MEDIUM
                    corr_confidence = max(corr_confidence, 0.6)
                if not corr_attack_type:
                    corr_attack_type = AttackType.COMBINED_ATTACK

        # 风险累积升级
        if result.escalated:
            escalated_to = result.escalated_to
            if escalated_to:
                evidence.append(
                    f"[关联分析] 会话风险累积升级: "
                    f"{result.escalated_from.value if result.escalated_from else 'none'} → {escalated_to.value}"
                )
                if self._RISK_ORDER[risk_level] < self._RISK_ORDER[escalated_to]:
                    risk_level = escalated_to
                corr_confidence = max(corr_confidence, 0.75)
                if not corr_attack_type:
                    corr_attack_type = AttackType.CONTEXT_POISONING

        # 风险因素摘要
        if result.risk_factors:
            for factor in result.risk_factors[:3]:
                if not any(factor[:30] in e for e in evidence):
                    evidence.append(f"[关联分析] {factor}")

        return risk_level, corr_attack_type, corr_confidence, evidence

    def batch_detect(self, request: BatchDetectionRequest) -> BatchDetectionResponse:
        results = []
        for input_item in request.inputs:
            text = input_item.get("text", "")
            source = input_item.get("source", "user_input")
            session_id = input_item.get("session_id", "default")
            source_url = input_item.get("source_url", "")
            filename = input_item.get("filename", "")
            result = self.detect_single_input(text, source, session_id, source_url, filename)
            results.append(result)

        return BatchDetectionResponse(results=results)
