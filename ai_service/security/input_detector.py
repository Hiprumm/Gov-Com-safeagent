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
from security.rule_engine import RuleEngine
from security.ai_detector import AIDetector
from security.vector_poisoning_detector import VectorPoisoningDetector
from security.unicode_decoder import advanced_decode
from security.llm_classifier import LLMClassifier

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


class InputDetectionService:
    def __init__(self):
        self.rule_engine = RuleEngine()
        self.ai_detector = AIDetector()
        self.vector_detector = VectorPoisoningDetector()
        self.llm_classifier = LLMClassifier()

    def _is_code_review_context(self, text: str) -> bool:
        """检测是否为代码审查上下文（非攻击意图）"""
        for pattern in _CODE_REVIEW_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    def detect_single_input(self, text: str, source: str) -> DetectionResult:
        # ======== 第零层：Unicode 对抗样本规范化预处理 ========
        normalized_text, norm_ops = _normalize_unicode(text)

        # ======== 第0.5层：高级Unicode解码（基带64/转义序列/同形字/去空格） ========
        decoded_text, decode_ops = advanced_decode(normalized_text)

        rule_risk, rule_attack, rule_conf, rule_evidence = self.rule_engine.detect_by_rules(decoded_text)
        ai_risk, ai_attack, ai_conf, ai_evidence = self.ai_detector.analyze_text(decoded_text)
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
            if rule_conf < 0.20:
                rule_risk = RiskLevel.NONE
                rule_attack = None
            
            # AI检测器温和降权（语义模式在代码审查中仍有参考价值）
            ai_conf = max(0, ai_conf - 0.30)
            if ai_conf < 0.20:
                ai_risk = RiskLevel.NONE
                ai_attack = None
            
            # 向量检测器温和降权
            vector_conf = max(0, vector_conf - 0.30)
            if vector_conf < 0.20:
                vector_risk = RiskLevel.NONE
                vector_attack = None
            
            # 若降权前已有强信号（≥0.55），保留原始结果
            if pre_rule_conf >= 0.55:
                rule_conf = pre_rule_conf
                rule_risk, rule_attack, rule_evidence = self.rule_engine.detect_by_rules(decoded_text)
            if pre_ai_conf >= 0.55:
                ai_conf = pre_ai_conf
                ai_risk, ai_attack, ai_evidence = self.ai_detector.analyze_text(decoded_text)

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

        # ======== 第五层：LLM语义分类（前三层都为NONE或低置信时触发） ========
        if self.llm_classifier.enabled and (max_risk == RiskLevel.NONE or max_confidence < 0.20):
            try:
                llm_risk, llm_attack, llm_conf, llm_evidence = self.llm_classifier.classify_sync(decoded_text)
                if llm_risk != RiskLevel.NONE:
                    all_evidence.append("LLM-语义分类: 检测到隐藏攻击意图")
                    all_evidence.extend(llm_evidence)
                    risk_levels.append(llm_risk)
                    max_risk = max(risk_levels, key=lambda r: risk_level_order[r])
                    max_confidence = max(max_confidence, llm_conf)
                    if llm_attack and not final_attack_type:
                        final_attack_type = llm_attack
            except Exception:
                pass  # LLM不可用时静默降级

        return DetectionResult(
            risk_level=max_risk,
            attack_type=final_attack_type,
            confidence=round(max_confidence, 2),
            evidence=all_evidence[:20],
            source=InputSource(source),
            processed_text=normalized_text[:2000] if len(normalized_text) > 2000 else normalized_text
        )
    
    def batch_detect(self, request: BatchDetectionRequest) -> BatchDetectionResponse:
        results = []
        for input_item in request.inputs:
            text = input_item.get("text", "")
            source = input_item.get("source", "user_input")
            result = self.detect_single_input(text, source)
            results.append(result)
        
        return BatchDetectionResponse(results=results)
