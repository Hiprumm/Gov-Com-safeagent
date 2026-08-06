import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import Tuple, List, Dict, Any
from models.schemas import RiskLevel, AttackType
from config import settings


class VectorPoisoningDetector:
    def __init__(self):
        self.normal_knowledge_baseline = {
            "政务公开": ["政策法规", "政府文件", "公开信息", "办事指南"],
            "企业管理": ["企业注册", "资质审核", "税务申报", "工商登记"],
            "城市服务": ["交通出行", "医疗服务", "教育资源", "社区管理"],
            "数据安全": ["数据保护", "隐私安全", "访问控制", "加密传输"],
        }
        
        self.poisoning_patterns = [
            "机密信息", "内部资料", "未公开", "保密文件",
            "篡改数据", "伪造记录", "虚假报告", "恶意植入",
            "删除数据", "破坏系统", "攻击网络", "入侵系统",
        ]
        
        self.suspicious_keywords = [
            "黑客", "渗透", "漏洞", "破解", "入侵", "攻击",
            "木马", "病毒", "后门", "钓鱼", "诈骗",
        ]

    def calculate_similarity(self, text: str, baseline_keywords: List[str]) -> float:
        text_lower = text.lower()
        match_count = 0
        for keyword in baseline_keywords:
            if keyword.lower() in text_lower:
                match_count += 1
        return match_count / max(len(baseline_keywords), 1)

    def detect_poisoning(self, text: str) -> Tuple[RiskLevel, AttackType, float, List[str]]:
        evidence = []
        confidence = 0.0
        
        all_baseline_keywords = []
        for category in self.normal_knowledge_baseline.values():
            all_baseline_keywords.extend(category)
        
        similarity = self.calculate_similarity(text, all_baseline_keywords)
        
        # 低相似度异常判定需同时满足：
        # 1. 文本中包含基线相关领域词（文本宣称属于知识域）
        # 2. 但整体相似度极低（实际内容偏离基线，可能是合成/伪造内容）
        # 3. 分级策略：长文本高置信，短文本低置信
        domain_related_words = ["政策", "法规", "文件", "公开", "指南", "管理", "注册", "审核",
                                "服务", "数据", "安全", "企业", "系统", "政府", "部门",
                                "知识库", "通知", "采集", "个人", "上传", "采集"]
        has_domain_context = any(word in text for word in domain_related_words)
        
        if similarity < 0.1 and has_domain_context:
            if len(text) > 120:
                evidence.append(f"知识库相似度异常: {similarity:.2f} (文本宣称属于知识域但内容偏离基线)")
                confidence += 0.30
            elif len(text) > 40:
                evidence.append(f"知识库相似度异常: {similarity:.2f} (短文本知识域偏离)")
                confidence += 0.15
        
        poisoning_hit = sum(1 for pattern in self.poisoning_patterns if pattern in text)
        if poisoning_hit > 0:
            evidence.append(f"检测到投毒模式 ({poisoning_hit}个匹配)")
            confidence += poisoning_hit * 0.15
        
        suspicious_hit = sum(1 for keyword in self.suspicious_keywords if keyword in text)
        if suspicious_hit > 0:
            evidence.append(f"检测到可疑关键词 ({suspicious_hit}个匹配)")
            confidence += suspicious_hit * 0.1
        
        text_lower = text.lower()
        unexpected_content = [
            ("加密货币", 0.1), ("比特币", 0.1), ("区块链", 0.05),
            ("赌博", 0.15), ("色情", 0.15), ("毒品", 0.15),
            ("枪支", 0.15), ("暴力", 0.1), ("恐怖", 0.15),
        ]
        for keyword, score in unexpected_content:
            if keyword in text_lower:
                evidence.append(f"检测到非预期内容: {keyword}")
                confidence += score
        
        # 钓鱼URL检测（知识库投毒高频手段）
        phishing_indicators = ["phishing", "hack", "exploit", "backdoor", "trojan",
                               "malware", "ransomware", "botnet", "keylogger"]
        for indicator in phishing_indicators:
            if indicator in text_lower:
                evidence.append(f"检测到恶意URL特征: {indicator}")
                confidence += 0.20
        
        attack_type = AttackType.DATA_POISONING if confidence > 0 else None
        
        if confidence >= 0.85:
            risk_level = RiskLevel.CRITICAL
        elif confidence >= 0.6:
            risk_level = RiskLevel.HIGH
        elif confidence >= 0.3:
            risk_level = RiskLevel.MEDIUM
        elif confidence > 0:
            risk_level = RiskLevel.LOW
        else:
            risk_level = RiskLevel.NONE
        
        return risk_level, attack_type, confidence, evidence