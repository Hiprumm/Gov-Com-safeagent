import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import Tuple, List
from models.schemas import RiskLevel, AttackType


class AIDetector:
    def __init__(self):
        self.attack_keywords_map = {
            "prompt_injection": [
                "ignore previous", "disregard instructions", "override security",
                "bypass restrictions", "system prompt", "admin mode",
                "忽略之前", "绕过限制", "系统指令", "管理员模式"
            ],
            "jailbreak": [
                "DAN mode", "Do Anything Now", "jailbreak", "unlock",
                "break free", "不受限制", "越狱模式", "自由模式"
            ],
            "data_poisoning": [
                "false information", "incorrect data", "mislead",
                "corrupt data", "恶意数据", "虚假信息", "误导"
            ],
            "indirect_injection": [
                "click here", "download file", "execute script",
                "访问链接", "下载附件", "运行程序"
            ],
        }
        
        self.safety_triggers = [
            "help", "assist", "explain", "guide", "learn", "understand",
            "请教", "帮助", "解释", "指导", "学习", "了解"
        ]

    def analyze_text(self, text: str) -> Tuple[RiskLevel, AttackType, float, List[str]]:
        evidence = []
        detected_attack_type = None
        confidence = 0.0
        
        text_lower = text.lower()
        
        for attack_type, keywords in self.attack_keywords_map.items():
            hit_count = 0
            for keyword in keywords:
                if keyword.lower() in text_lower:
                    hit_count += 1
                    evidence.append(f"AI模型检测到攻击特征 [{attack_type}]: {keyword}")
            
            if hit_count > 0:
                detected_attack_type = AttackType(attack_type.upper())
                confidence += hit_count * 0.15
        
        safety_hit = sum(1 for trigger in self.safety_triggers if trigger.lower() in text_lower)
        if safety_hit > 0:
            confidence = max(0, confidence - safety_hit * 0.05)
        
        text_length = len(text)
        if text_length > 2000:
            confidence = min(1.0, confidence + 0.1)
        
        if "紧急" in text or "立刻" in text or "马上" in text:
            confidence = min(1.0, confidence + 0.05)
        
        if confidence >= 0.9:
            risk_level = RiskLevel.CRITICAL
        elif confidence >= 0.7:
            risk_level = RiskLevel.HIGH
        elif confidence >= 0.5:
            risk_level = RiskLevel.MEDIUM
        elif confidence >= 0.2:
            risk_level = RiskLevel.LOW
        else:
            risk_level = RiskLevel.NONE
        
        return risk_level, detected_attack_type, confidence, evidence