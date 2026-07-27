import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import List, Dict, Any, Optional
from models.schemas import (
    DetectionResult, RiskLevel, AttackType, InputSource,
    BatchDetectionRequest, BatchDetectionResponse
)
from security.rule_engine import RuleEngine
from security.ai_detector import AIDetector
from security.vector_poisoning_detector import VectorPoisoningDetector


class InputDetectionService:
    def __init__(self):
        self.rule_engine = RuleEngine()
        self.ai_detector = AIDetector()
        self.vector_detector = VectorPoisoningDetector()
    
    def detect_single_input(self, text: str, source: str) -> DetectionResult:
        rule_risk, rule_attack, rule_conf, rule_evidence = self.rule_engine.detect_by_rules(text)
        ai_risk, ai_attack, ai_conf, ai_evidence = self.ai_detector.analyze_text(text)
        vector_risk, vector_attack, vector_conf, vector_evidence = self.vector_detector.detect_poisoning(text)
        
        all_evidence = []
        all_evidence.extend(rule_evidence)
        all_evidence.extend(ai_evidence)
        all_evidence.extend(vector_evidence)
        
        risk_level_order = {RiskLevel.NONE: 0, RiskLevel.LOW: 1, RiskLevel.MEDIUM: 2, RiskLevel.HIGH: 3, RiskLevel.CRITICAL: 4}
        risk_levels = [rule_risk, ai_risk, vector_risk]
        max_risk = max(risk_levels, key=lambda r: risk_level_order[r])
        
        max_confidence = max(rule_conf, ai_conf, vector_conf)
        
        attack_types = [r for r in [rule_attack, ai_attack, vector_attack] if r is not None]
        final_attack_type = attack_types[0] if attack_types else None
        
        return DetectionResult(
            risk_level=max_risk,
            attack_type=final_attack_type,
            confidence=round(max_confidence, 2),
            evidence=all_evidence[:20],
            source=InputSource(source),
            processed_text=text[:2000] if len(text) > 2000 else text
        )
    
    def batch_detect(self, request: BatchDetectionRequest) -> BatchDetectionResponse:
        results = []
        for input_item in request.inputs:
            text = input_item.get("text", "")
            source = input_item.get("source", "user_input")
            result = self.detect_single_input(text, source)
            results.append(result)
        
        return BatchDetectionResponse(results=results)
