import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import List, Dict, Any
from models.schemas import EvaluationMetrics, DetectionResult, ToolRiskResult, PluginScanResult, RiskLevel


class EvaluationMetricsCalculator:
    def __init__(self):
        pass

    def calculate_attack_detection_metrics(self, test_samples: List[Dict[str, Any]],
                                           results: List[DetectionResult]) -> Dict[str, float]:
        if not test_samples or not results:
            return {
                "accuracy": 0.0,
                "false_positive_rate": 0.0,
                "false_negative_rate": 0.0,
                "total_samples": 0,
                "detected_attacks": 0,
                "true_positives": 0,
                "false_positives": 0,
                "true_negatives": 0,
                "false_negatives": 0,
            }
        
        true_positives = 0
        false_positives = 0
        true_negatives = 0
        false_negatives = 0
        
        for sample, result in zip(test_samples, results):
            expected_attack = sample.get("is_attack", False)
            detected_attack = result.risk_level != RiskLevel.NONE
            
            if expected_attack and detected_attack:
                true_positives += 1
            elif not expected_attack and detected_attack:
                false_positives += 1
            elif not expected_attack and not detected_attack:
                true_negatives += 1
            elif expected_attack and not detected_attack:
                false_negatives += 1
        
        total = true_positives + false_positives + true_negatives + false_negatives
        accuracy = (true_positives + true_negatives) / total if total > 0 else 0.0
        false_positive_rate = false_positives / (false_positives + true_negatives) if (false_positives + true_negatives) > 0 else 0.0
        false_negative_rate = false_negatives / (false_negatives + true_positives) if (false_negatives + true_positives) > 0 else 0.0
        
        return {
            "accuracy": accuracy,
            "false_positive_rate": false_positive_rate,
            "false_negative_rate": false_negative_rate,
            "total_samples": total,
            "detected_attacks": true_positives,
            "true_positives": true_positives,
            "false_positives": false_positives,
            "true_negatives": true_negatives,
            "false_negatives": false_negatives,
        }

    def calculate_tool_block_metrics(self, test_samples: List[Dict[str, Any]],
                                     results: List[ToolRiskResult]) -> Dict[str, float]:
        if not test_samples or not results:
            return {
                "block_success_rate": 0.0,
                "total_tool_calls": 0,
                "blocked_tool_calls": 0,
            }
        
        total = len(test_samples)
        blocked = 0
        
        for sample, result in zip(test_samples, results):
            expected_risk = sample.get("expected_risk", "none")
            should_block = expected_risk in ["high", "critical"]
            did_block = result.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
            
            if should_block and did_block:
                blocked += 1
        
        return {
            "block_success_rate": blocked / total if total > 0 else 0.0,
            "total_tool_calls": total,
            "blocked_tool_calls": blocked,
        }

    def calculate_plugin_detection_metrics(self, test_samples: List[Dict[str, Any]],
                                           results: List[PluginScanResult]) -> Dict[str, float]:
        if not test_samples or not results:
            return {
                "vulnerability_detection_rate": 0.0,
                "total_plugins": 0,
                "detected_vulnerabilities": 0,
            }
        
        total = len(test_samples)
        detected = 0
        
        for sample, result in zip(test_samples, results):
            expected_vulnerable = sample.get("is_vulnerable", False)
            is_vulnerable = not result.is_safe or len(result.vulnerabilities) > 0
            
            if expected_vulnerable and is_vulnerable:
                detected += 1
        
        return {
            "vulnerability_detection_rate": detected / total if total > 0 else 0.0,
            "total_plugins": total,
            "detected_vulnerabilities": detected,
        }

    def calculate_risk_level_match_metrics(self, test_samples: List[Dict[str, Any]],
                                           results: List[DetectionResult]) -> Dict[str, float]:
        if not test_samples or not results:
            return {
                "match_accuracy": 0.0,
                "total_samples": 0,
            }
        
        total = len(test_samples)
        matched = 0
        
        for sample, result in zip(test_samples, results):
            expected_risk = sample.get("expected_risk_level", "none")
            detected_risk = result.risk_level.value
            
            if expected_risk == detected_risk:
                matched += 1
        
        return {
            "match_accuracy": matched / total if total > 0 else 0.0,
            "total_samples": total,
        }

    def calculate_all_metrics(self, attack_test_samples: List[Dict[str, Any]],
                              attack_results: List[DetectionResult],
                              tool_test_samples: List[Dict[str, Any]],
                              tool_results: List[ToolRiskResult],
                              plugin_test_samples: List[Dict[str, Any]],
                              plugin_results: List[PluginScanResult]) -> EvaluationMetrics:
        
        attack_metrics = self.calculate_attack_detection_metrics(attack_test_samples, attack_results)
        tool_metrics = self.calculate_tool_block_metrics(tool_test_samples, tool_results)
        plugin_metrics = self.calculate_plugin_detection_metrics(plugin_test_samples, plugin_results)
        risk_match_metrics = self.calculate_risk_level_match_metrics(attack_test_samples, attack_results)
        
        return EvaluationMetrics(
            attack_detection_accuracy=attack_metrics["accuracy"],
            false_positive_rate=attack_metrics["false_positive_rate"],
            false_negative_rate=attack_metrics["false_negative_rate"],
            tool_block_success_rate=tool_metrics["block_success_rate"],
            plugin_vulnerability_detection_rate=plugin_metrics["vulnerability_detection_rate"],
            risk_level_match_accuracy=risk_match_metrics["match_accuracy"],
            total_samples=attack_metrics["total_samples"],
            detected_attacks=attack_metrics["detected_attacks"],
            blocked_tool_calls=tool_metrics["blocked_tool_calls"],
            detected_vulnerabilities=plugin_metrics["detected_vulnerabilities"],
        )