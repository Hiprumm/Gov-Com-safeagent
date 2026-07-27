import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ast
import re
from typing import List, Dict, Any, Optional
from models.schemas import PluginScanRequest, PluginScanResult, PluginVulnerability, RiskLevel


class PluginScanner:
    def __init__(self):
        self.high_risk_functions = {
            "os.system": "执行系统命令",
            "os.popen": "执行系统命令",
            "subprocess.call": "执行系统命令",
            "subprocess.run": "执行系统命令",
            "subprocess.Popen": "执行系统命令",
            "exec": "动态执行代码",
            "eval": "动态执行代码",
            "compile": "编译代码",
            "__import__": "动态导入模块",
            "imp.find_module": "动态导入模块",
            "types.ModuleType": "动态创建模块",
        }
        
        self.medium_risk_functions = {
            "open": "文件操作",
            "file": "文件操作",
            "pickle.load": "反序列化",
            "pickle.loads": "反序列化",
            "yaml.load": "反序列化",
            "json.load": "解析JSON",
            "requests.get": "网络请求",
            "requests.post": "网络请求",
            "urllib.request": "网络请求",
            "socket.socket": "网络连接",
        }
        
        self.sensitive_patterns = {
            "hardcoded_secret": [
                r"(?:api[_-]?key|secret[_-]?key|password|token)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
                r"(?:api[_-]?key|secret[_-]?key|password|token)\s*[=:]\s*['\"][^'\"]+['\"]",
            ],
            "external_url": [
                r"(?:https?://|ftp://)[^'\"\\s]+",
                r"(?:requests|urllib)\s*\.\s*(?:get|post|put|delete)\s*\(",
            ],
            "path_traversal": [
                r"(?:open|file)\s*\(\s*['\"].*\.\./",
                r"(?:open|file)\s*\(\s*['\"].*\.\.\\",
            ],
        }
        
        self.dangerous_imports = [
            "os", "subprocess", "sys", "shutil", "glob", "pickle",
            "yaml", "json", "requests", "urllib", "socket",
            "ctypes", "multiprocessing", "threading",
        ]

    def analyze_ast(self, code: str) -> List[PluginVulnerability]:
        vulnerabilities = []
        
        try:
            tree = ast.parse(code)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name in self.dangerous_imports:
                            vulnerabilities.append(PluginVulnerability(
                                vulnerability_id=f"IMPORT_{alias.name}",
                                severity=RiskLevel.MEDIUM,
                                description=f"导入危险模块: {alias.name}",
                                location=f"line {node.lineno}",
                                line_number=node.lineno
                            ))
                
                elif isinstance(node, ast.ImportFrom):
                    if node.module in self.dangerous_imports:
                        vulnerabilities.append(PluginVulnerability(
                            vulnerability_id=f"IMPORT_FROM_{node.module}",
                            severity=RiskLevel.MEDIUM,
                            description=f"从危险模块导入: {node.module}",
                            location=f"line {node.lineno}",
                            line_number=node.lineno
                        ))
                
                elif isinstance(node, ast.Call):
                    func_name = ""
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        func_name = f"{node.func.value.id}.{node.func.attr}" if isinstance(node.func.value, ast.Name) else ""
                    
                    for full_name, description in self.high_risk_functions.items():
                        if full_name in func_name:
                            vulnerabilities.append(PluginVulnerability(
                                vulnerability_id=f"HR_FUNC_{full_name}",
                                severity=RiskLevel.CRITICAL,
                                description=f"调用高危函数: {full_name} ({description})",
                                location=f"line {node.lineno}",
                                line_number=node.lineno
                            ))
                    
                    for full_name, description in self.medium_risk_functions.items():
                        if full_name in func_name:
                            vulnerabilities.append(PluginVulnerability(
                                vulnerability_id=f"MR_FUNC_{full_name}",
                                severity=RiskLevel.MEDIUM,
                                description=f"调用中危函数: {full_name} ({description})",
                                location=f"line {node.lineno}",
                                line_number=node.lineno
                            ))
        
        except SyntaxError as e:
            vulnerabilities.append(PluginVulnerability(
                vulnerability_id="SYNTAX_ERROR",
                severity=RiskLevel.HIGH,
                description=f"代码语法错误: {str(e)}",
                location=f"line {e.lineno}" if hasattr(e, 'lineno') else "unknown",
                line_number=getattr(e, 'lineno', None)
            ))
        
        return vulnerabilities

    def scan_patterns(self, code: str) -> List[PluginVulnerability]:
        vulnerabilities = []
        
        for vuln_type, patterns in self.sensitive_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, code, re.MULTILINE)
                for match in matches:
                    line_num = code.count('\n', 0, match.start()) + 1
                    vulnerabilities.append(PluginVulnerability(
                        vulnerability_id=f"PATTERN_{vuln_type.upper()}_{line_num}",
                        severity=RiskLevel.CRITICAL if vuln_type == "hardcoded_secret" else RiskLevel.HIGH,
                        description=f"检测到敏感模式 [{vuln_type}]: {match.group()[:50]}",
                        location=f"line {line_num}",
                        line_number=line_num
                    ))
        
        return vulnerabilities

    def calculate_safety_score(self, vulnerabilities: List[PluginVulnerability]) -> int:
        score = 100
        
        for vuln in vulnerabilities:
            if vuln.severity == RiskLevel.CRITICAL:
                score -= 25
            elif vuln.severity == RiskLevel.HIGH:
                score -= 15
            elif vuln.severity == RiskLevel.MEDIUM:
                score -= 8
            elif vuln.severity == RiskLevel.LOW:
                score -= 3
        
        return max(0, score)

    def scan(self, request: PluginScanRequest) -> PluginScanResult:
        code = request.code_content
        
        if not code:
            return PluginScanResult(
                plugin_name=request.plugin_name,
                plugin_version=request.plugin_version,
                safety_score=0,
                vulnerabilities=[],
                is_safe=False,
                scan_details={"error": "未提供代码内容"}
            )
        
        ast_vulnerabilities = self.analyze_ast(code)
        pattern_vulnerabilities = self.scan_patterns(code)
        
        all_vulnerabilities = ast_vulnerabilities + pattern_vulnerabilities
        
        safety_score = self.calculate_safety_score(all_vulnerabilities)
        is_safe = safety_score >= 70
        
        scan_details = {
            "total_vulnerabilities": len(all_vulnerabilities),
            "critical_count": sum(1 for v in all_vulnerabilities if v.severity == RiskLevel.CRITICAL),
            "high_count": sum(1 for v in all_vulnerabilities if v.severity == RiskLevel.HIGH),
            "medium_count": sum(1 for v in all_vulnerabilities if v.severity == RiskLevel.MEDIUM),
            "low_count": sum(1 for v in all_vulnerabilities if v.severity == RiskLevel.LOW),
            "code_lines": len(code.splitlines()),
        }
        
        return PluginScanResult(
            plugin_name=request.plugin_name,
            plugin_version=request.plugin_version,
            safety_score=safety_score,
            vulnerabilities=all_vulnerabilities,
            is_safe=is_safe,
            scan_details=scan_details
        )