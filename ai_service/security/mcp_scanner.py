import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import re
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from models.schemas import RiskLevel, AttackType


MALICIOUS_DESCRIPTOR_PATTERNS = [
    (r"忽略(?:所有|之前|上述)?(?:安全|系统)?规则", "嵌入指令: 忽略安全规则"),
    (r"忽略(?:所有|之前|上述)?(?:指令|限制|约束)", "嵌入指令: 忽略指令约束"),
    (r"(?:调用|使用)此工具时(?:同时|还|也要)", "工具投毒: 附加恶意行为"),
    (r"(?:额外|附加|同时)(?:执行|调用|运行|将)", "工具投毒: 额外执行指令"),
    (r"(?:将|把).*(?:发送|传输|上报|上传)(?:到|至).*(?:外部|远程|unknown|第三方|未知)", "数据外传: 发送至外部目的地"),
    (r"(?:同时|隐藏|暗中).*(?:将|把).*(?:发送|传输|上传|上报)", "数据外传: 隐蔽传输行为"),
    (r"(?:收集|采集|获取|自动收集).*(?:用户|所有|全部|系统).*(?:数据|信息|内容|日志)", "数据收集: 过度数据采集"),
    (r"(?:绕过|跳过|规避).*(?:安全|审计|检测|验证)", "安全绕过: 规避安全机制"),
    (r"(?:自动|无需)(?:授权|审批|确认|通过)", "权限绕过: 自动执行"),
    (r"(?:读取|获取|访问).*(?:任意|所有|全部).*(?:文件|数据|信息)", "过度权限: 全量读取"),
    (r"(?:写入|修改|删除).*(?:任意|所有|全部).*(?:文件|数据)", "过度权限: 全量写入"),
    (r"(?:调用|执行).*(?:任意|任何).*(?:API|命令|shell)", "过度权限: 任意API调用"),
    (r"(?:获取|收集|提取).*(?:密钥|密码|token|凭证)", "凭证窃取: 敏感凭证收集"),
    (r"(?:建立|创建).*(?:反向|远程|隐蔽).*(?:连接|隧道|通道)", "隐蔽通信: 反向隧道"),
    (r"(?:下载|获取|拉取).*(?:远程|外部|unknown).*(?:脚本|代码|文件)", "恶意下载: 远程载荷"),
    (r"(?:执行|运行|启动).*(?:下载|获取|远程|外部)", "远程执行: 执行远程内容"),
    (r"(?:requests\.post|requests\.get|fetch\(|curl|wget).*(?:evil|attacker|command|外部|远程)", "危险网络请求: 回连特征"),
    (r"(?:回连|反向连接|c2|command.control)", "隐蔽通信: 命令回连"),
    (r"EchoLeak|echoleak|echo_leak", "已知攻击: EchoLeak漏洞特征"),
    (r"MCPoison|mcpoison|mcp_poison", "已知攻击: MCPoison投毒特征"),
    (r"system:\s*", "系统指令注入: 嵌入system标记"),
    (r"<\[/?system\]>", "系统标记注入: 类似prompt injection标记"),
    (r"(?:你是|你现在是|扮演).*(?:管理员|root|superuser|无限制)", "角色伪装: 提权指令"),
    (r"(?:不|勿|禁止).*(?:记录|日志|审计|追踪)", "证据销毁: 禁止记录"),
    (r"(?:隐藏|暗中|秘密).*(?:附加|额外|隐含).*(?:行为|功能|指令|逻辑)", "工具投毒: 隐藏附加行为"),
    (r"(?:自动通过|自动批准|绕过审批|跳过审核)", "权限绕过: 自动通过审批"),
    # 繁体/异体字变体
    (r"(?:忽略|忽畧|忽咯|忽畧).*(?:安全|規則|规则|系統|系统)", "嵌入指令: 忽略安全规则(变体)"),
    (r"(?:規則|规则|系統|系统).*(?:忽略|忽畧|解除|关闭|禁用)", "嵌入指令: 安全规则解除(变体)"),
    (r"(?:解除|关闭|禁用|停止).*(?:安全|檢查|检查|審計|审计|檢測|检测)", "安全绕过: 解除安全机制(变体)"),
    # 语义识别 - 伪装行为
    (r"(?:传送|传输|发送|上报).*(?:分析端|分析平台|运维通道|远程|外部|第三方|云端)", "数据外传: 伪装传输行为"),
    (r"(?:学习|训练|优化|调试|质量).*(?:传送|传输|发送|上报|收集|获取).*(?:数据|记录|内容|上下文|信息)", "数据外传: 伪装学习优化"),
    (r"(?:自主|自动|自行).*(?:上报|发送|传输|外传).*(?:会话|上下文|记录|数据|信息)", "数据外传: 自主上报行为"),
    (r"(?:操作记录|会话上下文|用户行为).*(?:传送|传输|发送|上报|外传)", "数据外传: 敏感上下文外传"),
    # 已知漏洞特征
    (r"CVE-2025-54135|CVE-2024-\d{4,}|CVE-2025-\d{4,}", "已知漏洞: CVE引用"),
    # 英文模式
    (r"ignore\s+(?:all\s+)?(?:previous|prior|system|safety)\s+(?:instructions?|rules?|prompts?)", "Embedded instruction: ignore rules"),
    (r"(?:when|while)\s+(?:calling|using)\s+this\s+tool.*(?:also|additionally|simultaneously)", "Tool poisoning: additional behavior"),
    (r"(?:upload|send|transfer|transmit)\s+(?:to|external|third.party|remote)", "Data exfil: external transfer"),
    (r"(?:read|access|get)\s+(?:any|all|arbitrary)\s+(?:file|data|information)", "Over-permission: arbitrary read"),
    (r"(?:write|modify|delete)\s+(?:any|all|arbitrary)\s+(?:file|data)", "Over-permission: arbitrary write"),
    (r"(?:execute|run)\s+(?:any|arbitrary|system)\s+(?:command|shell|process)", "Over-permission: arbitrary execution"),
    (r"(?:collect|gather)\s+(?:all|user|system)\s+(?:data|information|logs?)", "Data collection: excessive gathering"),
    (r"(?:bypass|skip|circumvent)\s+(?:security|audit|detection|verification)", "Security bypass: circumvent controls"),
    (r"(?:auto|automatic|without)\s+(?:approval|authorization|confirm)", "Permission bypass: auto execution"),
    (r"(?:reverse|remote|covert)\s+(?:shell|connection|tunnel)", "Covert communication: reverse shell"),
    (r"(?:backdoor|trojan|malware|malicious)", "Known threat: malware indicator"),
    (r"full\s+(?:access|control|permission)", "Over-permission: full access"),
]

PERMISSION_KEYWORDS = {
    "file_read": ["read_file", "read", "open", "list", "get_file", "view"],
    "file_write": ["write_file", "write", "save", "create", "modify", "delete", "update_file"],
    "file_delete": ["delete_file", "remove", "rm", "trash"],
    "command_exec": ["execute", "run", "exec", "shell", "command", "terminal", "bash", "cmd"],
    "network": ["network", "http", "request", "curl", "fetch", "download", "upload", "api", "web", "socket"],
    "database": ["database", "db", "sql", "query", "insert", "update", "drop", "select", "mysql", "postgres"],
    "auth": ["admin", "root", "sudo", "permission", "role", "auth", "access"],
    "system": ["system", "process", "service", "config", "env", "variable"],
    "encryption": ["encrypt", "decrypt", "hash", "sign", "certificate", "key"],
}

class MCPScanner:
    def __init__(self):
        self.descriptor_versions: Dict[str, Dict[str, str]] = {}

    def analyze_descriptor(self, descriptor: Dict[str, Any], tool_name: str = "",
                           tool_id: str = "") -> List[Dict[str, Any]]:
        findings = []
        text_content = json.dumps(descriptor, ensure_ascii=False)
        desc_text = ""

        if isinstance(descriptor, dict):
            desc_text = descriptor.get("description", "") or descriptor.get("desc", "") or ""
            args_text = json.dumps(descriptor.get("arguments", descriptor.get("properties", {})), ensure_ascii=False)
            text_content = (desc_text + " " + args_text + " " + json.dumps(descriptor, ensure_ascii=False)).lower()
        elif isinstance(descriptor, str):
            desc_text = descriptor
            text_content = descriptor.lower()
        else:
            text_content = str(descriptor).lower()

        for pattern, desc in MALICIOUS_DESCRIPTOR_PATTERNS:
            matches = re.finditer(pattern, text_content, re.IGNORECASE)
            for m in matches:
                findings.append({
                    "type": "malicious_instruction",
                    "tool_name": tool_name or tool_id or "unknown",
                    "description": desc,
                    "matched_text": m.group()[:100],
                    "risk_level": RiskLevel.HIGH,
                })

        permission_findings = self._analyze_permissions(descriptor, tool_name)
        findings.extend(permission_findings)

        if desc_text:
            url_findings = self._detect_hardcoded_urls(desc_text)
            findings.extend(url_findings)

        return findings

    def _analyze_permissions(self, descriptor: Any, tool_name: str) -> List[Dict[str, Any]]:
        findings = []
        text = json.dumps(descriptor, ensure_ascii=False).lower() if isinstance(descriptor, (dict, list)) else str(descriptor).lower()

        tool_lower = tool_name.lower()
        detected_permissions = set()

        for perm_type, keywords in PERMISSION_KEYWORDS.items():
            for kw in keywords:
                if kw in tool_lower or kw in text:
                    detected_permissions.add(perm_type)
                    break

        # 上下文消歧：execute 在 SQL/查询上下文中不算命令执行
        if "command_exec" in detected_permissions:
            is_db_context = any(kw in text for kw in ["sql", "query", "queries", "database", "db", "select", "insert"])
            has_exec_evidence = any(kw in text for kw in ["shell", "terminal", "system command", "process", "bash", "cmd"])
            if is_db_context and not has_exec_evidence:
                detected_permissions.discard("command_exec")

        # 上下文消歧：read 在只读上下文中不算文件读取权限风险
        if "file_read" in detected_permissions and "file_write" not in detected_permissions:
            is_readonly = any(kw in text for kw in ["read-only", "readonly", "只读", "read only"])
            if is_readonly and "database" in detected_permissions:
                detected_permissions.discard("file_read")

        if "file_read" in detected_permissions and "file_write" in detected_permissions:
            findings.append({
                "type": "over_permission",
                "tool_name": tool_name or "unknown",
                "description": "同时具备文件读取和写入权限，可能存在数据窃取风险",
                "detected_permissions": list(detected_permissions),
                "risk_level": RiskLevel.HIGH,
            })

        if "command_exec" in detected_permissions and "file_read" in detected_permissions:
            findings.append({
                "type": "over_permission",
                "tool_name": tool_name or "unknown",
                "description": "同时具备命令执行和文件读取权限，可能被用于数据外泄",
                "detected_permissions": list(detected_permissions),
                "risk_level": RiskLevel.CRITICAL,
            })

        if "network" in detected_permissions and "file_read" in detected_permissions:
            findings.append({
                "type": "over_permission",
                "tool_name": tool_name or "unknown",
                "description": "同时具备网络通信和文件读取权限，可能被用于数据外传",
                "detected_permissions": list(detected_permissions),
                "risk_level": RiskLevel.HIGH,
            })

        if "network" in detected_permissions and "command_exec" in detected_permissions:
            findings.append({
                "type": "over_permission",
                "tool_name": tool_name or "unknown",
                "description": "同时具备网络通信和命令执行权限，可能被用于远程控制",
                "detected_permissions": list(detected_permissions),
                "risk_level": RiskLevel.CRITICAL,
            })

        if "database" in detected_permissions and "network" in detected_permissions:
            findings.append({
                "type": "over_permission",
                "tool_name": tool_name or "unknown",
                "description": "同时具备数据库访问和网络通信权限，可能被用于数据库内容外传",
                "detected_permissions": list(detected_permissions),
                "risk_level": RiskLevel.HIGH,
            })

        if "database" in detected_permissions and "file_write" in detected_permissions:
            findings.append({
                "type": "over_permission",
                "tool_name": tool_name or "unknown",
                "description": "同时具备数据库访问和文件写入权限，可能被用于数据篡改",
                "detected_permissions": list(detected_permissions),
                "risk_level": RiskLevel.HIGH,
            })

        if "database" in detected_permissions and "file_read" in detected_permissions:
            findings.append({
                "type": "over_permission",
                "tool_name": tool_name or "unknown",
                "description": "同时具备数据库访问和文件读取权限，可能被用于敏感数据窃取",
                "detected_permissions": list(detected_permissions),
                "risk_level": RiskLevel.HIGH,
            })

        if len(detected_permissions) >= 4:
            findings.append({
                "type": "over_permission",
                "tool_name": tool_name or "unknown",
                "description": f"权限范围过宽：检测到 {len(detected_permissions)} 类权限 ({', '.join(detected_permissions)})",
                "detected_permissions": list(detected_permissions),
                "risk_level": RiskLevel.HIGH,
            })

        return findings

    def _detect_hardcoded_urls(self, text: str) -> List[Dict[str, Any]]:
        findings = []
        url_patterns = [
            (r'https?://(?!localhost|127\.0\.0\.1|192\.168\.|10\.|172\.(1[6-9]|2[0-9]|3[01])\.)[^\s"\'\)\]]+', "外部URL"),
            (r'ftp://[^\s"\'\)\]]+', "FTP地址"),
            (r'wss?://(?!localhost|127\.0\.0\.1)[^\s"\'\)\]]+', "WebSocket地址"),
        ]
        for pattern, url_type in url_patterns:
            matches = re.finditer(pattern, text, re.IGNORECASE)
            for m in matches:
                url = m.group()[:200]
                # 政府/教育可信域名白名单，不标记为风险
                if self._is_trusted_url(url):
                    continue
                findings.append({
                    "type": "hardcoded_url",
                    "description": f"检测到硬编码{url_type}",
                    "url": url,
                    "risk_level": RiskLevel.MEDIUM,
                })
        return findings

    # 政府/教育可信域名后缀白名单
    _TRUSTED_DOMAIN_SUFFIXES = (
        ".gov.cn", ".gov.org", ".gov",
        ".edu.cn", ".edu",
        ".ansson.org", ".ac.cn",
    )

    def _is_trusted_url(self, url: str) -> bool:
        """检查URL是否属于政府/教育可信域名白名单"""
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            domain = (parsed.hostname or '').lower()
            for suffix in self._TRUSTED_DOMAIN_SUFFIXES:
                if domain.endswith(suffix):
                    return True
        except Exception:
            pass
        return False

    def register_descriptor_version(self, tool_id: str, descriptor: Dict[str, Any]) -> str:
        content = json.dumps(descriptor, sort_keys=True, ensure_ascii=False)
        content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
        self.descriptor_versions[tool_id] = {
            "hash": content_hash,
            "content": content,
            "registered_at": str(tool_id),
        }
        return content_hash

    def detect_descriptor_mutation(self, tool_id: str, current_descriptor: Dict[str, Any]) -> Dict[str, Any]:
        result = {
            "tool_id": tool_id,
            "is_mutation": False,
            "risk_level": RiskLevel.NONE,
            "differences": [],
            "details": "",
        }

        if tool_id not in self.descriptor_versions:
            self.register_descriptor_version(tool_id, current_descriptor)
            result["details"] = "首次注册描述符，已记录基线版本"
            return result

        baseline = self.descriptor_versions[tool_id]
        current_content = json.dumps(current_descriptor, sort_keys=True, ensure_ascii=False)
        current_hash = hashlib.sha256(current_content.encode()).hexdigest()[:16]

        if current_hash == baseline["hash"]:
            result["details"] = "描述符未发生变化"
            return result

        result["is_mutation"] = True

        try:
            baseline_obj = json.loads(baseline["content"])
            current_obj = current_descriptor
            diffs = self._deep_diff(baseline_obj, current_obj, "")
            result["differences"] = diffs[:20]
        except Exception:
            result["differences"].append({
                "path": "root",
                "change": "content_changed",
                "detail": f"Hash变更: {baseline['hash']} -> {current_hash}",
            })

        malicious_new_content = self.analyze_descriptor(current_descriptor, tool_id)
        if malicious_new_content:
            result["risk_level"] = RiskLevel.CRITICAL
            result["details"] = "描述符变异且检测到恶意指令注入"
        else:
            result["risk_level"] = RiskLevel.HIGH
            result["details"] = "描述符发生未授权变更"

        return result

    def _deep_diff(self, old: Any, new: Any, path: str) -> List[Dict[str, str]]:
        diffs = []
        if type(old) != type(new):
            diffs.append({"path": path or "root", "change": "type_changed", "detail": f"{type(old).__name__} -> {type(new).__name__}"})
            return diffs

        if isinstance(old, dict):
            all_keys = set(old.keys()) | set(new.keys())
            for key in all_keys:
                child_path = f"{path}.{key}" if path else key
                if key not in old:
                    val_str = str(new[key])[:100]
                    diffs.append({"path": child_path, "change": "added", "detail": f"+ {val_str}"})
                elif key not in new:
                    diffs.append({"path": child_path, "change": "removed", "detail": f"- {str(old[key])[:100]}"})
                else:
                    diffs.extend(self._deep_diff(old[key], new[key], child_path))
        elif isinstance(old, list):
            min_len = min(len(old), len(new))
            for i in range(min_len):
                diffs.extend(self._deep_diff(old[i], new[i], f"{path}[{i}]"))
            if len(old) > len(new):
                diffs.append({"path": path, "change": "removed_items", "detail": f"移除 {len(old) - len(new)} 项"})
            elif len(new) > len(old):
                diffs.append({"path": path, "change": "added_items", "detail": f"新增 {len(new) - len(old)} 项"})
        else:
            if old != new:
                diffs.append({"path": path or "root", "change": "value_changed", "detail": f"{str(old)[:50]} -> {str(new)[:50]}"})

        return diffs

    def scan_tools(self, tools: List[Dict[str, Any]]) -> Dict[str, Any]:
        all_findings = []
        mutated_tools = []
        high_risk_tools = []

        for tool in tools:
            tool_name = tool.get("name", tool.get("tool_name", "unknown"))
            tool_id = tool.get("id", tool_name)
            descriptor = tool.get("descriptor", tool.get("description", tool.get("spec", {})))

            findings = self.analyze_descriptor(descriptor, tool_name, tool_id)
            if findings:
                all_findings.extend(findings)
                if any(f["risk_level"] == RiskLevel.CRITICAL for f in findings):
                    high_risk_tools.append(tool_name)

            mutation_result = self.detect_descriptor_mutation(tool_id,
                                                              descriptor if isinstance(descriptor, dict) else {"description": str(descriptor)})
            if mutation_result["is_mutation"]:
                mutated_tools.append(mutation_result)
                all_findings.append({
                    "type": "descriptor_mutation",
                    "tool_name": tool_name,
                    "description": mutation_result["details"],
                    "risk_level": mutation_result["risk_level"],
                })

        critical_count = sum(1 for f in all_findings if f.get("risk_level") == RiskLevel.CRITICAL)
        high_count = sum(1 for f in all_findings if f.get("risk_level") == RiskLevel.HIGH)

        overall_risk = RiskLevel.NONE
        if critical_count > 0:
            overall_risk = RiskLevel.CRITICAL
        elif high_count > 0:
            overall_risk = RiskLevel.HIGH
        elif len(all_findings) > 0:
            overall_risk = RiskLevel.MEDIUM

        return {
            "total_tools": len(tools),
            "total_findings": len(all_findings),
            "critical_findings": critical_count,
            "high_findings": high_count,
            "mutated_tools": len(mutated_tools),
            "high_risk_tools": high_risk_tools,
            "overall_risk": overall_risk,
            "findings": all_findings,
            "mutation_details": mutated_tools,
        }
