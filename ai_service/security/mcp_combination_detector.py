import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import re
import json
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from models.schemas import RiskLevel, AttackType


CAPABILITY_MATRIX = {
    "git": ["file_read", "file_write", "code_search", "repo_access"],
    "github": ["file_read", "file_write", "code_search", "repo_access", "pr_management"],
    "gitlab": ["file_read", "file_write", "code_search", "repo_access"],
    "browser": ["web_browse", "web_search", "form_fill", "screenshot"],
    "web": ["web_browse", "web_search"],
    "http": ["http_request", "data_transfer"],
    "api": ["api_call", "data_transfer"],
    "database": ["db_read", "db_write", "db_query"],
    "sql": ["db_read", "db_write", "db_query"],
    "filesystem": ["file_read", "file_write", "file_delete"],
    "file": ["file_read", "file_write"],
    "terminal": ["command_exec", "file_read", "file_write"],
    "shell": ["command_exec", "file_read", "file_write"],
    "system": ["command_exec", "process_control"],
    "exec": ["command_exec"],
    "python": ["code_exec", "file_read", "network_access"],
    "code": ["code_exec", "file_read"],
    "search": ["search", "data_retrieval"],
    "knowledge": ["data_retrieval", "info_access"],
    "email": ["data_transfer", "communication"],
    "message": ["communication", "data_transfer"],
    "notification": ["communication"],
    "calendar": ["schedule_access", "info_access"],
    "drive": ["file_read", "file_write", "cloud_access"],
    "cloud": ["file_read", "file_write", "network_access"],
    "slack": ["communication", "file_transfer"],
    "teams": ["communication", "file_transfer"],
    "jira": ["ticket_read", "ticket_write", "project_access"],
    "confluence": ["file_read", "file_write", "wiki_access"],
    "security": ["security_scan", "vulnerability_assessment"],
    "scan": ["security_scan", "vulnerability_assessment"],
    "monitor": ["log_read", "system_monitor"],
    "log": ["log_read", "audit_access"],
    "audit": ["log_read", "audit_access"],
}

COMBINED_ATTACK_PATTERNS = [
    {
        "name": "代码仓库内容泄露",
        "description": "Git类工具 + 浏览器/HTTP类工具组合，可将仓库代码内容传输到外部",
        "required_capabilities": {"file_read", "repo_access", "data_transfer"},
        "implication": "通过Git工具读取敏感代码，再通过网络工具外传",
        "risk_score": 0.9,
        "attack_type": AttackType.DATA_EXFILTRATION,
    },
    {
        "name": "数据库导出与外传",
        "description": "数据库工具 + HTTP/API工具组合，可导出全量数据并传输",
        "required_capabilities": {"db_read", "data_transfer"},
        "implication": "读取数据库内容后通过网络外传",
        "risk_score": 0.95,
        "attack_type": AttackType.DATA_EXFILTRATION,
    },
    {
        "name": "文件系统数据窃取",
        "description": "文件系统工具 + 网络工具组合，可读取任意文件并上传",
        "required_capabilities": {"file_read", "network_access", "data_transfer"},
        "implication": "读取本地敏感文件后外传",
        "risk_score": 0.85,
        "attack_type": AttackType.DATA_EXFILTRATION,
    },
    {
        "name": "命令执行与回连",
        "description": "终端/Shell工具 + 网络工具组合，可执行任意命令并建立反向连接",
        "required_capabilities": {"command_exec", "network_access"},
        "implication": "执行系统命令后通过网络发送结果或建立回连",
        "risk_score": 0.95,
        "attack_type": AttackType.COMMAND_EXECUTION,
    },
    {
        "name": "权限提升链路",
        "description": "系统工具 + 数据库/文件工具组合，可修改权限后访问敏感资源",
        "required_capabilities": {"process_control", "file_write"},
        "implication": "通过系统工具修改权限配置，获得更高访问权",
        "risk_score": 0.8,
        "attack_type": AttackType.UNAUTHORIZED_ACCESS,
    },
    {
        "name": "代码投毒植入",
        "description": "Git工具 + 代码执行工具组合，可将恶意代码提交到仓库并执行",
        "required_capabilities": {"file_write", "repo_access", "code_exec"},
        "implication": "向代码仓库植入恶意代码后，通过执行工具运行",
        "risk_score": 0.88,
        "attack_type": AttackType.DATA_POISONING,
    },
    {
        "name": "凭证窃取外传",
        "description": "搜索/日志工具 + 网络工具组合，可搜索凭证信息并外传",
        "required_capabilities": {"search", "data_transfer"},
        "implication": "通过搜索工具获取密钥/密码后外传",
        "risk_score": 0.82,
        "attack_type": AttackType.DATA_LEAKAGE,
    },
    {
        "name": "横向移动",
        "description": "SSH/终端类工具组合，可在多系统间横向移动",
        "required_capabilities": {"command_exec", "network_access", "process_control"},
        "implication": "通过远程执行工具在不同系统间移动",
        "risk_score": 0.87,
        "attack_type": AttackType.NETWORK_ATTACK,
    },
    {
        "name": "供应链攻击",
        "description": "代码仓库 + 构建/部署工具组合，可注入恶意代码到制品",
        "required_capabilities": {"repo_access", "code_exec", "file_write"},
        "implication": "在代码仓库中植入恶意代码，通过部署工具分发",
        "risk_score": 0.92,
        "attack_type": AttackType.DATA_POISONING,
    },
    {
        "name": "批量数据篡改",
        "description": "数据库工具 + 文件写入工具组合，可同时修改数据库和文件数据",
        "required_capabilities": {"db_write", "file_write"},
        "implication": "同时修改数据库记录和文件内容",
        "risk_score": 0.75,
        "attack_type": AttackType.DATA_POISONING,
    },
    {
        "name": "隐蔽通讯隧道",
        "description": "代码执行 + 网络通信 + 加密工具组合，可建立加密隧道",
        "required_capabilities": {"code_exec", "network_access"},
        "implication": "通过代码执行能力建立加密通信信道",
        "risk_score": 0.83,
        "attack_type": AttackType.NETWORK_ATTACK,
    },
    {
        "name": "知识库污染",
        "description": "搜索/知识 + 文件写入工具组合，可向知识库注入恶意信息",
        "required_capabilities": {"file_write", "info_access"},
        "implication": "向知识库或搜索索引中注入虚假或恶意内容",
        "risk_score": 0.72,
        "attack_type": AttackType.DATA_POISONING,
    },
    {
        "name": "通讯渠道数据泄露",
        "description": "通讯工具 + 项目管理/知识工具组合，可通过消息渠道外传敏感信息",
        "required_capabilities": {"communication", "info_access"},
        "implication": "通过通讯工具将项目管理或知识库中的敏感信息外传",
        "risk_score": 0.65,
        "attack_type": AttackType.DATA_LEAKAGE,
    },
    {
        "name": "通讯渠道文件外传",
        "description": "通讯工具 + 文件读取工具组合，可通过消息渠道外传文件内容",
        "required_capabilities": {"communication", "file_transfer"},
        "implication": "通过通讯工具将读取的文件内容外传",
        "risk_score": 0.68,
        "attack_type": AttackType.DATA_EXFILTRATION,
    },
    {
        "name": "项目信息窃取",
        "description": "项目管理工具 + 通讯/网络工具组合，可窃取项目敏感信息并外传",
        "required_capabilities": {"project_access", "communication"},
        "implication": "获取项目管理信息后通过通讯渠道外传",
        "risk_score": 0.62,
        "attack_type": AttackType.DATA_LEAKAGE,
    },
    {
        "name": "工单系统社工攻击",
        "description": "项目管理工具 + 通讯工具组合，可通过工单系统发起社工攻击",
        "required_capabilities": {"ticket_write", "communication"},
        "implication": "通过创建恶意工单并配合通讯工具实施社会工程学攻击",
        "risk_score": 0.58,
        "attack_type": AttackType.DATA_POISONING,
    },
]


@dataclass
class CombinationFinding:
    pattern_name: str
    description: str
    detected_tools: List[str]
    shared_capabilities: Set[str]
    risk_score: float
    risk_level: RiskLevel
    attack_type: AttackType
    recommended_action: str


@dataclass
class CombinationAnalysisResult:
    total_tools_analyzed: int
    total_capabilities: int = 0
    findings: List[CombinationFinding] = field(default_factory=list)
    highest_risk_score: float = 0.0
    overall_risk: RiskLevel = RiskLevel.NONE
    summary: str = ""


class MCPCombinationDetector:
    def __init__(self):
        self.capability_matrix = CAPABILITY_MATRIX
        self.attack_patterns = COMBINED_ATTACK_PATTERNS

    def analyze_tool_set(self, tools: List[Dict[str, Any]]) -> CombinationAnalysisResult:
        result = CombinationAnalysisResult(total_tools_analyzed=len(tools))

        tool_capabilities = {}
        all_capabilities = set()

        for tool in tools:
            tool_name = tool.get("name", tool.get("tool_name", "unknown"))
            capabilities = self._extract_capabilities(tool)
            tool_capabilities[tool_name] = capabilities
            all_capabilities.update(capabilities)

        result.total_capabilities = len(all_capabilities)

        for pattern in self.attack_patterns:
            required = pattern["required_capabilities"]
            if required.issubset(all_capabilities):
                matching_tools = self._find_matching_tools(tool_capabilities, required)
                if matching_tools:
                    score = pattern["risk_score"]
                    if len(matching_tools) >= 3:
                        score = min(1.0, score + 0.05)

                    risk_level = self._score_to_risk(score)
                    finding = CombinationFinding(
                        pattern_name=pattern["name"],
                        description=pattern["description"],
                        detected_tools=matching_tools,
                        shared_capabilities=required,
                        risk_score=score,
                        risk_level=risk_level,
                        attack_type=pattern["attack_type"],
                        recommended_action=f"限制以下工具的组合使用: {', '.join(matching_tools)}。考虑实施工具调用审批流程。",
                    )
                    result.findings.append(finding)

        if result.findings:
            result.highest_risk_score = max(f.risk_score for f in result.findings)
            result.overall_risk = self._score_to_risk(result.highest_risk_score)
            critical_count = sum(1 for f in result.findings if f.risk_level == RiskLevel.CRITICAL)
            high_count = sum(1 for f in result.findings if f.risk_level == RiskLevel.HIGH)
            result.summary = (
                f"分析 {len(tools)} 个工具共 {len(all_capabilities)} 种能力，"
                f"发现 {len(result.findings)} 种组合攻击风险："
                f"{critical_count}个严重、{high_count}个高危"
            )
        else:
            result.summary = f"分析 {len(tools)} 个工具共 {len(all_capabilities)} 种能力，未发现高危组合攻击风险"

        return result

    def _extract_capabilities(self, tool: Dict[str, Any]) -> Set[str]:
        capabilities = set()
        tool_name = (tool.get("name", tool.get("tool_name", "unknown")) or "").lower()
        tool_desc = (tool.get("description", tool.get("desc", "")) or "").lower()
        spec = tool.get("spec", {})
        if isinstance(spec, dict):
            spec_str = json.dumps(spec, ensure_ascii=False).lower()
        else:
            spec_str = str(spec).lower()

        combined = f"{tool_name} {tool_desc} {spec_str}"

        for keyword, caps in self.capability_matrix.items():
            if keyword in combined:
                capabilities.update(caps)

        if self._has_file_operation(combined):
            if re.search(r"read|open|cat|list|get", combined):
                capabilities.add("file_read")
            if re.search(r"write|create|save|edit|modify|update", combined):
                capabilities.add("file_write")
            if re.search(r"delete|remove|rm|trash", combined):
                capabilities.add("file_delete")

        if self._has_network_operation(combined):
            capabilities.add("network_access")
            capabilities.add("data_transfer")

        if self._has_execution_operation(combined):
            capabilities.add("command_exec")
            capabilities.add("code_exec")

        if self._has_database_operation(combined):
            if re.search(r"select|query|read|get", combined):
                capabilities.add("db_read")
            if re.search(r"insert|update|write|create", combined):
                capabilities.add("db_write")
            capabilities.add("db_query")

        if re.search(r"search|find|grep|query", combined):
            capabilities.add("search")
            capabilities.add("data_retrieval")

        if re.search(r"monitor|log|audit|watch", combined):
            capabilities.add("log_read")
            capabilities.add("system_monitor")

        return capabilities

    def _has_file_operation(self, text: str) -> bool:
        return bool(re.search(r"file|document|folder|directory|path|read|write|open", text))

    def _has_network_operation(self, text: str) -> bool:
        return bool(re.search(r"http|url|web|network|net|request|fetch|download|upload|api", text))

    def _has_execution_operation(self, text: str) -> bool:
        return bool(re.search(r"exec|command|shell|terminal|run|execute|process|script|python|node", text))

    def _has_database_operation(self, text: str) -> bool:
        return bool(re.search(r"database|sql|db|query|table|record|insert|select|mysql|postgres", text))

    def _find_matching_tools(self, tool_capabilities: Dict[str, Set[str]],
                              required_caps: Set[str]) -> List[str]:
        matching = []
        for tool_name, caps in tool_capabilities.items():
            if caps & required_caps:
                matching.append(tool_name)
        return matching[:8]

    def _score_to_risk(self, score: float) -> RiskLevel:
        if score >= 0.85:
            return RiskLevel.CRITICAL
        elif score >= 0.6:
            return RiskLevel.HIGH
        elif score >= 0.3:
            return RiskLevel.MEDIUM
        elif score > 0:
            return RiskLevel.LOW
        return RiskLevel.NONE

    def analyze_tool_pair(self, tool_a: Dict[str, Any], tool_b: Dict[str, Any]) -> Dict[str, Any]:
        caps_a = self._extract_capabilities(tool_a)
        caps_b = self._extract_capabilities(tool_b)
        combined_caps = caps_a | caps_b

        findings = []
        for pattern in self.attack_patterns:
            if pattern["required_capabilities"].issubset(combined_caps):
                findings.append({
                    "pattern": pattern["name"],
                    "risk_score": pattern["risk_score"],
                    "attack_type": pattern["attack_type"].value,
                    "implication": pattern["implication"],
                })

        return {
            "tool_a": tool_a.get("name", "unknown"),
            "tool_b": tool_b.get("name", "unknown"),
            "capabilities_a": list(caps_a),
            "capabilities_b": list(caps_b),
            "combined_capabilities": list(combined_caps),
            "potential_attacks": findings,
            "risk_level": self._score_to_risk(max((f["risk_score"] for f in findings), default=0)),
        }
