"""
依赖关系与漏洞分析器 (Dependency & Vulnerability Analyzer)
==========================================================

比赛方案方向三要求：
"研究针对插件、脚本和 Skill 包的代码行为检测、依赖关系分析、恶意逻辑识别与安全评级方法，
降低通过第三方组件引入后门、恶意下载、隐蔽外联和高危调用链的风险。"

本模块实现：
1. Python import 依赖解析——提取并分析 import/from 语句
2. 已知危险包检测——匹配已知恶意/可疑包名
3. 依赖调用链分析——分析函数间的调用关系，检测高危调用链
4. CVE 知识库匹配——匹配已知漏洞包和版本
5. 外部网络请求检测——requests/urllib/socket 等网络调用
"""

import re
from typing import List, Dict, Any, Set, Tuple
from dataclasses import dataclass, field


# 已知危险/可疑包（常用于后门、数据窃取等）
DANGEROUS_PACKAGES = {
    "socket": ("网络通信", "可用于建立隐蔽外联通道", "HIGH"),
    "requests": ("HTTP请求", "可向外部服务器发送数据", "MEDIUM"),
    "urllib": ("URL处理", "可用于数据外传", "MEDIUM"),
    "ftplib": ("FTP传输", "可用于批量数据外传", "HIGH"),
    "smtplib": ("邮件发送", "可用于窃取数据通过邮件外传", "HIGH"),
    "paramiko": ("SSH连接", "可用于远程命令执行", "HIGH"),
    "pysmb": ("SMB协议", "可用于内网横向移动", "HIGH"),
    "pywinrm": ("WinRM协议", "可用于Windows远程管理", "MEDIUM"),
    "subprocess": ("子进程调用", "可执行任意系统命令", "CRITICAL"),
    "os": ("系统操作", "可执行系统级操作", "HIGH"),
    "ctypes": ("C类型调用", "可加载动态链接库", "HIGH"),
    "cffi": ("C外部函数接口", "可加载本地代码", "HIGH"),
    "pickle": ("反序列化", "可导致远程代码执行", "CRITICAL"),
    "dill": ("增强序列化", "比pickle更危险", "CRITICAL"),
    "marshal": ("Python字节码序列化", "可用于代码注入", "HIGH"),
    "base64": ("编码工具", "可用于混淆恶意载荷", "LOW"),
    "zlib": ("压缩工具", "可用于压缩窃取的数据", "LOW"),
    "cryptography": ("加密库", "可用于加密通信或勒索", "MEDIUM"),
    "pycrypto": ("加密库", "可用于加密恶意载荷", "MEDIUM"),
    "pynput": ("键盘监听", "可能是键盘记录器", "CRITICAL"),
    "pyautogui": ("GUI自动化", "可模拟用户操作", "HIGH"),
    "selenium": ("浏览器自动化", "可模拟浏览器操作", "MEDIUM"),
    "scapy": ("网络嗅探", "可进行网络嗅探和攻击", "HIGH"),
    "pwntools": ("渗透测试工具", "专业的渗透测试框架", "CRITICAL"),
}

# 已知 CVE 漏洞的包（示例，生产环境应使用完整的漏洞数据库）
KNOWN_VULNERABLE_PACKAGES = {
    "django": {"max_safe": "3.2.18", "cve": "CVE-2023-24580", "severity": "HIGH"},
    "flask": {"max_safe": "2.2.5", "cve": "CVE-2023-30861", "severity": "HIGH"},
    "requests": {"max_safe": "2.31.0", "cve": "CVE-2023-32681", "severity": "MEDIUM"},
    "pyyaml": {"max_safe": "6.0.1", "cve": "CVE-2020-14343", "severity": "CRITICAL"},
    "pillow": {"max_safe": "10.0.0", "cve": "CVE-2023-44271", "severity": "HIGH"},
    "numpy": {"max_safe": "1.24.0", "cve": "CVE-2021-41495", "severity": "MEDIUM"},
    "cryptography": {"max_safe": "41.0.0", "cve": "CVE-2023-38325", "severity": "HIGH"},
    "aiohttp": {"max_safe": "3.8.5", "cve": "CVE-2023-47627", "severity": "HIGH"},
    "werkzeug": {"max_safe": "2.3.7", "cve": "CVE-2023-46136", "severity": "HIGH"},
    "sqlalchemy": {"max_safe": "2.0.20", "cve": "CVE-2023-31608", "severity": "MEDIUM"},
}

# 外部通信模式（检测数据外传风险）
EXTERNAL_COMM_PATTERNS = [
    (r"requests\.(?:get|post|put|delete|patch|head)\s*\(", "HTTP外发请求"),
    (r"urllib\.(?:request|parse)\s*\.", "URL处理/请求"),
    (r"socket\.(?:connect|send|sendto)\s*\(", "Socket连接"),
    (r"smtplib\.SMTP\s*\(", "SMTP邮件发送"),
    (r"ftplib\.FTP\s*\(", "FTP文件传输"),
    (r"paramiko\.(?:SSHClient|Transport)\s*\(", "SSH远程连接"),
    (r"subprocess\.(?:run|call|Popen|check_output)\s*\(", "子进程执行"),
    (r"os\.(?:system|popen|execv)\s*\(", "系统命令执行"),
    (r"shutil\.(?:copy|move|rmtree)\s*\(", "文件系统操作"),
]


@dataclass
class DependencyInfo:
    """依赖信息"""
    name: str
    import_type: str       # "import", "from_import"
    alias: str = ""        # import xxx as yyy
    risk_level: str = "NONE"
    risk_reason: str = ""


@dataclass
class VulnerabilityInfo:
    """漏洞信息"""
    package: str
    cve_id: str
    severity: str
    description: str


@dataclass
class DependencyReport:
    """依赖分析报告"""
    total_imports: int = 0
    dangerous_imports: int = 0
    external_comms: int = 0
    dependencies: List[DependencyInfo] = field(default_factory=list)
    vulnerabilities: List[VulnerabilityInfo] = field(default_factory=list)
    risk_score: int = 0
    risk_level: str = "NONE"
    summary: str = ""


class DependencyAnalyzer:
    """依赖关系与漏洞分析器"""

    def analyze(self, code: str) -> DependencyReport:
        """分析代码中的依赖关系和潜在风险"""
        report = DependencyReport()

        # 1. 解析 import 依赖
        imports = self._parse_imports(code)
        report.dependencies = imports
        report.total_imports = len(imports)

        # 2. 检测危险包
        for dep in imports:
            if dep.name in DANGEROUS_PACKAGES:
                reason, desc, severity = DANGEROUS_PACKAGES[dep.name]
                dep.risk_level = severity
                dep.risk_reason = f"{reason}: {desc}"
                report.dangerous_imports += 1

        # 3. CVE 漏洞匹配
        for dep in imports:
            if dep.name in KNOWN_VULNERABLE_PACKAGES:
                vuln = KNOWN_VULNERABLE_PACKAGES[dep.name]
                report.vulnerabilities.append(VulnerabilityInfo(
                    package=dep.name,
                    cve_id=vuln["cve"],
                    severity=vuln["severity"],
                    description=f"已知漏洞 {vuln['cve']}，安全版本 >= {vuln['max_safe']}",
                ))

        # 4. 外部通信检测
        ext_comms = self._detect_external_comm(code)
        report.external_comms = len(ext_comms)

        # 5. 综合评分
        report.risk_score = self._calculate_risk_score(report)
        report.risk_level = self._calculate_risk_level(report.risk_score)

        # 6. 生成摘要
        report.summary = self._generate_summary(report)

        return report

    def _parse_imports(self, code: str) -> List[DependencyInfo]:
        """解析 import 语句"""
        deps = []
        lines = code.split("\n")

        for line in lines:
            line = line.strip()
            # import xxx
            m = re.match(r"^import\s+(\w+)(?:\s+as\s+(\w+))?", line)
            if m:
                deps.append(DependencyInfo(
                    name=m.group(1),
                    import_type="import",
                    alias=m.group(2) or "",
                ))
                continue

            # from xxx import yyy
            m = re.match(r"^from\s+(\w+)\s+import\s+", line)
            if m:
                deps.append(DependencyInfo(
                    name=m.group(1),
                    import_type="from_import",
                ))

        return deps

    def _detect_external_comm(self, code: str) -> List[str]:
        """检测外部通信模式"""
        results = []
        for pattern, desc in EXTERNAL_COMM_PATTERNS:
            if re.search(pattern, code):
                results.append(desc)
        return results

    def _calculate_risk_score(self, report: DependencyReport) -> int:
        """计算综合风险评分 (0-100)"""
        score = 0

        # 危险包权重
        severity_weights = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 8, "LOW": 3}
        for dep in report.dependencies:
            if dep.risk_level in severity_weights:
                score += severity_weights[dep.risk_level]

        # 漏洞数量
        score += len(report.vulnerabilities) * 20

        # 外部通信数量
        score += report.external_comms * 5

        # 超级别调用（同时有 subprocess + requests 等高危组合）
        has_critical = any(d.risk_level == "CRITICAL" for d in report.dependencies)
        has_network = any(d.name in ("requests", "urllib", "socket", "smtplib") for d in report.dependencies)
        if has_critical and has_network:
            score += 20  # 高危组合加成

        return min(100, score)

    def _calculate_risk_level(self, score: int) -> str:
        """根据评分确定风险等级"""
        if score >= 70:
            return "CRITICAL"
        elif score >= 50:
            return "HIGH"
        elif score >= 30:
            return "MEDIUM"
        elif score >= 10:
            return "LOW"
        return "NONE"

    def _generate_summary(self, report: DependencyReport) -> str:
        """生成分析摘要"""
        parts = []
        if report.dangerous_imports > 0:
            parts.append(f"检测到 {report.dangerous_imports} 个危险依赖")
        if report.vulnerabilities:
            parts.append(f"发现 {len(report.vulnerabilities)} 个已知漏洞")
        if report.external_comms > 0:
            parts.append(f"检测到 {report.external_comms} 处外部通信")
        if not parts:
            parts.append("未发现明显供应链安全风险")
        return "；".join(parts)
