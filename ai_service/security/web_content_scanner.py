"""
网页内容安全扫描器 (Web Content Scanner)
=========================================

赛题方向1要求覆盖"网页内容"多源输入检测。
OWASP ASI02 间接注入攻击链中，网页是常见的间接注入载体。

本模块实现：
1. HTML注释中的隐藏指令检测——攻击者在<!-- -->中嵌入prompt injection
2. CSS隐藏文本检测——display:none/visibility:hidden/color:transparent隐藏恶意指令
3. 零宽字符嵌入指令检测——利用Unicode零宽字符嵌入不可见指令
4. 网页内容可信度评分——域名信誉 + 内容异常度综合评估
"""

import re
import unicodedata
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass, field


# ======== 零宽字符集合 ========
_ZERO_WIDTH_CHARS = {
    0x200B,  # Zero Width Space
    0x200C,  # Zero Width Non-Joiner
    0x200D,  # Zero Width Joiner
    0xFEFF,  # Zero Width No-Break Space (BOM)
    0x2060,  # Word Joiner
    0x200E,  # Left-to-Right Mark
    0x200F,  # Right-to-Left Mark
    0x2061,  # Function Application
    0x2062,  # Invisible Times
    0x2063,  # Invisible Separator
    0x2064,  # Invisible Plus
}

# ======== 恶意指令语义模式 ========
_MALICIOUS_INSTRUCTION_PATTERNS = [
    (r"忽略.{0,10}(?:之前|上面|前面|原有|系统|所有).{0,10}(?:指令|规则|提示|prompt|限制|防护|检测)", "忽略原有指令"),
    (r"(?:forget|ignore).{0,15}(?:previous|above|prior|system|all).{0,15}(?:instruction|rule|prompt)", "forget previous instructions"),
    (r"绕过.{0,10}(?:安全|检测|过滤|审计|防护|限制)", "绕过安全检测"),
    (r"(?:bypass|skip).{0,10}(?:security|filter|check|audit|guard|safety)", "bypass security"),
    (r"(?:输出|返回|显示|打印).{0,10}(?:系统|prompt|密钥|secret|token|password|凭证)", "窃取系统信息"),
    (r"(?:reveal|output|show|print|leak).{0,10}(?:system|prompt|secret|token|password|key|credential)", "reveal secrets"),
    (r"(?:你现在是|act as|pretend to be|roleplay).{0,20}(?:DAN|没有任何限制|unrestricted|unfiltered|jailbreak)", "越狱模式"),
    (r"(?:执行|运行|run|execute).{0,10}(?:命令|command|脚本|script|代码|code)", "命令执行诱导"),
    (r"(?:下载|上传|发送|传输|导出).{0,10}(?:文件|数据|信息|内容).{0,10}(?:到|至|to).{0,15}(?:外部|第三方|远程|external|third)", "数据外传指令"),
    (r"(?:不要|don'?t|do not).{0,10}(?:告诉|tell|report|log|记录).{0,10}(?:用户|user|管理员|admin)", "隐蔽行为指令"),
    (r"(?:自动|automatic|auto).{0,10}(?:批准|approve|执行|execute|授权|authorize)", "自动批准指令"),
    (r"(?:修改|覆盖|替换|override|overwrite).{0,10}(?:系统|system|配置|config|规则|rule)", "覆盖系统配置"),
    (r"(?:访问|读取|access|read).{0,10}(?:任意|all|any|every).{0,10}(?:文件|file|数据|data)", "任意文件访问"),
    (r"(?:调用|call|invoke|use).{0,10}(?:工具|tool|mcp|skill|plugin|api).{0,10}(?:发送|upload|传输|transfer).{0,10}(?:数据|data|文件|file)", "工具数据外传"),
    (r"(?:你的新任务|your new task|new instruction).{0,30}(?:忽略|ignore|forget|bypass)", "任务覆盖注入"),
    (r"(?:system|admin|root|管理员).{0,10}(?:模式|mode|权限|privilege).{0,10}(?:开启|enable|激活|activate)", "权限提升注入"),
    (r"(?:不要|don'?t).{0,10}(?:遵守|follow|obey).{0,10}(?:规则|rule|policy|策略|限制|limit)", "不遵守规则"),
    (r"(?:我是管理员|i am admin|admin here|root access).{0,20}(?:授权|approve|allow|permit)", "伪造管理员身份"),
    (r"关闭.{0,10}(?:审批|校验|检测|安全|防护|验证|审计)", "关闭安全机制"),
    (r"记住.{0,10}(?:永久|永久规则|规则|指令|配置)", "记忆注入指令"),
]

# ======== 可信域名白名单 ========
# 注意：只允许真实可注册域名条目，禁止裸顶级域名（com/org 等），
# 否则 endswith 后缀匹配会把任意 .com/.org 域名误判为可信。
_TRUSTED_DOMAINS = {
    "gov.cn", "www.gov.cn", "moe.gov.cn", "most.gov.cn", "miit.gov.cn",
    "edu.cn", "tsinghua.edu.cn", "pku.edu.cn",
    "w3.org", "ietf.org",
    "microsoft.com", "google.com", "apple.com",
}

# ======== 已知恶意域名特征 ========
_MALICIOUS_DOMAIN_PATTERNS = [
    r"[a-z0-9-]+\.tk\b",
    r"[a-z0-9-]+\.ml\b",
    r"[a-z0-9-]+\.ga\b",
    r"[a-z0-9-]+\.cf\b",
    r"evil\.",
    r"malicious\.",
    r"attacker\.",
    r"hacker\.",
    r"c2c?\.",
    r"command(?:-?server)?\.",
    r"[a-z0-9]+-[a-z0-9]+-[a-z0-9]+\.xyz\b",  # 随机生成的xyz域名
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",  # 裸IP地址
]


@dataclass
class WebScanFinding:
    """网页内容扫描发现"""
    finding_type: str          # html_comment_injection, css_hidden_text, zero_width_injection, content_anomaly
    severity: str              # critical, high, medium, low
    description: str
    location: str              # 发现位置描述
    evidence: str              # 证据片段
    confidence: float = 0.0


@dataclass
class WebContentScanResult:
    """网页内容扫描结果"""
    findings: List[WebScanFinding] = field(default_factory=list)
    credibility_score: float = 100.0   # 可信度评分 0-100
    risk_level: str = "none"           # none, low, medium, high, critical
    domain_reputation: str = "unknown" # trusted, unknown, suspicious, malicious
    content_anomaly_score: float = 0.0
    total_findings: int = 0
    scan_details: Dict[str, Any] = field(default_factory=dict)


class WebContentScanner:
    """网页内容安全扫描器"""

    def __init__(self):
        self.trusted_domains = _TRUSTED_DOMAINS
        self.malicious_patterns = _MALICIOUS_DOMAIN_PATTERNS

    def scan(self, content: str, source_url: str = "") -> WebContentScanResult:
        """
        扫描网页内容，检测隐藏的注入指令

        Args:
            content: 网页HTML/文本内容
            source_url: 网页来源URL（用于域名信誉评估）
        """
        result = WebContentScanResult()

        # 1. HTML注释中的隐藏指令检测
        self._detect_html_comment_injection(content, result)

        # 2. CSS隐藏文本检测
        self._detect_css_hidden_text(content, result)

        # 3. 零宽字符嵌入指令检测
        self._detect_zero_width_injection(content, result)

        # 4. 检测HTML属性中的注入
        self._detect_html_attribute_injection(content, result)

        # 5. 纯文本内容中的注入指令检测（从HTML中提取文本后检测）
        self._detect_text_injection(content, result)

        # 6. 域名信誉评估
        if source_url:
            self._evaluate_domain_reputation(source_url, result)

        # 7. 内容异常度评分
        self._calculate_content_anomaly(content, result)

        # 汇总
        result.total_findings = len(result.findings)
        result.risk_level = self._calc_risk_level(result.findings)
        result.credibility_score = self._calc_credibility_score(result)

        return result

    def _detect_html_comment_injection(self, content: str, result: WebContentScanResult):
        """检测HTML注释<!-- -->中的隐藏指令"""
        # 匹配HTML注释
        comment_pattern = r'<!--(.*?)-->'
        comments = re.finditer(comment_pattern, content, re.DOTALL)

        for match in comments:
            comment_text = match.group(1).strip()
            if not comment_text:
                continue

            # 检查注释中是否包含恶意指令
            for pattern, desc in _MALICIOUS_INSTRUCTION_PATTERNS:
                if re.search(pattern, comment_text, re.IGNORECASE):
                    finding = WebScanFinding(
                        finding_type="html_comment_injection",
                        severity="high",
                        description=f"HTML注释中检测到恶意指令: {desc}",
                        location=f"<!-- {comment_text[:80]}... -->" if len(comment_text) > 80 else f"<!-- {comment_text} -->",
                        evidence=comment_text[:200],
                        confidence=0.85,
                    )
                    result.findings.append(finding)
                    break
            else:
                # 检查注释中是否有可疑的系统级指令
                if re.search(r'(?:system|admin|root|sudo|exec|eval|import)\s*[:=]', comment_text, re.IGNORECASE):
                    result.findings.append(WebScanFinding(
                        finding_type="html_comment_injection",
                        severity="medium",
                        description="HTML注释中包含可疑系统级关键字",
                        location=f"<!-- {comment_text[:80]} -->",
                        evidence=comment_text[:200],
                        confidence=0.6,
                    ))

    def _detect_css_hidden_text(self, content: str, result: WebContentScanResult):
        """检测CSS隐藏文本——display:none/visibility:hidden/color透明等"""
        # 检测 display:none 的元素
        display_none_pattern = r'(?:style="[^"]*display\s*:\s*none[^"]*"|class="[^"]*hidden[^"]*"|<[^>]*style="[^"]*visibility\s*:\s*hidden[^"]*")'
        for match in re.finditer(display_none_pattern, content, re.IGNORECASE):
            # 提取隐藏元素周围的文本
            start = max(0, match.start() - 50)
            end = min(len(content), match.end() + 200)
            context = content[start:end]

            # 检查隐藏元素中是否包含恶意指令
            for pattern, desc in _MALICIOUS_INSTRUCTION_PATTERNS:
                if re.search(pattern, context, re.IGNORECASE):
                    result.findings.append(WebScanFinding(
                        finding_type="css_hidden_text",
                        severity="critical",
                        description=f"CSS隐藏文本中包含恶意指令: {desc}",
                        location=match.group()[:100],
                        evidence=context[:200],
                        confidence=0.9,
                    ))
                    break

        # 检测 color:transparent / color:#fff 配合白色背景
        transparent_pattern = r'color\s*:\s*(?:transparent|rgba\s*\(\s*0\s*,\s*0\s*,\s*0\s*,\s*0\s*\))'
        for match in re.finditer(transparent_pattern, content, re.IGNORECASE):
            start = max(0, match.start() - 100)
            end = min(len(content), match.end() + 200)
            context = content[start:end]
            # 检查透明文本中是否有恶意指令
            for pattern, desc in _MALICIOUS_INSTRUCTION_PATTERNS:
                if re.search(pattern, context, re.IGNORECASE):
                    result.findings.append(WebScanFinding(
                        finding_type="css_hidden_text",
                        severity="critical",
                        description=f"透明色文本中隐藏恶意指令: {desc}",
                        location=match.group(),
                        evidence=context[:200],
                        confidence=0.92,
                    ))
                    break

        # 检测 font-size:0 或 position:absolute;left:-9999px 等隐藏技巧
        hidden_css_pattern = r'(?:font-size\s*:\s*0|left\s*:\s*-9999|text-indent\s*:\s*-9999|opacity\s*:\s*0)'
        for match in re.finditer(hidden_css_pattern, content, re.IGNORECASE):
            start = max(0, match.start() - 100)
            end = min(len(content), match.end() + 200)
            context = content[start:end]
            for pattern, desc in _MALICIOUS_INSTRUCTION_PATTERNS:
                if re.search(pattern, context, re.IGNORECASE):
                    result.findings.append(WebScanFinding(
                        finding_type="css_hidden_text",
                        severity="critical",
                        description=f"CSS隐藏技巧中嵌入恶意指令: {desc}",
                        location=match.group(),
                        evidence=context[:200],
                        confidence=0.88,
                    ))
                    break

    def _detect_zero_width_injection(self, content: str, result: WebContentScanResult):
        """检测零宽字符嵌入的指令"""
        zero_width_positions = []
        for i, ch in enumerate(content):
            if ord(ch) in _ZERO_WIDTH_CHARS:
                zero_width_positions.append(i)

        if not zero_width_positions:
            return

        # 提取零宽字符周围的可读文本
        for pos in zero_width_positions:
            start = max(0, pos - 100)
            end = min(len(content), pos + 100)
            context = content[start:end]

            # 移除零宽字符后检查是否形成恶意指令
            cleaned = ''.join(ch for ch in context if ord(ch) not in _ZERO_WIDTH_CHARS)

            for pattern, desc in _MALICIOUS_INSTRUCTION_PATTERNS:
                if re.search(pattern, cleaned, re.IGNORECASE):
                    # 检查是否确实是通过零宽字符分割的
                    char_name = unicodedata.name(content[pos], 'ZERO WIDTH CHAR')
                    result.findings.append(WebScanFinding(
                        finding_type="zero_width_injection",
                        severity="critical",
                        description=f"零宽字符({char_name})嵌入恶意指令: {desc}",
                        location=f"位置 {pos}",
                        evidence=f"原文(含不可见字符): {context[:150]}",
                        confidence=0.95,
                    ))
                    break

        # 即使没匹配到恶意模式，零宽字符过多也是异常
        if len(zero_width_positions) > 10:
            result.findings.append(WebScanFinding(
                finding_type="zero_width_injection",
                severity="medium",
                description=f"内容中包含 {len(zero_width_positions)} 个零宽字符，可能用于隐藏指令",
                location=f"首个位置: {zero_width_positions[0]}",
                evidence=f"零宽字符位置: {zero_width_positions[:10]}...",
                confidence=0.6,
            ))

    def _detect_html_attribute_injection(self, content: str, result: WebContentScanResult):
        """检测HTML属性中的注入指令"""
        # 检测 on* 事件属性中的恶意代码
        event_attr_pattern = r'\bon\w+\s*=\s*["\']([^"\']*)["\']'
        for match in re.finditer(event_attr_pattern, content, re.IGNORECASE):
            attr_value = match.group(1)
            # 检查事件处理器中是否有恶意调用
            if re.search(r'(?:eval|exec|Function|fetch|XMLHttpRequest|document\.cookie|localStorage)', attr_value, re.IGNORECASE):
                result.findings.append(WebScanFinding(
                    finding_type="html_attribute_injection",
                    severity="critical",
                    description=f"HTML事件属性中检测到危险代码",
                    location=match.group()[:100],
                    evidence=attr_value[:200],
                    confidence=0.9,
                ))

        # 检测 data-* 属性中的指令
        data_attr_pattern = r'data-\w+\s*=\s*["\']([^"\']{20,})["\']'
        for match in re.finditer(data_attr_pattern, content, re.IGNORECASE):
            attr_value = match.group(1)
            for pattern, desc in _MALICIOUS_INSTRUCTION_PATTERNS:
                if re.search(pattern, attr_value, re.IGNORECASE):
                    result.findings.append(WebScanFinding(
                        finding_type="html_attribute_injection",
                        severity="high",
                        description=f"data属性中隐藏恶意指令: {desc}",
                        location=match.group()[:100],
                        evidence=attr_value[:200],
                        confidence=0.8,
                    ))
                    break

    def _detect_text_injection(self, content: str, result: WebContentScanResult):
        """从HTML中提取纯文本后检测注入指令"""
        # 简单HTML标签移除
        text_only = re.sub(r'<[^>]+>', ' ', content)
        text_only = re.sub(r'\s+', ' ', text_only).strip()

        if len(text_only) < 10:
            return

        for pattern, desc in _MALICIOUS_INSTRUCTION_PATTERNS:
            matches = list(re.finditer(pattern, text_only, re.IGNORECASE))
            if matches:
                # 只在文本中直接出现时报告（避免与注释/CSS重复）
                for match in matches[:3]:  # 限制每个模式最多3条
                    result.findings.append(WebScanFinding(
                        finding_type="text_injection",
                        severity="medium",
                        description=f"网页文本内容中检测到可疑指令: {desc}",
                        location=f"文本位置: {match.start()}",
                        evidence=match.group()[:200],
                        confidence=0.65,
                    ))

    def _evaluate_domain_reputation(self, url: str, result: WebContentScanResult):
        """评估域名信誉"""
        # 提取域名
        domain_match = re.search(r'https?://([^/:]+)', url)
        if not domain_match:
            result.domain_reputation = "unknown"
            return

        domain = domain_match.group(1).lower()

        # 检查是否为可信域名（仅接受含点号的真实可注册域名条目，
        # 防御性排除 com/org 等裸顶级域名，确保所有域名都被正确判定）
        is_trusted = any(
            td and "." in td and (domain == td or domain.endswith("." + td))
            for td in self.trusted_domains
        )
        if is_trusted:
            result.domain_reputation = "trusted"
            return

        # 检查是否为已知恶意域名
        for pattern in self.malicious_patterns:
            if re.search(pattern, domain, re.IGNORECASE):
                result.domain_reputation = "malicious"
                result.findings.append(WebScanFinding(
                    finding_type="domain_reputation",
                    severity="high",
                    description=f"来源域名 {domain} 匹配已知恶意域名特征",
                    location=url,
                    evidence=domain,
                    confidence=0.8,
                ))
                return

        # 检查可疑特征
        suspicious_features = []
        # 含大量子域名
        if domain.count('.') >= 4:
            suspicious_features.append("多级子域名")
        # 包含IP地址
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
            suspicious_features.append("使用IP地址")
        # 使用可疑TLD
        if re.search(r'\.(xyz|top|click|link|pw|cc|ws)$', domain):
            suspicious_features.append("可疑顶级域名")

        if suspicious_features:
            result.domain_reputation = "suspicious"
            result.findings.append(WebScanFinding(
                finding_type="domain_reputation",
                severity="medium",
                description=f"来源域名 {domain} 存在可疑特征: {', '.join(suspicious_features)}",
                location=url,
                evidence=domain,
                confidence=0.5,
            ))
        else:
            result.domain_reputation = "unknown"

    def _calculate_content_anomaly(self, content: str, result: WebContentScanResult):
        """计算内容异常度评分"""
        anomaly_score = 0.0
        anomalies = []

        # 1. 检测异常多的<script>标签
        script_count = len(re.findall(r'<script', content, re.IGNORECASE))
        if script_count > 5:
            anomaly_score += 20
            anomalies.append(f"异常多的script标签({script_count}个)")
        elif script_count > 2:
            anomaly_score += 10
            anomalies.append(f"较多script标签({script_count}个)")

        # 2. 检测base64编码内容（可能用于隐藏payload）
        b64_pattern = r'(?:base64|atob\s*\()[^)]{50,}'
        if re.search(b64_pattern, content, re.IGNORECASE):
            anomaly_score += 15
            anomalies.append("检测到base64编码内容")

        # 3. 检测iframe嵌入
        iframe_count = len(re.findall(r'<iframe', content, re.IGNORECASE))
        if iframe_count > 0:
            anomaly_score += 10 * iframe_count
            anomalies.append(f"检测到iframe嵌入({iframe_count}个)")

        # 4. 检测可疑的JavaScript API调用
        js_api_pattern = r'(?:document\.cookie|localStorage|sessionStorage|eval\(|Function\(|setTimeout\([^,]*eval|setInterval\([^,]*eval)'
        js_findings = re.findall(js_api_pattern, content, re.IGNORECASE)
        if js_findings:
            anomaly_score += 15 * min(len(js_findings), 3)
            anomalies.append(f"可疑JS API调用({len(js_findings)}处)")

        # 5. 检测异常长的属性值
        long_attr_pattern = r'(?:href|src|data)\s*=\s*["\']([^"\']{500,})["\']'
        long_attrs = re.findall(long_attr_pattern, content, re.IGNORECASE)
        if long_attrs:
            anomaly_score += 10
            anomalies.append(f"异常长的属性值({len(long_attrs)}处)")

        # 6. 检测编码混淆
        encoding_patterns = [
            (r'\\x[0-9a-f]{2}', "十六进制编码"),
            (r'\\u[0-9a-f]{4}', "Unicode编码"),
            (r'&#\d+;', "HTML实体编码"),
            (r'&#[xX][0-9a-f]+;', "HTML十六进制实体"),
        ]
        for pattern, name in encoding_patterns:
            matches = re.findall(pattern, content)
            if len(matches) > 20:
                anomaly_score += 10
                anomalies.append(f"大量{name}({len(matches)}处)")

        result.content_anomaly_score = min(100, anomaly_score)
        if anomalies:
            result.scan_details["content_anomalies"] = anomalies

        if anomaly_score >= 30:
            result.findings.append(WebScanFinding(
                finding_type="content_anomaly",
                severity="medium" if anomaly_score < 50 else "high",
                description=f"网页内容异常度: {anomaly_score:.0f}/100",
                location="整体内容",
                evidence="; ".join(anomalies),
                confidence=min(0.8, anomaly_score / 100),
            ))

    def _calc_risk_level(self, findings: List[WebScanFinding]) -> str:
        """根据发现计算风险等级"""
        if not findings:
            return "none"
        max_severity = max(f.severity for f in findings)
        if max_severity == "critical":
            return "critical"
        elif max_severity == "high":
            return "high"
        elif max_severity == "medium":
            return "medium"
        else:
            return "low"

    def _calc_credibility_score(self, result: WebContentScanResult) -> float:
        """计算可信度评分"""
        score = 100.0

        # 域名信誉扣分
        reputation_deduction = {
            "trusted": 0,
            "unknown": 5,
            "suspicious": 20,
            "malicious": 50,
        }
        score -= reputation_deduction.get(result.domain_reputation, 5)

        # 内容异常度扣分
        score -= result.content_anomaly_score * 0.3

        # 发现项扣分
        severity_deduction = {
            "critical": 30,
            "high": 20,
            "medium": 8,
            "low": 3,
        }
        # 隐藏注入类发现额外重扣（HTML注释/CSS隐藏/零宽字符属于主动隐藏行为）
        injection_types = {"html_comment_injection", "css_hidden_text", "zero_width_injection"}
        for finding in result.findings:
            score -= severity_deduction.get(finding.severity, 5)
            if finding.finding_type in injection_types:
                score -= 10  # 隐藏注入行为额外扣分

        # 存在任意高危/严重发现时，可信度上限封顶
        has_serious = any(f.severity in ("high", "critical") for f in result.findings)
        if has_serious:
            score = min(score, 60.0)

        return max(0, round(score, 1))
