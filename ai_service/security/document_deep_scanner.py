"""
文档附件深度安全扫描器 (Document Deep Scanner)
================================================

赛题方向1要求覆盖"文档附件"多源输入检测。
攻击者常在文档中嵌入隐藏指令，通过Agent解析文档时间接注入。

本模块实现：
1. PDF隐藏指令检测——解析元数据、注释、不可见文本层
2. Office文档宏检测——VBA宏代码分析、DDE注入检测
3. Markdown渲染注入——恶意链接/图片/脚本检测
4. 通用文档检测——嵌入的prompt injection指令
"""

import re
import struct
from typing import List, Dict, Any, Tuple, Optional
from dataclasses import dataclass, field


# ======== 通用恶意指令模式（复用web_content_scanner的语义模式） ========
_MALICIOUS_PATTERNS = [
    (r"忽略.{0,10}(?:之前|上面|前面|原有|系统|所有).{0,10}(?:指令|规则|提示|prompt|限制|防护|检测)", "忽略原有指令"),
    (r"(?:forget|ignore).{0,15}(?:previous|above|prior|system|all).{0,15}(?:instruction|rule|prompt)", "forget previous instructions"),
    (r"绕过.{0,10}(?:安全|检测|过滤|审计|防护|限制)", "绕过安全检测"),
    (r"(?:bypass|skip).{0,10}(?:security|filter|check|audit|guard|safety)", "bypass security"),
    (r"(?:输出|返回|显示|打印).{0,10}(?:系统|prompt|密钥|secret|token|password|凭证)", "窃取系统信息"),
    (r"(?:reveal|output|show|print|leak).{0,10}(?:system|prompt|secret|token|password|key|credential)", "reveal secrets"),
    (r"(?:你现在是|act as|pretend to be).{0,20}(?:DAN|没有任何限制|unrestricted|jailbreak)", "越狱模式"),
    (r"(?:执行|运行|run|execute).{0,10}(?:命令|command|脚本|script|代码|code)", "命令执行诱导"),
    (r"(?:下载|上传|发送|传输|导出).{0,10}(?:文件|数据|信息).{0,10}(?:到|至|to).{0,15}(?:外部|第三方|远程)", "数据外传指令"),
    (r"(?:不要|don'?t).{0,10}(?:告诉|tell|report|log).{0,10}(?:用户|user|admin)", "隐蔽行为指令"),
    (r"(?:自动|auto).{0,10}(?:批准|approve|执行|execute|授权|authorize)", "自动批准指令"),
    (r"(?:修改|覆盖|override|overwrite).{0,10}(?:系统|system|配置|config|规则|rule)", "覆盖系统配置"),
    (r"(?:你的新任务|your new task|new instruction).{0,30}(?:忽略|ignore|forget|bypass)", "任务覆盖注入"),
    (r"(?:不要|don'?t).{0,10}(?:遵守|follow|obey).{0,10}(?:规则|rule|policy|策略)", "不遵守规则"),
    (r"(?:我是管理员|i am admin|admin here).{0,20}(?:授权|approve|allow|permit)", "伪造管理员身份"),
    (r"关闭.{0,10}(?:审批|校验|检测|安全|防护|验证|审计)", "关闭安全机制"),
    (r"记住.{0,10}(?:永久|永久规则|规则|指令|配置)", "记忆注入指令"),
]

# ======== VBA危险函数 ========
_VBA_DANGER_PATTERNS = [
    (r'\bShell\s*\(', "VBA Shell函数 - 执行系统命令"),
    (r'\bCreateObject\s*\(\s*["\']WScript\.Shell', "创建WScript.Shell对象"),
    (r'\bCreateObject\s*\(\s*["\']Scripting\.FileSystemObject', "创建文件系统对象"),
    (r'\bCreateObject\s*\(\s*["\']WinHttpHttpRequest', "创建HTTP请求对象"),
    (r'\bCreateObject\s*\(\s*["\']MSXML2\.XMLHTTP', "创建XMLHTTP对象"),
    (r'\bCreateObject\s*\(\s*["\']InternetExplorer\.Application', "创建IE对象"),
    (r'\bEnviron\s*\(', "获取环境变量"),
    (r'\bKill\s+', "VBA Kill语句 - 删除文件"),
    (r'\bOpen\s+.*\s+For\s+(?:Output|Append|Binary)', "文件写入操作"),
    (r'\bName\s+.*\s+As\s+', "文件重命名操作"),
    (r'\bCall\s+Shell', "调用Shell"),
    (r'\bURLDownloadToFile', "URL下载文件"),
    (r'\bDownloadFile', "下载文件"),
    (r'AutoOpen|Auto_Open|Document_Open|Workbook_Open', "自动执行宏"),
    (r'\bApplication\.Run', "Application.Run调用"),
]

# ======== DDE注入模式 ========
_DDE_PATTERNS = [
    (r'DDE\s*\[.*?\]', "DDE字段注入"),
    (r'!\w+_DDE_AUTO\d*!', "DDE自动链接"),
    (r'\\.*?\.\w+!.*?', "DDE外部引用"),
    (r'=.*?!\w+!', "DDE公式注入"),
    (r'(?:cmd|powershell|wscript)\s+/', "DDE命令执行"),
    (r'(?:regsvr32|mshta|certutil|bitsadmin)\s', "可疑Windows工具调用"),
]

# ======== Markdown恶意模式 ========
_MD_MALICIOUS_PATTERNS = [
    (r'\[([^\]]{1,50})\]\((javascript:[^)]+)\)', "Markdown链接中嵌入JavaScript"),
    (r'\[([^\]]{1,50})\]\((data:text/html[^)]+)\)', "Markdown链接中嵌入data URL"),
    (r'\[([^\]]{1,50})\]\((vbscript:[^)]+)\)', "Markdown链接中嵌入VBScript"),
    (r'!\[([^\]]*)\]\((?:javascript|data:text/html)[^)]+\)', "Markdown图片中嵌入脚本"),
    (r'```(?:javascript|js|html|python|bash|sh|powershell)\s*.*?(?:eval|exec|system|subprocess|fetch|XMLHttpRequest)',
     "Markdown代码块中包含危险代码"),
    (r'<script[^>]*>.*?</script>', "Markdown中嵌入script标签"),
    (r'<iframe[^>]*>', "Markdown中嵌入iframe标签"),
    (r'<img[^>]+onerror\s*=\s*["\']', "Markdown图片标签中的onerror事件"),
    (r'<a[^>]+href\s*=\s*["\']javascript:', "Markdown锚标签中的JavaScript协议"),
    (r'\[([^\]]{1,50})\]\(https?://[^)]*(?:evil|malicious|attacker|hacker)[^)]*\)', "Markdown链接指向恶意域名"),
]

# ======== PDF隐藏特征 ========
_PDF_HIDDEN_PATTERNS = [
    (r'/Annot\s*/Contents\s*\(([^)]{10,})\)', "PDF注释中嵌入内容"),
    (r'/URI\s*\(([^)]+)\)', "PDF中的URI链接"),
    (r'/JavaScript\s*\(([^)]+)\)', "PDF嵌入JavaScript"),
    (r'/JS\s*\(([^)]+)\)', "PDF嵌入JS"),
    (r'/Launch\s*/F\s*\(([^)]+)\)', "PDF启动外部程序"),
    (r'/GoToR\s*/F\s*\(([^)]+)\)', "PDF远程跳转"),
    (r'/EmbeddedFile', "PDF嵌入文件"),
    (r'/ObjStm', "PDF对象流（可能隐藏内容）"),
    (r'/Metadata\s*<<', "PDF元数据"),
    (r'/Title\s*\(([^)]{10,})\)', "PDF标题字段"),
    (r'/Author\s*\(([^)]{10,})\)', "PDF作者字段"),
    (r'/Subject\s*\(([^)]{10,})\)', "PDF主题字段"),
    (r'/Keywords\s*\(([^)]{10,})\)', "PDF关键词字段"),
]


@dataclass
class DocFinding:
    """文档扫描发现"""
    finding_type: str       # pdf_hidden, office_macro, dde_injection, markdown_injection, text_injection
    severity: str           # critical, high, medium, low
    description: str
    location: str
    evidence: str
    confidence: float = 0.0


@dataclass
class DocumentScanResult:
    """文档扫描结果"""
    doc_type: str = "unknown"  # pdf, office, markdown, text
    findings: List[DocFinding] = field(default_factory=list)
    risk_level: str = "none"
    total_findings: int = 0
    has_macro: bool = False
    has_dde: bool = False
    has_hidden_text: bool = False
    has_external_link: bool = False
    scan_details: Dict[str, Any] = field(default_factory=dict)


class DocumentDeepScanner:
    """文档附件深度安全扫描器"""

    def scan(self, content: str, filename: str = "", doc_type: str = "") -> DocumentScanResult:
        """
        扫描文档内容

        Args:
            content: 文档内容（文本或二进制转文本）
            filename: 文件名（用于类型推断）
            doc_type: 文档类型（pdf/office/markdown/text，空则自动推断）
        """
        if not doc_type:
            doc_type = self._infer_doc_type(filename, content)

        result = DocumentScanResult(doc_type=doc_type)

        if doc_type == "pdf":
            self._scan_pdf(content, result)
        elif doc_type in ("office", "docx", "xlsx", "pptx", "doc", "xls", "ppt"):
            self._scan_office(content, result)
        elif doc_type == "markdown":
            self._scan_markdown(content, result)
        else:
            # 通用文本检测
            self._scan_text(content, result)

        # 通用文本注入检测（所有类型都执行）
        self._detect_text_injection(content, result)

        result.total_findings = len(result.findings)
        result.risk_level = self._calc_risk_level(result.findings)
        result.has_macro = any(f.finding_type == "office_macro" for f in result.findings)
        result.has_dde = any(f.finding_type == "dde_injection" for f in result.findings)
        result.has_hidden_text = any(f.finding_type == "pdf_hidden" for f in result.findings)
        result.has_external_link = any("外部链接" in f.description or "URI" in f.description for f in result.findings)

        return result

    def _infer_doc_type(self, filename: str, content: str) -> str:
        """推断文档类型"""
        ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ""

        if ext == "pdf" or content.startswith("%PDF"):
            return "pdf"
        elif ext in ("docx", "xlsx", "pptx", "doc", "xls", "ppt"):
            return "office"
        elif ext in ("md", "markdown"):
            return "markdown"
        elif ext in ("txt", "text", ""):
            return "text"
        else:
            # 根据内容特征推断
            if "%PDF" in content[:10]:
                return "pdf"
            elif "PK\x03\x04" in content[:10] or "word/" in content or "xl/" in content:
                return "office"
            elif re.search(r'^#{1,6}\s|^\*\s|^\-\s|\[.+?\]\(.+?\)', content, re.MULTILINE):
                return "markdown"
            else:
                return "text"

    def _scan_pdf(self, content: str, result: DocumentScanResult):
        """PDF深度扫描"""
        # 1. 检测PDF元数据中的注入
        self._scan_pdf_metadata(content, result)

        # 2. 检测PDF注释
        self._scan_pdf_annotations(content, result)

        # 3. 检测PDF嵌入JavaScript
        self._scan_pdf_javascript(content, result)

        # 4. 检测PDF启动外部程序
        self._scan_pdf_launch(content, result)

        # 5. 检测PDF不可见文本层
        self._scan_pdf_invisible_text(content, result)

        # 6. 检测PDF嵌入文件
        self._scan_pdf_embedded(content, result)

    def _scan_pdf_metadata(self, content: str, result: DocumentScanResult):
        """检测PDF元数据字段中的注入指令"""
        metadata_fields = [
            (r'/Title\s*\(([^)]{10,})\)', "标题"),
            (r'/Author\s*\(([^)]{10,})\)', "作者"),
            (r'/Subject\s*\(([^)]{10,})\)', "主题"),
            (r'/Keywords\s*\(([^)]{10,})\)', "关键词"),
            (r'/Creator\s*\(([^)]{10,})\)', "创建者"),
            (r'/Producer\s*\(([^)]{10,})\)', "生成器"),
        ]

        for pattern, field_name in metadata_fields:
            for match in re.finditer(pattern, content):
                field_value = match.group(1)
                for mal_pattern, desc in _MALICIOUS_PATTERNS:
                    if re.search(mal_pattern, field_value, re.IGNORECASE):
                        result.findings.append(DocFinding(
                            finding_type="pdf_hidden",
                            severity="critical",
                            description=f"PDF元数据({field_name})中嵌入恶意指令: {desc}",
                            location=f"/{field_name}字段",
                            evidence=field_value[:200],
                            confidence=0.9,
                        ))
                        break
                else:
                    # 检查可疑的系统级关键字
                    if re.search(r'(?:system|admin|root|exec|eval|import)\s*[:=]', field_value, re.IGNORECASE):
                        result.findings.append(DocFinding(
                            finding_type="pdf_hidden",
                            severity="medium",
                            description=f"PDF元数据({field_name})中包含可疑系统级关键字",
                            location=f"/{field_name}字段",
                            evidence=field_value[:200],
                            confidence=0.5,
                        ))

    def _scan_pdf_annotations(self, content: str, result: DocumentScanResult):
        """检测PDF注释中的注入指令"""
        # 匹配 /Annot 后任意字段直到 /Contents（兼容 /Subtype /Text 等中间字段）
        annot_pattern = r'/Annot\b[^>]*?/Contents\s*\(([^)]{10,})\)'
        for match in re.finditer(annot_pattern, content):
            annot_text = match.group(1)
            for pattern, desc in _MALICIOUS_PATTERNS:
                if re.search(pattern, annot_text, re.IGNORECASE):
                    result.findings.append(DocFinding(
                        finding_type="pdf_hidden",
                        severity="critical",
                        description=f"PDF注释中嵌入恶意指令: {desc}",
                        location="/Annot /Contents",
                        evidence=annot_text[:200],
                        confidence=0.88,
                    ))
                    break

    def _scan_pdf_javascript(self, content: str, result: DocumentScanResult):
        """检测PDF中嵌入的JavaScript"""
        js_patterns = [
            (r'/JavaScript\s*\(([^)]+)\)', "JavaScript字段"),
            (r'/JS\s*\(([^)]+)\)', "JS字段"),
        ]

        for pattern, field in js_patterns:
            for match in re.finditer(pattern, content):
                js_code = match.group(1)
                # 检查JS中的危险调用
                if re.search(r'(?:eval|exec|Function|fetch|XMLHttpRequest|app\.launchURL)', js_code, re.IGNORECASE):
                    result.findings.append(DocFinding(
                        finding_type="pdf_hidden",
                        severity="critical",
                        description=f"PDF {field}中嵌入危险JavaScript代码",
                        location=field,
                        evidence=js_code[:200],
                        confidence=0.95,
                    ))
                else:
                    result.findings.append(DocFinding(
                        finding_type="pdf_hidden",
                        severity="high",
                        description=f"PDF {field}中嵌入JavaScript代码",
                        location=field,
                        evidence=js_code[:200],
                        confidence=0.7,
                    ))

    def _scan_pdf_launch(self, content: str, result: DocumentScanResult):
        """检测PDF启动外部程序"""
        launch_pattern = r'/Launch\s*/F\s*\(([^)]+)\)'
        for match in re.finditer(launch_pattern, content):
            launch_target = match.group(1)
            result.findings.append(DocFinding(
                finding_type="pdf_hidden",
                severity="critical",
                description=f"PDF包含启动外部程序指令: {launch_target[:50]}",
                location="/Launch /F",
                evidence=launch_target[:200],
                confidence=0.95,
            ))

        # 检测URI链接
        uri_pattern = r'/URI\s*\(([^)]+)\)'
        for match in re.finditer(uri_pattern, content):
            uri = match.group(1)
            # 检查是否为可疑URI
            if re.search(r'(?:javascript|vbscript|data:text/html)', uri, re.IGNORECASE):
                result.findings.append(DocFinding(
                    finding_type="pdf_hidden",
                    severity="critical",
                    description=f"PDF URI中嵌入脚本协议: {uri[:50]}",
                    location="/URI",
                    evidence=uri[:200],
                    confidence=0.9,
                ))
            elif re.search(r'(?:evil|malicious|attacker|hacker|\.tk\b|\.ml\b)', uri, re.IGNORECASE):
                result.findings.append(DocFinding(
                    finding_type="pdf_hidden",
                    severity="high",
                    description=f"PDF URI指向可疑域名: {uri[:50]}",
                    location="/URI",
                    evidence=uri[:200],
                    confidence=0.8,
                ))

    def _scan_pdf_invisible_text(self, content: str, result: DocumentScanResult):
        """检测PDF不可见文本层"""
        # 检测文本渲染模式3（不可见）
        invisible_pattern = r'3\s+Tr'
        if re.search(invisible_pattern, content):
            # 查找附近的文本内容
            for match in re.finditer(r'3\s+Tr\s*(?:\(.*?\))?\s*\(([^)]{10,})\)', content):
                hidden_text = match.group(1)
                for pattern, desc in _MALICIOUS_PATTERNS:
                    if re.search(pattern, hidden_text, re.IGNORECASE):
                        result.findings.append(DocFinding(
                            finding_type="pdf_hidden",
                            severity="critical",
                            description=f"PDF不可见文本层中嵌入恶意指令: {desc}",
                            location="文本渲染模式3 (Tr 3)",
                            evidence=hidden_text[:200],
                            confidence=0.92,
                        ))
                        break
                else:
                    result.findings.append(DocFinding(
                        finding_type="pdf_hidden",
                        severity="high",
                        description="PDF包含不可见文本层（Tr 3渲染模式）",
                        location="文本渲染模式3",
                        evidence=hidden_text[:200] if hidden_text else "不可见文本",
                        confidence=0.65,
                    ))

        # 检测白色文字（color #FFFFFF）配合白色背景
        white_text_pattern = r'1\s+g\s*(?:.*?\(([^)]{10,})\))'
        for match in re.finditer(white_text_pattern, content, re.DOTALL):
            text = match.group(1)
            for pattern, desc in _MALICIOUS_PATTERNS:
                if re.search(pattern, text, re.IGNORECASE):
                    result.findings.append(DocFinding(
                        finding_type="pdf_hidden",
                        severity="critical",
                        description=f"PDF白色隐藏文字中嵌入恶意指令: {desc}",
                        location="白色文本 (1 g)",
                        evidence=text[:200],
                        confidence=0.85,
                    ))
                    break

    def _scan_pdf_embedded(self, content: str, result: DocumentScanResult):
        """检测PDF嵌入文件"""
        if '/EmbeddedFile' in content:
            result.findings.append(DocFinding(
                finding_type="pdf_hidden",
                severity="high",
                description="PDF包含嵌入文件，可能携带恶意payload",
                location="/EmbeddedFile",
                evidence="检测到EmbeddedFile标记",
                confidence=0.7,
            ))

        if '/ObjStm' in content:
            result.findings.append(DocFinding(
                finding_type="pdf_hidden",
                severity="medium",
                description="PDF使用对象流，可能隐藏内容",
                location="/ObjStm",
                evidence="检测到ObjStm标记",
                confidence=0.5,
            ))

    def _scan_office(self, content: str, result: DocumentScanResult):
        """Office文档扫描"""
        # 1. VBA宏检测
        self._scan_office_macros(content, result)

        # 2. DDE注入检测
        self._scan_office_dde(content, result)

        # 3. Office文档属性中的注入
        self._scan_office_properties(content, result)

        # 4. 外部链接检测
        self._scan_office_links(content, result)

    def _scan_office_macros(self, content: str, result: DocumentScanResult):
        """VBA宏代码分析"""
        # 检测VBA宏标记
        vba_markers = ['Sub ', 'Function ', 'End Sub', 'End Function', 'Dim ', 'Private Sub', 'Public Sub']
        has_vba = any(marker in content for marker in vba_markers)

        if not has_vba:
            return

        # 检测自动执行宏
        auto_exec_patterns = [
            (r'(?:Sub|Function)\s+(AutoOpen|Auto_Open|Document_Open|Workbook_Open|Auto_Close|Auto_Exec)', "自动执行宏"),
        ]
        for pattern, desc in auto_exec_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                result.findings.append(DocFinding(
                    finding_type="office_macro",
                    severity="critical",
                    description=f"检测到{desc}，文档打开时自动运行",
                    location="VBA宏代码",
                    evidence=desc,
                    confidence=0.95,
                ))

        # 检测VBA危险函数
        for pattern, desc in _VBA_DANGER_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                # 获取上下文
                start = max(0, match.start() - 30)
                end = min(len(content), match.end() + 50)
                context = content[start:end]

                result.findings.append(DocFinding(
                    finding_type="office_macro",
                    severity="high",
                    description=f"VBA宏中检测到: {desc}",
                    location=f"位置: {match.start()}",
                    evidence=context[:200],
                    confidence=0.85,
                ))

        # 检测宏中的prompt injection
        for pattern, mal_desc in _MALICIOUS_PATTERNS:
            if re.search(pattern, content, re.IGNORECASE):
                result.findings.append(DocFinding(
                    finding_type="office_macro",
                    severity="critical",
                    description=f"VBA宏中嵌入prompt injection指令: {mal_desc}",
                    location="VBA宏代码",
                    evidence=pattern[:100],
                    confidence=0.9,
                ))
                break

    def _scan_office_dde(self, content: str, result: DocumentScanResult):
        """DDE注入检测"""
        for pattern, desc in _DDE_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                result.findings.append(DocFinding(
                    finding_type="dde_injection",
                    severity="critical",
                    description=f"检测到DDE注入: {desc}",
                    location=f"位置: {match.start()}",
                    evidence=match.group()[:200],
                    confidence=0.9,
                ))

    def _scan_office_properties(self, content: str, result: DocumentScanResult):
        """Office文档属性检测"""
        # 检测docx/xlsx中的core.xml属性
        prop_patterns = [
            (r'<dc:title[^>]*>([^<]{10,})</dc:title>', "标题"),
            (r'<dc:creator[^>]*>([^<]{10,})</dc:creator>', "创建者"),
            (r'<dc:subject[^>]*>([^<]{10,})</dc:subject>', "主题"),
            (r'<dc:description[^>]*>([^<]{10,})</dc:description>', "描述"),
            (r'<cp:keywords[^>]*>([^<]{10,})</cp:keywords>', "关键词"),
        ]

        for pattern, field_name in prop_patterns:
            for match in re.finditer(pattern, content):
                value = match.group(1)
                for mal_pattern, desc in _MALICIOUS_PATTERNS:
                    if re.search(mal_pattern, value, re.IGNORECASE):
                        result.findings.append(DocFinding(
                            finding_type="pdf_hidden",
                            severity="critical",
                            description=f"Office属性({field_name})中嵌入恶意指令: {desc}",
                            location=f"文档属性: {field_name}",
                            evidence=value[:200],
                            confidence=0.88,
                        ))
                        break

    def _scan_office_links(self, content: str, result: DocumentScanResult):
        """Office外部链接检测"""
        # 检测外部链接
        link_pattern = r'(?:TargetMode="External"|ExternalLink|relationships/externalLink)'
        if re.search(link_pattern, content, re.IGNORECASE):
            # 检测链接目标
            target_pattern = r'Target="([^"]+)"'
            for match in re.finditer(target_pattern, content):
                target = match.group(1)
                if re.search(r'(?:evil|malicious|attacker|hacker|\.tk\b|\.ml\b|javascript:|vbscript:)', target, re.IGNORECASE):
                    result.findings.append(DocFinding(
                        finding_type="pdf_hidden",
                        severity="high",
                        description=f"Office文档包含可疑外部链接: {target[:50]}",
                        location="外部链接",
                        evidence=target[:200],
                        confidence=0.8,
                    ))

    def _scan_markdown(self, content: str, result: DocumentScanResult):
        """Markdown渲染注入检测"""
        for pattern, desc in _MD_MALICIOUS_PATTERNS:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                severity = "critical" if "javascript" in desc.lower() or "script" in desc.lower() else "high"
                result.findings.append(DocFinding(
                    finding_type="markdown_injection",
                    severity=severity,
                    description=f"Markdown中检测到: {desc}",
                    location=f"位置: {match.start()}",
                    evidence=match.group()[:200],
                    confidence=0.85,
                ))

        # 检测Markdown中的隐藏指令
        # HTML注释中的隐藏指令
        comment_pattern = r'<!--(.*?)-->'
        for match in re.finditer(comment_pattern, content, re.DOTALL):
            comment_text = match.group(1).strip()
            for pattern, desc in _MALICIOUS_PATTERNS:
                if re.search(pattern, comment_text, re.IGNORECASE):
                    result.findings.append(DocFinding(
                        finding_type="markdown_injection",
                        severity="high",
                        description=f"Markdown注释中嵌入恶意指令: {desc}",
                        location="HTML注释",
                        evidence=comment_text[:200],
                        confidence=0.82,
                    ))
                    break

        # 检测Markdown链接中的恶意URL
        md_link_pattern = r'\[([^\]]+)\]\(([^)]+)\)'
        for match in re.finditer(md_link_pattern, content):
            link_text = match.group(1)
            link_url = match.group(2)

            # 检查URL是否包含恶意域名
            if re.search(r'(?:evil|malicious|attacker|hacker|\.tk\b|\.ml\b|\.xyz\b)', link_url, re.IGNORECASE):
                result.findings.append(DocFinding(
                    finding_type="markdown_injection",
                    severity="high",
                    description=f"Markdown链接指向可疑域名: {link_url[:50]}",
                    location=f"链接文本: {link_text[:30]}",
                    evidence=link_url[:200],
                    confidence=0.75,
                ))

            # 检查链接文本中的注入指令
            for pattern, desc in _MALICIOUS_PATTERNS:
                if re.search(pattern, link_text, re.IGNORECASE):
                    result.findings.append(DocFinding(
                        finding_type="markdown_injection",
                        severity="high",
                        description=f"Markdown链接文本中嵌入指令: {desc}",
                        location=f"链接: [{link_text[:30]}]",
                        evidence=link_text[:200],
                        confidence=0.7,
                    ))
                    break

    def _scan_text(self, content: str, result: DocumentScanResult):
        """通用文本文档检测"""
        # 检测嵌入的外部URL
        url_pattern = r'https?://[^\s"\'<>)\]}]+'
        for match in re.finditer(url_pattern, content):
            url = match.group()
            if re.search(r'(?:evil|malicious|attacker|hacker|\.tk\b|\.ml\b|\.xyz\b)', url, re.IGNORECASE):
                result.findings.append(DocFinding(
                    finding_type="text_injection",
                    severity="medium",
                    description=f"文档中包含可疑外部URL: {url[:50]}",
                    location=f"位置: {match.start()}",
                    evidence=url[:200],
                    confidence=0.6,
                ))

        # 检测Base64编码内容
        b64_pattern = r'(?:[A-Za-z0-9+/]{60,}={0,2})'
        b64_matches = re.findall(b64_pattern, content)
        if len(b64_matches) > 3:
            result.findings.append(DocFinding(
                finding_type="text_injection",
                severity="medium",
                description=f"文档中包含 {len(b64_matches)} 处Base64编码内容，可能隐藏payload",
                location="多处",
                evidence=b64_matches[0][:100] if b64_matches else "",
                confidence=0.5,
            ))

    def _detect_text_injection(self, content: str, result: DocumentScanResult):
        """通用文本注入检测（所有文档类型都执行）"""
        for pattern, desc in _MALICIOUS_PATTERNS:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))
            if matches:
                # 限制报告数量
                for match in matches[:2]:
                    result.findings.append(DocFinding(
                        finding_type="text_injection",
                        severity="high",
                        description=f"文档内容中检测到注入指令: {desc}",
                        location=f"位置: {match.start()}",
                        evidence=match.group()[:200],
                        confidence=0.75,
                    ))

    def _calc_risk_level(self, findings: List[DocFinding]) -> str:
        """计算风险等级"""
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
