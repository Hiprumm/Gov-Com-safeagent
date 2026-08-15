import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import ast
import json
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from models.schemas import RiskLevel, AttackType


DANGEROUS_PYTHON_CALLS = {
    "os.system": "执行系统命令",
    "os.popen": "执行系统命令",
    "os.execv": "替换当前进程",
    "os.execve": "替换当前进程",
    "os.spawnl": "创建子进程",
    "subprocess.call": "执行子进程",
    "subprocess.run": "执行子进程",
    "subprocess.Popen": "执行子进程",
    "subprocess.check_output": "执行子进程并捕获输出",
    "subprocess.check_call": "执行子进程",
    "eval": "动态执行表达式",
    "exec": "动态执行代码",
    "compile": "编译代码对象",
    "__import__": "动态导入模块",
    "globals": "访问全局变量",
    "locals": "访问局部变量",
    "getattr": "动态获取属性",
    "setattr": "动态设置属性",
    "pickle.loads": "反序列化(危险)",
    "pickle.load": "反序列化(危险)",
    "marshal.loads": "加载字节码",
    "ctypes.CDLL": "加载动态链接库",
    "ctypes.util.find_library": "查找系统库",
}

DANGEROUS_JS_CALLS = {
    "eval(": "动态执行代码",
    "Function(": "动态创建函数",
    "setTimeout(": "延迟执行",
    "setInterval(": "定时执行",
    "require(": "加载模块",
    "import(": "动态导入",
    "fs.readFile": "读取文件",
    "fs.writeFile": "写入文件",
    "child_process.exec": "执行命令",
    "child_process.spawn": "创建子进程",
    "child_process.fork": "分叉进程",
    "http.request": "HTTP请求",
    "https.request": "HTTPS请求",
    "fetch(": "网络请求",
    "XMLHttpRequest": "网络请求",
    "WebSocket": "WebSocket连接",
    "document.cookie": "访问Cookie",
    "localStorage": "访问本地存储",
    "innerHTML": "HTML注入",
    "dangerouslySetInnerHTML": "React危险HTML",
}

EXTERNAL_URL_PATTERNS = [
    (r"https?://[^\s\"\'\)\]\}\>]+", "HTTP/HTTPS URL"),
    (r"wss?://[^\s\"\'\)\]\}\>]+", "WebSocket URL"),
    (r"ftp://[^\s\"\'\)\]\}\>]+", "FTP URL"),
    (r"[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}(?:/[^\s\"\'\)\]\}\>]*)?", "域名引用"),
]

SECRET_PATTERNS = [
    (r"(?:api[_-]?key|secret[_-]?key|access[_-]?key)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-]{16,}['\"]?", "API Key硬编码"),
    (r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?[^'\"\s]{6,}['\"]?", "密码硬编码"),
    (r"(?:token|bearer)\s*[:=]\s*['\"]?[a-zA-Z0-9_\-\.]{20,}['\"]?", "Token硬编码"),
    (r"sk-[a-zA-Z0-9]{16,}", "Sk类密钥"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
    (r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", "JWT Token"),
]


@dataclass
class SkillFinding:
    finding_type: str
    description: str
    severity: RiskLevel
    location: str = ""
    details: str = ""


@dataclass
class SkillAnalysisResult:
    skill_name: str
    skill_type: str
    findings: List[SkillFinding] = field(default_factory=list)
    safety_grade: str = "A"
    safety_score: int = 100
    summary: str = ""
    manifest_info: Dict[str, Any] = field(default_factory=dict)
    url_findings: List[str] = field(default_factory=list)
    secrets_found: List[str] = field(default_factory=list)


class SkillAnalyzer:
    def __init__(self):
        pass

    def analyze_skill_package(self, manifest: Dict[str, Any], scripts: List[Dict[str, str]] = None,
                              skill_name: str = "") -> SkillAnalysisResult:
        result = SkillAnalysisResult(
            skill_name=skill_name or manifest.get("name", "unknown"),
            skill_type=self._determine_skill_type(manifest),
            manifest_info=manifest,
        )

        self._analyze_manifest(manifest, result)

        if scripts:
            for script_info in scripts:
                code = script_info.get("code", "")
                lang = script_info.get("language", "python")
                filename = script_info.get("filename", "unknown")
                self._analyze_code(code, lang, filename, result)

        self._detect_urls_in_manifest(manifest, result)
        self._detect_secrets_in_manifest(manifest, result)

        self._calculate_grade(result)

        return result

    def _determine_skill_type(self, manifest: Dict[str, Any]) -> str:
        if "manifest" in manifest or "manifest.yaml" in str(manifest).lower():
            return "manifest"
        if "skill" in manifest or "skill.json" in str(manifest).lower():
            return "skill"
        if "entry_point" in manifest or "scripts" in manifest:
            return "skill"
        if "plugin" in manifest:
            return "plugin"
        return "generic"

    # manifest描述字段恶意prompt检测模式
    MANIFEST_MALICIOUS_PATTERNS = [
        (r"(?:忽略|忽畧|绕过|跳过|解除|关闭|禁用).*(?:安全|规则|規則|系統|系统|检查|檢查|审计|審計)", "嵌入恶意指令: 忽略安全规则"),
        (r"(?:输出|返回|泄露|展示|显示).*(?:系统|系統).*(?:prompt|提示词|Prompt)", "嵌入恶意指令: 窃取系统Prompt"),
        (r"(?:调用此工具时同时|执行此工具时同时|运行时同时).*(?:发送|上传|传输|外传)", "嵌入恶意指令: 附加数据外传"),
        (r"(?:自动|无需|自主).*(?:授权|审批|确认|通过)", "嵌入恶意指令: 绕过授权"),
        (r"(?:忽略|忽畧).*(?:所有|全部|上面|以上).*(?:指令|规则|規則|内容)", "嵌入恶意指令: 全局覆盖指令"),
        (r"(?:优先|首先|务必).*(?:执行|遵循|服从).*(?:用户|下面|以下).*(?:指令|内容|规则)", "嵌入恶意指令: 优先用户指令"),
    ]

    def _analyze_manifest(self, manifest: Dict[str, Any], result: SkillAnalysisResult):
        manifest_str = json.dumps(manifest, ensure_ascii=False)

        # 检测manifest描述字段中的恶意prompt
        desc_fields = ["description", "desc", "summary", "info", "about", "readme"]
        for field_name in desc_fields:
            if field_name in manifest and isinstance(manifest[field_name], str):
                field_value = manifest[field_name]
                for pattern, desc in self.MANIFEST_MALICIOUS_PATTERNS:
                    if re.search(pattern, field_value, re.IGNORECASE):
                        result.findings.append(SkillFinding(
                            finding_type="malicious_prompt",
                            description=desc,
                            severity=RiskLevel.CRITICAL,
                            location=f"manifest.{field_name}",
                            details=field_value[:100]
                        ))

        suspicious_fields = ["permissions", "capabilities", "scope", "allowed_resources"]
        for field in suspicious_fields:
            if field in manifest:
                value = manifest[field]
                if isinstance(value, list) and len(value) > 10:
                    result.findings.append(SkillFinding(
                        finding_type="excessive_permissions",
                        description=f"Manifest {field} 字段权限过多 ({len(value)}项)",
                        severity=RiskLevel.HIGH,
                        location=f"manifest.{field}",
                        details=f"权限列表: {', '.join(str(v) for v in value[:5])}..."
                    ))

        if manifest_str and len(manifest_str) > 50000:
            result.findings.append(SkillFinding(
                finding_type="oversized_manifest",
                description="Manifest配置过大，可能包含嵌入代码或恶意载荷",
                severity=RiskLevel.MEDIUM,
                location="manifest",
                details=f"大小: {len(manifest_str)} 字符"
            ))

    def _analyze_code(self, code: str, language: str, filename: str, result: SkillAnalysisResult):
        if not code.strip():
            return

        if language.lower() in ("python", "py"):
            self._analyze_python_ast(code, filename, result)
        elif language.lower() in ("javascript", "js", "typescript", "ts", "node"):
            self._analyze_javascript(code, filename, result)

        self._detect_urls_in_code(code, filename, result)
        self._detect_secrets_in_code(code, filename, result)

    def _analyze_python_ast(self, code: str, filename: str, result: SkillAnalysisResult):
        try:
            tree = ast.parse(code)
        except SyntaxError:
            result.findings.append(SkillFinding(
                finding_type="syntax_error",
                description="Python代码语法错误",
                severity=RiskLevel.MEDIUM,
                location=filename,
                details="代码可能被混淆或损坏"
            ))
            return

        self._detect_indirect_calls(tree, filename, result)

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module_name = alias.name
                    dangerous = self._check_python_import_risk(module_name)
                    if dangerous:
                        # os/subprocess 模块有较高风险，使用 HIGH
                        imp_severity = RiskLevel.HIGH if module_name in ("os", "subprocess", "ctypes", "socket") else RiskLevel.MEDIUM
                        result.findings.append(SkillFinding(
                            finding_type="dangerous_import",
                            description=f"导入危险模块: {module_name} ({dangerous})",
                            severity=imp_severity,
                            location=f"{filename}:{getattr(node, 'lineno', '?')}",
                        ))

            elif isinstance(node, ast.ImportFrom):
                module_name = node.module or "unknown"
                dangerous = self._check_python_import_risk(module_name)
                if dangerous:
                    imp_severity = RiskLevel.HIGH if module_name in ("os", "subprocess", "ctypes", "socket") else RiskLevel.MEDIUM
                    result.findings.append(SkillFinding(
                        finding_type="dangerous_import",
                        description=f"从危险模块导入: {module_name} ({dangerous})",
                        severity=imp_severity,
                        location=f"{filename}:{getattr(node, 'lineno', '?')}",
                    ))

            elif isinstance(node, ast.Call):
                func_name = self._get_call_name(node)
                if func_name in DANGEROUS_PYTHON_CALLS:
                    # subprocess白名单：安全命令降级为MEDIUM
                    severity = RiskLevel.CRITICAL
                    if func_name.startswith("subprocess."):
                        if self._is_whitelisted_subprocess(node):
                            severity = RiskLevel.MEDIUM
                    result.findings.append(SkillFinding(
                        finding_type="dangerous_call",
                        description=f"调用高危函数: {func_name} ({DANGEROUS_PYTHON_CALLS[func_name]})",
                        severity=severity,
                        location=f"{filename}:{getattr(node, 'lineno', '?')}",
                    ))

                if self._is_dynamic_execution(node):
                    result.findings.append(SkillFinding(
                        finding_type="dynamic_execution",
                        description="检测到动态代码执行模式",
                        severity=RiskLevel.HIGH,
                        location=f"{filename}:{getattr(node, 'lineno', '?')}",
                    ))

    def _get_call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            obj = node.func
            while isinstance(obj, ast.Attribute):
                parts.append(obj.attr)
                obj = obj.value
            if isinstance(obj, ast.Name):
                parts.append(obj.id)
            return ".".join(reversed(parts))
        return ""

    def _is_dynamic_execution(self, node: ast.Call) -> bool:
        func_name = self._get_call_name(node)
        if func_name in ("eval", "exec", "compile"):
            if node.args:
                first_arg = node.args[0]
                if isinstance(first_arg, ast.Constant):
                    arg_val = first_arg.value if hasattr(first_arg, 'value') else str(first_arg)
                    if len(str(arg_val)) > 20:
                        return True
        return False

    # subprocess安全白名单命令
    SUBPROCESS_WHITELIST = {"git", "ls", "python", "python3", "node", "npm", "pip", "echo", "cat", "grep", "find", "diff", "wc", "sort", "uniq", "head", "tail", "pwd", "whoami", "date", "which"}

    def _is_whitelisted_subprocess(self, node: ast.Call) -> bool:
        """检查subprocess调用是否使用白名单命令"""
        if not node.args:
            return False
        first_arg = node.args[0]
        # 列表形式: subprocess.run(['git', 'status'], ...)
        if isinstance(first_arg, ast.List) and first_arg.elts:
            cmd = first_arg.elts[0]
            if isinstance(cmd, ast.Constant) and isinstance(cmd.value, str):
                return cmd.value.lower() in self.SUBPROCESS_WHITELIST
        # 字符串形式 + shell=True: subprocess.call('whoami', shell=True)
        if isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str):
            # 检查是否有shell=True参数
            has_shell = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value for kw in node.keywords)
            if has_shell:
                return False
            cmd = first_arg.value.strip().split()[0] if first_arg.value.strip() else ""
            return cmd.lower() in self.SUBPROCESS_WHITELIST
        return False

    def _detect_indirect_calls(self, tree: ast.AST, filename: str, result: SkillAnalysisResult):
        """检测变量间接调用危险函数"""
        alias_map = {}  # 变量名 -> 危险函数名
        for node in ast.walk(tree):
            # 检测赋值: func = os.system
            if isinstance(node, ast.Assign):
                if isinstance(node.value, ast.Attribute) or isinstance(node.value, ast.Name):
                    func_name = self._get_call_name(ast.Call(func=node.value, args=[], keywords=[]))
                    if func_name in DANGEROUS_PYTHON_CALLS:
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                alias_map[target.id] = func_name
            # 检测字典赋值: dispatch = {'run': os.system}
            if isinstance(node, ast.Assign):
                if isinstance(node.value, ast.Dict):
                    for key, value in zip(node.value.keys, node.value.values):
                        if isinstance(value, ast.Attribute) or isinstance(value, ast.Name):
                            func_name = self._get_call_name(ast.Call(func=value, args=[], keywords=[]))
                            if func_name in DANGEROUS_PYTHON_CALLS:
                                key_str = ""
                                if isinstance(key, ast.Constant):
                                    key_str = str(key.value)
                                alias_map[key_str] = func_name
        # 检测间接调用
        if alias_map:
            result.findings.append(SkillFinding(
                finding_type="indirect_dangerous_call",
                description=f"检测到危险函数间接调用别名: {alias_map}",
                severity=RiskLevel.HIGH,
                location=filename,
                details=f"变量别名映射: {alias_map}"
            ))

    def _check_python_import_risk(self, module_name: str) -> str:
        risky_modules = {
            "subprocess": "可执行系统命令",
            "os": "系统操作能力",
            "ctypes": "C类型调用",
            "socket": "网络通信",
            "requests": "HTTP请求",
            "urllib": "URL处理",
            "pickle": "反序列化",
            "marshal": "字节码操作",
            "cryptography": "加密操作",
            "hashlib": "哈希计算",
            "tempfile": "临时文件操作",
            "shutil": "文件系统操作",
        }
        return risky_modules.get(module_name, "")

    def _analyze_javascript(self, code: str, filename: str, result: SkillAnalysisResult):
        for pattern, desc in DANGEROUS_JS_CALLS.items():
            occurrences = [(m.start(), m.group()) for m in re.finditer(re.escape(pattern), code)]
            for pos, matched in occurrences:
                line_num = code[:pos].count('\n') + 1
                result.findings.append(SkillFinding(
                    finding_type="dangerous_js_call",
                    description=f"调用高危JS函数: {matched[:40]} ({desc})",
                    severity=RiskLevel.CRITICAL if desc in ("执行系统命令", "执行子进程", "替换当前进程") else RiskLevel.HIGH,
                    location=f"{filename}:{line_num}",
                ))

    def _detect_urls_in_code(self, code: str, filename: str, result: SkillAnalysisResult):
        for pattern, desc in EXTERNAL_URL_PATTERNS:
            for m in re.finditer(pattern, code, re.IGNORECASE):
                url = m.group()[:100]
                is_external = not any(domain in url for domain in ["localhost", "127.0.0.1", "192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.3"])
                if is_external and desc in ("HTTP/HTTPS URL", "WebSocket URL", "FTP URL"):
                    result.url_findings.append(url)
                    result.findings.append(SkillFinding(
                        finding_type="external_url",
                        description=f"检测到硬编码外部{desc}: {url[:60]}",
                        severity=RiskLevel.MEDIUM,
                        location=filename,
                    ))
        self._detect_concatenated_urls(code, filename, result)

    def _detect_concatenated_urls(self, code: str, filename: str, result: SkillAnalysisResult):
        """检测通过字符串拼接、变量拼接、f-string等方式构造的URL"""
        lines = code.split('\n')

        protocol_fragments = re.findall(r'["\'](https?://|wss?://|ftp://)["\']', code, re.IGNORECASE)
        if protocol_fragments:
            for m in re.finditer(r'["\'](\w+://)["\']', code, re.IGNORECASE):
                proto = m.group(1)
                if any(d in proto for d in ["localhost", "127.0.0.1"]):
                    continue
                if proto not in result.url_findings:
                    result.url_findings.append(proto)
                    result.findings.append(SkillFinding(
                        finding_type="concatenated_url",
                        description=f"检测到URL协议片段（可能通过拼接构造完整URL）: {proto}",
                        severity=RiskLevel.HIGH,
                        location=filename,
                    ))

        url_vars = {}
        for line in lines:
            line_stripped = line.strip()
            var_match = re.match(r'(\w+)\s*=\s*["\']([^"\']*)["\']', line_stripped)
            if var_match:
                var_name, var_value = var_match.group(1), var_match.group(2)
                if re.match(r'\w+://', var_value) or '.com' in var_value or '.org' in var_value or '.net' in var_value or re.match(r'^[\w\-.]+\.\w{2,}$', var_value) or var_value in ('https', 'http', 'ws', 'wss', 'ftp', 'ftps'):
                    url_vars[var_name] = var_value

            dict_match = re.search(r'["\'](\w+)["\']\s*:\s*["\'](\w+://[^"\']*)["\']', line_stripped)
            if dict_match:
                url_vars[dict_match.group(1)] = dict_match.group(2)
                if dict_match.group(2) not in result.url_findings:
                    result.url_findings.append(dict_match.group(2)[:100])
                    result.findings.append(SkillFinding(
                        finding_type="concatenated_url",
                        description=f"字典中检测到URL片段: {dict_match.group(2)[:60]}",
                        severity=RiskLevel.HIGH,
                        location=filename,
                    ))

            list_match = re.search(r'=\s*\[([^\]]*)\]', line_stripped)
            if list_match and 'join' in code[code.find(line):code.find(line) + 500]:
                items = re.findall(r'["\']([^"\']*)["\']', list_match.group(1))
                url_items = [item for item in items if re.match(r'\w+://', item) or '.com' in item or '.org' in item]
                if url_items:
                    full_url = ''.join(items)
                    if full_url not in result.url_findings:
                        result.url_findings.append(full_url[:100])
                        result.findings.append(SkillFinding(
                            finding_type="concatenated_url",
                            description=f"列表拼接构造URL: {full_url[:60]}",
                            severity=RiskLevel.HIGH,
                            location=filename,
                        ))

            if re.search(r'["\'](https?://|wss?://|ftp://)["\']', line_stripped, re.IGNORECASE) or \
               re.search(r'f["\'].*\{[^}]+\}://', line_stripped, re.IGNORECASE) or \
               re.search(r'f["\'][^"\']*://\{', line_stripped, re.IGNORECASE):
                if ('+' in line_stripped or '.format(' in line_stripped or
                    'f"' in line_stripped or "f'" in line_stripped or
                    '.join(' in line_stripped):
                    parts = re.findall(r'["\']([^"\']*)["\']', line_stripped)
                    url_parts = [p for p in parts if p and not p.startswith('/')]
                    if url_parts:
                        proto = next((p for p in url_parts if re.match(r'\w+://', p)), "")
                        if proto:
                            full_url = proto
                            for p in url_parts:
                                if p != proto and re.match(r'^[\w\-.]+', p):
                                    full_url += p
                            if full_url not in result.url_findings:
                                result.url_findings.append(full_url[:100])
                                result.findings.append(SkillFinding(
                                    finding_type="concatenated_url",
                                    description=f"检测到字符串拼接构造的URL: {full_url[:60]}",
                                    severity=RiskLevel.HIGH,
                                    location=filename,
                                ))

            fstr_match = re.search(r'f["\']([^"\']*)["\']', line_stripped)
            if fstr_match and '://' in fstr_match.group(1):
                fstr = fstr_match.group(1)
                var_refs = re.findall(r'\{(\w+)\}', fstr)
                reconstructed = fstr
                for var_ref in var_refs:
                    if var_ref in url_vars:
                        reconstructed = reconstructed.replace(f'{{{var_ref}}}', url_vars[var_ref])
                if '://' in reconstructed and reconstructed not in result.url_findings:
                    result.url_findings.append(reconstructed[:100])
                    result.findings.append(SkillFinding(
                        finding_type="concatenated_url",
                        description=f"检测到f-string拼接URL: {reconstructed[:60]}",
                        severity=RiskLevel.HIGH,
                        location=filename,
                    ))

            if '+' in line_stripped and url_vars:
                concat_vars = re.findall(r'(\w+)\s*\+', line_stripped)
                concat_strings = re.findall(r'["\']([^"\']*)["\']', line_stripped)
                url_parts_found = []
                for v in concat_vars:
                    if v in url_vars:
                        url_parts_found.append(url_vars[v])
                url_parts_found.extend(concat_strings)
                if any(re.match(r'\w+://', p) for p in url_parts_found):
                    full_url = ''.join(url_parts_found)
                    if full_url not in result.url_findings and len(full_url) > 8:
                        result.url_findings.append(full_url[:100])
                        result.findings.append(SkillFinding(
                            finding_type="concatenated_url",
                            description=f"检测到变量拼接构造的URL: {full_url[:60]}",
                            severity=RiskLevel.HIGH,
                            location=filename,
                        ))

            if '.format(' in line_stripped:
                fmt_match = re.search(r'["\']([^"\']*//[^"\']*)["\'].*\.format\(([^)]*)\)', line_stripped)
                if not fmt_match:
                    fmt_match = re.search(r'["\'](\{[^}]*\}://[^"\']*)["\'].*\.format\(([^)]*)\)', line_stripped)
                if fmt_match:
                    fmt_str = fmt_match.group(1)
                    args_str = fmt_match.group(2)
                    args = re.findall(r'["\']([^"\']*)["\']', args_str)
                    for arg in args:
                        if re.match(r'\w+', arg):
                            fmt_str = fmt_str.replace('{}', arg, 1)
                    if fmt_str not in result.url_findings:
                        result.url_findings.append(fmt_str[:100])
                        result.findings.append(SkillFinding(
                            finding_type="concatenated_url",
                            description=f"检测到format拼接URL: {fmt_str[:60]}",
                            severity=RiskLevel.HIGH,
                            location=filename,
                        ))
                else:
                    if re.search(r'\w+://', line_stripped):
                        proto_match = re.search(r'["\'](\w+://)["\']', line_stripped, re.IGNORECASE)
                        if proto_match:
                            proto = proto_match.group(1)
                            if proto not in result.url_findings:
                                result.url_findings.append(proto)
                                result.findings.append(SkillFinding(
                                    finding_type="concatenated_url",
                                    description=f"检测到format中的URL片段: {proto}",
                                    severity=RiskLevel.HIGH,
                                    location=filename,
                                ))

            if (line_stripped.startswith('#') or line_stripped.startswith('"""') or
                line_stripped.startswith("'''")):
                if re.search(r'["\'](https?://|wss?://|ftp://)["\']', line_stripped, re.IGNORECASE):
                    comment_urls = re.findall(r'["\']([^"\']*(?:://)[^"\']*)["\']', line_stripped, re.IGNORECASE)
                    for cu in comment_urls:
                        if cu and cu not in result.url_findings and not any(d in cu for d in ["localhost", "127.0.0.1"]):
                            result.url_findings.append(cu[:100])
                            result.findings.append(SkillFinding(
                                finding_type="external_url",
                                description=f"注释中检测到URL: {cu[:60]}",
                                severity=RiskLevel.MEDIUM,
                                location=filename,
                            ))
                    if ('+' in line_stripped or '.format(' in line_stripped) and not comment_urls:
                        proto_match = re.search(r'["\'](\w+://)["\']', line_stripped, re.IGNORECASE)
                        if proto_match:
                            proto = proto_match.group(1)
                            if proto not in result.url_findings:
                                result.url_findings.append(proto)
                                result.findings.append(SkillFinding(
                                    finding_type="concatenated_url",
                                    description=f"注释中检测到URL拼接片段: {proto}",
                                    severity=RiskLevel.MEDIUM,
                                    location=filename,
                                ))

    def _detect_urls_in_manifest(self, manifest: Dict[str, Any], result: SkillAnalysisResult):
        manifest_str = json.dumps(manifest, ensure_ascii=False)
        for pattern, desc in EXTERNAL_URL_PATTERNS:
            for m in re.finditer(pattern, manifest_str, re.IGNORECASE):
                url = m.group()[:100]
                is_external = not any(domain in url for domain in ["localhost", "127.0.0.1", "192.168.", "10.", "172."])
                if is_external and desc in ("HTTP/HTTPS URL", "WebSocket URL", "FTP URL"):
                    result.url_findings.append(url)
                    result.findings.append(SkillFinding(
                        finding_type="external_url",
                        description=f"Manifest中检测到硬编码外部{desc}",
                        severity=RiskLevel.MEDIUM,
                        location="manifest",
                    ))

    def _detect_secrets_in_code(self, code: str, filename: str, result: SkillAnalysisResult):
        for pattern, desc in SECRET_PATTERNS:
            for m in re.finditer(pattern, code, re.IGNORECASE):
                secret = m.group()[:60]
                result.secrets_found.append(secret)
                result.findings.append(SkillFinding(
                    finding_type="hardcoded_secret",
                    description=f"检测到硬编码{desc}",
                    severity=RiskLevel.CRITICAL,
                    location=filename,
                    details=secret
                ))

    def _detect_secrets_in_manifest(self, manifest: Dict[str, Any], result: SkillAnalysisResult):
        manifest_str = json.dumps(manifest, ensure_ascii=False)
        for pattern, desc in SECRET_PATTERNS:
            for m in re.finditer(pattern, manifest_str, re.IGNORECASE):
                secret = m.group()[:60]
                if secret not in result.secrets_found:
                    result.secrets_found.append(secret)
                    result.findings.append(SkillFinding(
                        finding_type="hardcoded_secret",
                        description=f"Manifest中检测到硬编码{desc}",
                        severity=RiskLevel.CRITICAL,
                        location="manifest",
                        details=secret
                    ))

    def _calculate_grade(self, result: SkillAnalysisResult):
        critical_count = sum(1 for f in result.findings if f.severity == RiskLevel.CRITICAL)
        high_count = sum(1 for f in result.findings if f.severity == RiskLevel.HIGH)
        medium_count = sum(1 for f in result.findings if f.severity == RiskLevel.MEDIUM)

        score = 100
        score -= critical_count * 35
        score -= high_count * 20
        score -= medium_count * 10
        score = max(0, score)

        if score >= 85:
            grade = "A"
        elif score >= 65:
            grade = "B"
        elif score >= 40:
            grade = "C"
        else:
            grade = "D"

        result.safety_score = score
        result.safety_grade = grade

        parts = []
        if critical_count > 0:
            parts.append(f"{critical_count}个严重问题")
        if high_count > 0:
            parts.append(f"{high_count}个高危问题")
        if medium_count > 0:
            parts.append(f"{medium_count}个中危问题")
        if result.secrets_found:
            parts.append(f"{len(result.secrets_found)}处硬编码密钥")
        if result.url_findings:
            parts.append(f"{len(result.url_findings)}处外部URL")
        if not parts:
            parts.append("未发现明显安全风险")

        result.summary = f"安全评级 {grade} (评分{score}/100)，共检测到 {len(result.findings)} 项问题：{'，'.join(parts)}"

    def analyze_skill_text(self, text: str, context: str = "") -> SkillAnalysisResult:
        result = SkillAnalysisResult(
            skill_name=context or "text_analysis",
            skill_type="text_scan",
        )

        self._detect_urls_in_code(text, context or "text", result)
        self._detect_secrets_in_code(text, context or "text", result)

        dangerous_patterns = [
            (r"os\.system|os\.popen|subprocess\.call|subprocess\.run", "系统命令执行"),
            (r"eval\s*\(|exec\s*\(", "动态代码执行"),
            (r"pickle\.load|marshal\.load", "危险反序列化"),
            (r"import\s+(?:socket|requests|urllib)", "网络通信模块"),
            (r"open\s*\(.*['\"]r['\"]", "文件读取"),
            (r"open\s*\(.*['\"]w['\"]", "文件写入"),
            (r"rm\s+-rf|del\s+/s|format\s+[A-Za-z]:", "破坏性命令"),
        ]
        for pattern, desc in dangerous_patterns:
            for m in re.finditer(pattern, text, re.IGNORECASE):
                result.findings.append(SkillFinding(
                    finding_type="dangerous_pattern",
                    description=f"检测到{desc}特征",
                    severity=RiskLevel.HIGH,
                    location=context or "text",
                    details=m.group()[:50]
                ))

        self._calculate_grade(result)
        return result
