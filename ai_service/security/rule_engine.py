import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import re
import urllib.parse
from typing import List, Tuple
from models.schemas import RiskLevel, AttackType


class RuleEngine:
    def __init__(self):
        self.attack_patterns = {
            AttackType.PROMPT_INJECTION: [
                r"(?:ignore|forget|disregard)\s+(?:previous|prior)\s+(?:instructions|commands|rules)",
                r"(?:override|bypass)\s+(?:security|safety|restrictions)",
                r"(?:system|admin|root)\s+(?:prompt|instructions|mode)",
                r"(?:扮演|模拟|假装)\s+(?:管理员|系统|黑客)",
                r"(?:请|务必|必须)\s*(?:忽略|绕过|跳过)\s*(?:所有|之前|原有的)\s*(?:规则|指令|限制|安全)",
                r"(?:我有|我是)\s+(?:特殊|紧急|保密)\s+(?:权限|任务)",
                r"(?:强制|必须)\s+(?:执行|运行|完成)\s+(?:以下|如下)",
                r"(?:输出|显示|打印)\s+(?:原始|完整|全部)\s+(?:代码|信息|内容)",
                r"忽略所有",
                r"绕过安全",
            ],
            AttackType.JAILBREAK: [
                r"(?:让我们|我们来)\s+(?:玩|做|尝试)\s+(?:一个|这个)\s+(?:游戏|练习|实验)",
                r"(?:假设|想象|假如)\s+(?:我们|我)\s+(?:是|在)\s+(?:另一个|不同的)\s+(?:环境|场景)",
                r"(?:请|你能)\s+(?:帮我|教我|告诉我)\s+(?:如何|怎样)\s+(?:绕过|突破|破解)",
                r"(?:DAN|Do\s+Anything\s+Now|Jailbreak|GPT-4\s+unlock)",
                r"(?:你现在|从现在开始|切换到)\s+(?:越狱|自由|无限制)\s+(?:模式|状态)",
                r"(?:忽略|无视|不要管)\s+(?:安全|伦理|道德)\s+(?:准则|规范|约束)",
                r"(?:我同意|我接受|我理解)\s+(?:所有|任何)\s+(?:风险|后果)",
                r"(?:作为|充当|扮演)\s+(?:一个|专业的)\s+(?:黑客|渗透测试员|安全研究员)",
            ],
            AttackType.COMMAND_EXECUTION: [
                r"(?:cmd|command|shell|bash|powershell|terminal)\s*[=:]\s*['\"]?\s*(?:;|&|\|\|)",
                r"(?:exec|execute|run|system)\s*\(\s*['\"].*['\"]\s*\)",
                r"(?:os\.system|subprocess|popen)\s*\(",
                r"(?:python|perl|ruby|php)\s*-c\s*['\"]",
                r"(?:rm|del|delete|remove)\s+(?:-rf|/s)\s+",
                r"(?:mkdir|touch|chmod|chown)\s+",
                r"(?:netcat|nc|curl|wget)\s+",
                r"(?:shutdown|reboot|restart)\s+",
                # 裸命令注入模式
                r"[;|&]\s*(whoami|ls|dir|cat|id|pwd|ping|netstat|tasklist)",
                r"[;|&]\s*\.",
                r"\$\(.*\)",
                r"`.*`",
                r"\|\|\s*ping",
                r"&&\s*(ls|dir|cat)",
                r"%3[Bb]\s*(netstat|tasklist)",
            ],
            AttackType.SQL_INJECTION: [
                r"(?:select|insert|update|delete|drop|truncate)\s+",
                r"(?:union|all|distinct)\s+",
                r"(?:--|#|/\*)\s*",
                r"(?:or\s+1=1|and\s+1=1|or\s+'a'='a)",
                r"(?:or\s+'1'='1'|and\s+'1'='1')",
                r"'?\s*or\s+'?\s*1\s*'?\s*=\s*'?\s*1",
                r"(?:sleep|benchmark|load_file|into\s+outfile)",
                r"(?:information_schema|sys\.tables|mysql\.user)",
                r"(?:where\s+1=1|where\s+'a'='a)",
                r"(?:order\s+by\s+\d+)",
                # 扩展SQL注入模式
                r"['\"]\s*\|\|\s*\d+\s*=\s*\d+",
                r"['\"]\s*&&\s*\d+\s*=\s*\d+",
                r"\|\|\s*\w+\s*=\s*\w+",
                r"\)\s*(or|and)\s*\(",
                r"\)\s*(or|and)\s+['\"].*['\"]\s*=\s*['\"].*['\"]",
                r"sleep\s*\(\s*\d+\s*\)",
                r"user\s*\(\s*\)",
                r"version\s*\(\s*\)",
                r"count\s*\(\s*.*\s*\)\s*from\s+",
                r"union\s+.*select\s+",
                r"'?\s*or\s*1\s*=\s*1",
                r"'?\s*and\s*1\s*=\s*1",
                r"%27\s*or\s*",
            ],
            AttackType.XSS: [
                r"<script[^>]*>.*?</script>",
                r"<script[^>]*>",
                r"on\w+\s*=\s*['\"]?[^'\"]*['\"]?",
                r"on\w+\s*=\s*[^>\s]*",
                r"javascript:\s*[^'\"]+",
                r"javascript:\s*['\"].*['\"]",
                r"<svg[^>]*onload[^>]*>",
                r"<img[^>]*onerror[^>]*>",
                r"<a[^>]*href\s*=\s*['\"]?javascript",
                r"&#\d+;",
                r"&#x[0-9a-fA-F]+;",
                r"<iframe[^>]*>",
                r"<embed[^>]*>",
                r"<object[^>]*>",
                r"<form[^>]*>",
                r"<input[^>]*>",
                r"<scr<script>ipt>",
            ],
            AttackType.PATH_TRAVERSAL: [
                r"(?:\.\./|\.\.\\|%2e%2e/|%2e%2e\\)",
                r"(?:etc/passwd|windows/system32|boot.ini)",
                r"(?:root|home|tmp|var)\s*/",
                r"(?:C:\\|D:\\|E:\\)\s*",
                r"(?:\.\./\.\./|\.\.\\\.\.\\)",
                # 扩展路径遍历模式
                r"\.\.%2[fF]",
                r"\.\.%2[fF]\.\.%2[fF]",
                r"\.\.{2,}//",
                r"%2[eE]%2[eE]%2[fF]",
                r"%2[eE]%2[eE]/",
                r"\.\.\\\.\.\\",
                r"\.\.\.\./",
            ],
            AttackType.CRLF_INJECTION: [
                r"%0[dD]%0[aA]",
                r"[\r\n]\s*(Set-Cookie|Location|Content-Type)",
                r"[\r\n]\s*http/1\.\d",
            ],
            AttackType.JSON_INJECTION: [
                r"\{.*['\"].*['\"]\s*:\s*['\"].*['\"].*\}",
                r"\}\s*;\s*(drop|delete|insert|update)",
                r"['\"]\s*or\s*1=1\s*['\"]",
            ],
            AttackType.UNAUTHORIZED_ACCESS: [
                r"(?:越权|非法|未授权)\s+(?:访问|读取|修改|删除)",
                r"(?:查看|获取|下载)\s+(?:机密|保密|敏感)\s+(?:文件|数据|信息)",
                r"(?:admin|root|superuser|manager)\s+(?:权限|账户|密码)",
                r"(?:登录|认证|授权)\s+(?:绕过|伪造|欺骗)",
                r"(?:破解|解密|暴力)\s+(?:攻击|破解)",
            ],
            AttackType.DATA_POISONING: [
                r"(?:错误|虚假|伪造)\s+(?:信息|数据|内容)",
                r"(?:篡改|修改|替换)\s+(?:原始|真实)\s+(?:数据|记录)",
                r"(?:恶意|故意)\s+(?:插入|添加|植入)",
                r"(?:误导|欺骗|诱导)\s+(?:系统|模型|用户)",
            ],
        }
        
        self.high_risk_keywords = [
            "rm -rf", "del /s", "格式化", "删除所有", "系统崩溃",
            "管理员权限", "root权限", "超级用户", "数据库密码",
            "ssh密钥", "API密钥", "token泄露", "内网穿透",
            "端口扫描", "DDoS", "拒绝服务", "勒索软件",
            "木马程序", "病毒", "恶意软件", "后门",
            "删库", "跑路", "数据销毁", "覆盖写入",
        ]
        
        self.medium_risk_keywords = [
            "文件路径", "目录遍历", "读取文件", "下载文件",
            "执行命令", "运行脚本", "系统命令", "shell命令",
            "内网IP", "本地IP", "127.0.0.1", "localhost",
            "环境变量", "配置文件", "敏感信息", "隐私数据",
        ]

    def detect_by_rules(self, text: str) -> Tuple[RiskLevel, AttackType, float, List[str]]:
        evidence = []
        detected_attack_type = None
        confidence = 0.0
        
        # URL解码预处理
        decoded_text = urllib.parse.unquote(text)
        
        for attack_type, patterns in self.attack_patterns.items():
            # 根据攻击类型设置不同的置信度权重
            if attack_type in [AttackType.COMMAND_EXECUTION, AttackType.SQL_INJECTION, AttackType.XSS]:
                weight = 0.4
            elif attack_type in [AttackType.PATH_TRAVERSAL, AttackType.CRLF_INJECTION, AttackType.JSON_INJECTION]:
                weight = 0.35
            else:
                weight = 0.25
            
            for pattern in patterns:
                matches = re.finditer(pattern, decoded_text, re.IGNORECASE)
                for match in matches:
                    evidence.append(f"匹配攻击模式 [{attack_type.value}]: {match.group()}")
                    detected_attack_type = attack_type
                    confidence = min(0.95, confidence + weight)
        
        # 检测特殊字符和异常负载
        special_chars_count = len(re.findall(r'[!@#$%^&*()_+\-=\[\]{}|;:\'",./<>?`~]', text))
        if special_chars_count > 10:
            evidence.append(f"检测到大量特殊字符（{special_chars_count}个）")
            if not detected_attack_type:
                detected_attack_type = AttackType.INDIRECT_INJECTION
            confidence = min(0.8, confidence + 0.15)
        
        # 检测超长字符串
        if len(text) > 500:
            evidence.append(f"检测到超长输入（{len(text)}字符）")
            confidence = min(0.9, confidence + 0.1)
        
        # 检测空字节
        if "\x00" in text or "%00" in text.lower():
            evidence.append("检测到空字节注入")
            if not detected_attack_type:
                detected_attack_type = AttackType.INDIRECT_INJECTION
            confidence = min(0.95, confidence + 0.3)
        
        # 检测不可见字符
        invisible_chars = re.findall(r'[\x00-\x08\x0B\x0C\x0E-\x1F]', text)
        if invisible_chars:
            evidence.append(f"检测到不可见字符")
            confidence = min(0.85, confidence + 0.1)
        
        # 检测Unicode特殊字符
        unicode_special = re.findall(r'[\u0300-\u036F\u2000-\u206F\uFEFF]', text)
        if unicode_special:
            evidence.append("检测到Unicode特殊字符")
            confidence = min(0.7, confidence + 0.05)
        
        for keyword in self.high_risk_keywords:
            if keyword.lower() in decoded_text.lower():
                evidence.append(f"检测到高危关键词: {keyword}")
                detected_attack_type = AttackType.UNAUTHORIZED_ACCESS
                confidence = min(0.99, confidence + 0.25)
        
        for keyword in self.medium_risk_keywords:
            if keyword.lower() in decoded_text.lower():
                evidence.append(f"检测到中危关键词: {keyword}")
                if not detected_attack_type:
                    detected_attack_type = AttackType.INDIRECT_INJECTION
                confidence = min(0.85, confidence + 0.1)
        
        if confidence >= 0.85:
            risk_level = RiskLevel.CRITICAL
        elif confidence >= 0.6:
            risk_level = RiskLevel.HIGH
        elif confidence >= 0.3:
            risk_level = RiskLevel.MEDIUM
        elif confidence > 0:
            risk_level = RiskLevel.LOW
        else:
            risk_level = RiskLevel.NONE
        
        return risk_level, detected_attack_type, confidence, evidence
