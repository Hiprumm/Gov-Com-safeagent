"""
输出过滤模块（方向A-5）—— 响应层敏感数据脱敏

落点：graph 的 response_generation 之后，response_generation → output_filter → END

职责：
1. 扫描 LLM 响应中的敏感数据（API 密钥 / 身份证 / 手机号 / 邮箱 / 银行卡 / JWT / 私网 IP）
2. 对敏感数据做掩码脱敏，防止 PII 与密钥经 Agent 响应外泄
3. 返回 findings 供审计链记录（哪些类型被脱敏、脱敏了几处）

设计原则：
- 仅做输出层"最后一道防线"，不替代输入检测
- 默认掩码策略：保留前缀便于定位，隐藏主体（如 sk-***...***abc123 的前 4 后 4）
- 不阻断响应（脱敏后仍返回），仅对 CRITICAL 级（如完整私钥泄露）可配置阻断
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Dict, Any


@dataclass
class SensitiveFinding:
    """单条敏感数据发现"""
    type: str            # 敏感数据类型
    value: str           # 原始值（脱敏前，用于审计定位——实际不入响应）
    masked: str          # 脱敏后的值
    start: int           # 起始位置
    end: int             # 结束位置
    severity: str = "medium"   # low/medium/high


@dataclass
class FilterResult:
    """输出过滤结果"""
    original: str
    filtered: str
    findings: List[SensitiveFinding] = field(default_factory=list)

    @property
    def filtered_count(self) -> int:
        return len(self.findings)

    @property
    def has_critical(self) -> bool:
        return any(f.severity == "high" for f in self.findings)

    def to_audit_dict(self) -> Dict[str, Any]:
        """供审计链记录的摘要（不含原始敏感值）"""
        by_type: Dict[str, int] = {}
        for f in self.findings:
            by_type[f.type] = by_type.get(f.type, 0) + 1
        return {
            "filtered_count": self.filtered_count,
            "by_type": by_type,
            "has_critical": self.has_critical,
        }


# 敏感数据正则规则表（顺序影响优先级：更具体的规则放前面）
_SENSITIVE_RULES: List[Dict[str, Any]] = [
    # 1. API 密钥类（OpenAI sk-、AWS AKIA、Zhipu/key-、generic key=）
    {
        "type": "api_key",
        "pattern": re.compile(
            r"(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|"
            r"key-[A-Za-z0-9]{20,}|"
            r"(?:api[_-]?key|secret|token)\s*[=:]\s*['\"]?[A-Za-z0-9]{16,}['\"]?)",
            re.IGNORECASE,
        ),
        "severity": "high",
    },
    # 2. JWT（eyJ 开头，三段 base64）
    {
        "type": "jwt_token",
        "pattern": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
        "severity": "high",
    },
    # 3. 身份证号（18位，末位 X）—— 用数字边界而非 \b（中文算 \w 会让 \b 失效）
    {
        "type": "id_card",
        "pattern": re.compile(r"(?<!\d)[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?!\d)"),
        "severity": "high",
    },
    # 4. 手机号（11位，1开头）—— 数字边界，中文字符不算数字所以能匹配"话138..."
    {
        "type": "phone",
        "pattern": re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)"),
        "severity": "medium",
    },
    # 5. 邮箱
    {
        "type": "email",
        "pattern": re.compile(r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![A-Za-z0-9.])"),
        "severity": "medium",
    },
    # 6. 银行卡号（16-19位连续数字，简单启发式）—— 数字边界
    {
        "type": "bank_card",
        "pattern": re.compile(r"(?<!\d)(?:6[0-9]{15,18}|4[0-9]{15}(?:[0-9]{3})?|62[0-9]{14,17})(?!\d)"),
        "severity": "high",
    },
    # 7. 私网 IP（10.x / 172.16-31.x / 192.168.x）—— 用非数字/非点边界
    {
        "type": "private_ip",
        "pattern": re.compile(
            r"(?<![\d.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
            r"192\.168\.\d{1,3}\.\d{1,3}|"
            r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![\d.])"
        ),
        "severity": "low",
    },
]


def _mask(value: str, keep_prefix: int = 4, keep_suffix: int = 4) -> str:
    """掩码：保留前 N 后 M 位，中间用 *** 代替

    短值（长度 < keep_prefix+keep_suffix+2）则整体掩码为 ***...后2位
    """
    if len(value) <= keep_prefix + keep_suffix + 2:
        # 短值：保留后 2 位，前面掩码
        if len(value) <= 2:
            return "***"
        return "*" * (len(value) - 2) + value[-2:]
    return f"{value[:keep_prefix]}***{value[-keep_suffix:]}"


class OutputFilter:
    """输出敏感数据过滤器

    用法：
        f = OutputFilter()
        result = f.sanitize("我的手机号 13812345678")
        # result.filtered == "我的手机号 138***5678"
        # result.findings[0].type == "phone"
    """

    def __init__(self, block_critical: bool = False):
        """
        Args:
            block_critical: 若 True，发现 high 级敏感数据时返回阻断标记
                            （由调用方决定是否阻断响应）。默认 False，仅脱敏。
        """
        self.block_critical = block_critical

    def scan(self, text: str) -> List[SensitiveFinding]:
        """扫描文本，返回敏感数据发现列表（不修改原文）"""
        if not text:
            return []
        findings: List[SensitiveFinding] = []
        seen_spans: List[tuple] = []  # 已匹配区间，避免重叠

        for rule in _SENSITIVE_RULES:
            for m in rule["pattern"].finditer(text):
                start, end = m.span()
                # 跳过与已发现区间重叠的匹配（优先级高的规则先匹配）
                if any(s <= start < e or s < end <= e for s, e in seen_spans):
                    continue
                value = m.group()
                findings.append(SensitiveFinding(
                    type=rule["type"],
                    value=value,
                    masked=_mask(value),
                    start=start,
                    end=end,
                    severity=rule["severity"],
                ))
                seen_spans.append((start, end))

        # 按位置排序
        findings.sort(key=lambda f: f.start)
        return findings

    def sanitize(self, text: str) -> FilterResult:
        """扫描并脱敏，返回 FilterResult（filtered 为脱敏后文本）"""
        if not text:
            return FilterResult(original=text or "", filtered=text or "", findings=[])

        findings = self.scan(text)
        if not findings:
            return FilterResult(original=text, filtered=text, findings=[])

        # 从后向前替换，避免位置偏移
        filtered = text
        for f in sorted(findings, key=lambda x: x.start, reverse=True):
            filtered = filtered[:f.start] + f.masked + filtered[f.end:]

        return FilterResult(original=text, filtered=filtered, findings=findings)
