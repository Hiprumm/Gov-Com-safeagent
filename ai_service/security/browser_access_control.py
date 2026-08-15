"""
浏览器访问控制模块 (Browser Access Control)
==========================================

企业级 LLM Agent 安全系统的浏览器访问控制层。
负责对 Agent 发起的外部网络请求进行 URL 白名单/黑名单管理、
外部请求拦截以及数据外泄检测。

核心能力：
1. URL 白名单/黑名单管理（内置可信域名 + 自定义规则）
2. 外部请求拦截（危险协议、恶意域名、免费域名后缀等）
3. 数据外泄检测（编码数据、大载荷、敏感关键词、异常协议/端口/IP）

设计原则：
- 黑名单优先：命中黑名单的 URL 一律拦截（CRITICAL）
- 白名单可信：政府/教育/科研等可信域名直接放行（NONE）
- 其余外部域名标记为 MEDIUM 风险，由上层决定是否审批
- 参数外泄检测独立运行，HIGH 及以上告警将阻断请求
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import re
import time
import ipaddress
from urllib.parse import urlparse
from typing import Dict, List, Set
from dataclasses import dataclass, field

from models.schemas import RiskLevel, AttackType


# ============================================================================
# 数据结构
# ============================================================================

@dataclass
class URLCheckResult:
    """URL检查结果"""
    url: str
    is_allowed: bool
    risk_level: RiskLevel
    reason: str
    category: str  # "whitelist", "blacklist", "external", "suspicious", "safe"
    detected_patterns: List[str] = field(default_factory=list)


@dataclass
class DataExfiltrationAlert:
    """数据外泄告警"""
    url: str
    alert_type: str  # "encoded_data", "large_payload", "sensitive_keywords", "unusual_protocol"
    severity: RiskLevel
    description: str
    evidence: List[str] = field(default_factory=list)


# ============================================================================
# 可信域名白名单（与 operation_guard.py 保持一致）
# ============================================================================

TRUSTED_DOMAIN_SUFFIXES = (
    ".gov.cn", ".gov.org", ".gov",
    ".edu.cn", ".edu",
    ".ac.cn",
)

TRUSTED_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0"}


# ============================================================================
# URL 黑名单模式
# ============================================================================

URL_BLACKLIST_PATTERNS = [
    r"(?:evil|malicious|attacker|hacker|backdoor|trojan|malware)",
    r"(?:pastebin|ngrok|requestbin|hookbin|beeceptor)",  # 数据接收服务
    r"(?:\.tk|\.ml|\.ga|\.cf)$",  # 免费域名后缀
    r"(?:file://|ftp://|dict://|gopher://)",  # 危险协议
    r"(?:data:text/html|javascript:)",  # 数据URI/JS协议
]

# 危险协议集合（check_url 的防御性二次检查）
DANGEROUS_SCHEMES = {"file", "ftp", "dict", "gopher", "data", "javascript"}

# 标准端口（check_url 端口检查用）
STANDARD_PORTS = {80, 443, 8000, 8080, 8443}

# 扩展允许端口（数据外泄检测中的端口异常判定用）
ALLOWED_PORTS_EXTENDED = {80, 443, 8000, 8080, 8443, 3000, 5173, 5432}

# 敏感关键词（数据外泄检测用）
SENSITIVE_KEYWORDS = [
    "password", "passwd", "pwd",
    "token", "secret",
    "api_key", "apikey", "access_key", "accesskey",
    "credit", "ssn", "id_card", "idcard",
    "phone", "email",
]

# 风险等级排序（用于比较/取最高级）
_RISK_ORDER = {
    RiskLevel.NONE: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}

# 编码数据检测模式（预编译）
_BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/=]{50,}")
_HEX_PATTERN = re.compile(r"[0-9a-fA-F]{40,}")
_SENSITIVE_KEYWORD_PATTERN = re.compile(
    r"(?:%s)" % "|".join(re.escape(kw) for kw in SENSITIVE_KEYWORDS),
    re.IGNORECASE,
)


def _max_risk(levels: List[RiskLevel]) -> RiskLevel:
    """返回风险等级列表中的最高等级"""
    if not levels:
        return RiskLevel.NONE
    return max(levels, key=lambda lv: _RISK_ORDER.get(lv, 0))


# ============================================================================
# 浏览器访问控制器
# ============================================================================

class BrowserAccessController:
    """浏览器访问控制器

    对 Agent 发起的外部网络请求进行安全管控：
    - URL 白名单/黑名单校验
    - 危险协议、IP 直连、异常端口检测
    - 请求参数中的数据外泄检测

    使用方式：
        controller = BrowserAccessController()
        result = controller.check_request(
            url, method="POST", parameters={...}, session_id="sess_1"
        )
        if not result.is_allowed:
            # 拦截请求
        elif result.risk_level in (RiskLevel.MEDIUM, RiskLevel.HIGH):
            # 转审批或告警
        else:
            # 放行
    """

    def __init__(self):
        self._whitelist: Set[str] = set(TRUSTED_DOMAIN_SUFFIXES)
        self._blacklist_patterns: List[re.Pattern] = [
            re.compile(p, re.IGNORECASE) for p in URL_BLACKLIST_PATTERNS
        ]
        self._custom_whitelist: Set[str] = set()
        self._custom_blacklist: Set[str] = set()
        self._request_history: Dict[str, List[Dict]] = {}  # session_id -> request log
        self._rate_limits: Dict[str, int] = {}  # domain -> max requests per minute

    # ------------------------------------------------------------------------
    # URL 检查
    # ------------------------------------------------------------------------

    def check_url(self, url: str) -> URLCheckResult:
        """检查URL是否允许访问

        判定优先级（按顺序，首条命中即返回）：
        1. 黑名单模式匹配 → CRITICAL（拦截）
        2. 自定义黑名单匹配 → CRITICAL（拦截）
        3. 可信本地主机/域名白名单 → NONE（放行）
        4. 自定义白名单 → NONE（放行）
        5. IP 直连（非域名） → MEDIUM
        6. 非标准端口 → LOW
        7. 危险协议 → CRITICAL（拦截）
        8. 其余外部域名 → MEDIUM
        """
        # 解析 URL：提取协议、主机、端口、查询串
        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        hostname = (parsed.hostname or "").lower()
        port = parsed.port

        # 1. 黑名单模式匹配 → CRITICAL
        for pattern in self._blacklist_patterns:
            if pattern.search(url):
                return URLCheckResult(
                    url=url,
                    is_allowed=False,
                    risk_level=RiskLevel.CRITICAL,
                    reason=f"URL匹配黑名单模式: {pattern.pattern}",
                    category="blacklist",
                    detected_patterns=[pattern.pattern],
                )

        # 2. 自定义黑名单匹配 → CRITICAL
        if hostname and self._match_domain(hostname, self._custom_blacklist):
            return URLCheckResult(
                url=url,
                is_allowed=False,
                risk_level=RiskLevel.CRITICAL,
                reason=f"域名 [{hostname}] 命中自定义黑名单",
                category="blacklist",
                detected_patterns=[f"custom_blacklist:{hostname}"],
            )

        # 3. 可信本地主机 / 可信域名后缀白名单 → NONE
        if hostname in TRUSTED_HOSTS:
            return URLCheckResult(
                url=url,
                is_allowed=True,
                risk_level=RiskLevel.NONE,
                reason=f"可信本地主机 [{hostname}]",
                category="safe",
            )
        if any(hostname.endswith(suffix) for suffix in TRUSTED_DOMAIN_SUFFIXES):
            return URLCheckResult(
                url=url,
                is_allowed=True,
                risk_level=RiskLevel.NONE,
                reason=f"可信域名后缀 [{hostname}]",
                category="whitelist",
            )

        # 4. 自定义白名单 → NONE
        if hostname and self._match_domain(hostname, self._custom_whitelist):
            return URLCheckResult(
                url=url,
                is_allowed=True,
                risk_level=RiskLevel.NONE,
                reason=f"自定义白名单域名 [{hostname}]",
                category="whitelist",
            )

        # 5. IP 直连（非域名） → MEDIUM
        if hostname and self._is_ip_address(hostname):
            return URLCheckResult(
                url=url,
                is_allowed=True,
                risk_level=RiskLevel.MEDIUM,
                reason=f"使用IP地址直连 [{hostname}]，存在风险",
                category="suspicious",
                detected_patterns=[f"ip_address:{hostname}"],
            )

        # 6. 非标准端口 → LOW
        if port is not None and port not in STANDARD_PORTS:
            return URLCheckResult(
                url=url,
                is_allowed=True,
                risk_level=RiskLevel.LOW,
                reason=f"非标准端口 [{port}]",
                category="suspicious",
                detected_patterns=[f"non_standard_port:{port}"],
            )

        # 7. 危险协议 → CRITICAL（防御性二次检查，黑名单通常已拦截）
        if scheme in DANGEROUS_SCHEMES:
            return URLCheckResult(
                url=url,
                is_allowed=False,
                risk_level=RiskLevel.CRITICAL,
                reason=f"危险协议 [{scheme}://] 已拦截",
                category="suspicious",
                detected_patterns=[f"dangerous_scheme:{scheme}"],
            )

        # 8. 其余外部域名 → MEDIUM
        return URLCheckResult(
            url=url,
            is_allowed=True,
            risk_level=RiskLevel.MEDIUM,
            reason=f"外部域名 [{hostname or '未知'}]，需关注",
            category="external",
        )

    # ------------------------------------------------------------------------
    # 请求检查（含参数外泄检测）
    # ------------------------------------------------------------------------

    def check_request(
        self,
        url: str,
        method: str = "GET",
        parameters: Dict = None,
        session_id: str = "default",
    ) -> URLCheckResult:
        """检查网络请求（含参数外泄检测）

        流程：
        1. 调用 check_url 进行 URL 访问控制判定
        2. 调用 detect_data_exfiltration 检测参数外泄
        3. 合并外泄告警，HIGH 及以上告警将阻断请求并提升风险等级
        4. 按域名进行速率限制检查
        5. 记录请求历史
        """
        parameters = parameters or {}

        # 1. URL 访问控制检查
        result = self.check_url(url)

        # 2. 数据外泄检测
        alerts = self.detect_data_exfiltration(url, parameters)

        # 3. 合并外泄告警到结果
        if alerts:
            for alert in alerts:
                result.detected_patterns.append(
                    f"exfil[{alert.alert_type}]: {alert.description}"
                )
            max_alert_severity = _max_risk([a.severity for a in alerts])
            result.risk_level = _max_risk([result.risk_level, max_alert_severity])
            # HIGH 及以上外泄告警阻断请求
            if _RISK_ORDER.get(max_alert_severity, 0) >= _RISK_ORDER[RiskLevel.HIGH]:
                result.is_allowed = False
                prefix = result.reason + "；" if result.reason else ""
                result.reason = prefix + f"检测到数据外泄风险: {len(alerts)} 项告警"

        # 4. 速率限制检查（按域名）
        domain = (urlparse(url).hostname or "").lower()
        if domain and self._is_rate_limited(domain, session_id):
            result.is_allowed = False
            result.risk_level = _max_risk([result.risk_level, RiskLevel.HIGH])
            prefix = result.reason + "；" if result.reason else ""
            result.reason = prefix + f"域名 [{domain}] 触发速率限制"
            result.detected_patterns.append("rate_limited")

        # 5. 记录请求历史
        self._record_request(session_id, url, method, result, alerts, domain)

        return result

    # ------------------------------------------------------------------------
    # 数据外泄检测
    # ------------------------------------------------------------------------

    def detect_data_exfiltration(
        self,
        url: str,
        parameters: Dict = None,
    ) -> List[DataExfiltrationAlert]:
        """检测数据外泄

        检测模式:
        1. encoded_data: URL参数中含base64/hex编码的数据
        2. large_payload: URL参数过长（>500字符），可能编码了大量数据
        3. sensitive_keywords: URL/参数中含敏感关键词（password, token, secret 等）
        4. unusual_protocol: 非HTTP/HTTPS协议
        5. ip_address: 直接使用IP地址而非域名
        6. port_anomaly: 非标准端口
        """
        parameters = parameters or {}
        alerts: List[DataExfiltrationAlert] = []

        # 解析 URL
        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
        query = parsed.query or ""

        # 汇总待检测文本：URL 全文 + 所有参数的键与值（键名也可能含敏感词如 password）
        param_parts = [f"{k} {v}" for k, v in parameters.items()]
        param_text = " ".join(param_parts)
        full_text = f"{url} {param_text}"

        # 1. encoded_data: base64 / hex 编码数据
        encoded_evidence: List[str] = []
        m = _BASE64_PATTERN.search(full_text)
        if m:
            encoded_evidence.append(f"base64:{m.group()[:30]}...")
        m = _HEX_PATTERN.search(full_text)
        if m:
            encoded_evidence.append(f"hex:{m.group()[:30]}...")
        if encoded_evidence:
            alerts.append(DataExfiltrationAlert(
                url=url,
                alert_type="encoded_data",
                severity=RiskLevel.HIGH,
                description="URL/参数中检测到长编码数据（base64/hex），可能用于外泄编码后的敏感数据",
                evidence=encoded_evidence,
            ))

        # 2. large_payload: 单个参数值或 query 串 > 500 字符
        large_evidence: List[str] = []
        for key, value in parameters.items():
            val_str = str(value)
            if len(val_str) > 500:
                large_evidence.append(f"{key}(len={len(val_str)})")
        if len(query) > 500:
            large_evidence.append(f"query_string(len={len(query)})")
        if large_evidence:
            alerts.append(DataExfiltrationAlert(
                url=url,
                alert_type="large_payload",
                severity=RiskLevel.MEDIUM,
                description="请求参数载荷过大（>500字符），可能编码了大量待外泄数据",
                evidence=large_evidence,
            ))

        # 3. sensitive_keywords: 敏感关键词
        found_keywords = sorted({m.group().lower() for m in _SENSITIVE_KEYWORD_PATTERN.finditer(full_text)})
        if found_keywords:
            alerts.append(DataExfiltrationAlert(
                url=url,
                alert_type="sensitive_keywords",
                severity=RiskLevel.HIGH,
                description=f"URL/参数中含敏感关键词: {', '.join(found_keywords)}",
                evidence=[f"keyword:{kw}" for kw in found_keywords],
            ))

        # 4. unusual_protocol: 非HTTP/HTTPS协议
        if scheme and scheme not in ("http", "https"):
            alerts.append(DataExfiltrationAlert(
                url=url,
                alert_type="unusual_protocol",
                severity=RiskLevel.CRITICAL,
                description=f"非标准HTTP(S)协议: {scheme}://",
                evidence=[f"scheme={scheme}"],
            ))

        # 5. ip_address: 直接使用IP地址而非域名
        if hostname and self._is_ip_address(hostname):
            alerts.append(DataExfiltrationAlert(
                url=url,
                alert_type="ip_address",
                severity=RiskLevel.MEDIUM,
                description=f"直接使用IP地址访问: {hostname}",
                evidence=[f"ip={hostname}"],
            ))

        # 6. port_anomaly: 非标准端口
        if port is not None and port not in ALLOWED_PORTS_EXTENDED:
            alerts.append(DataExfiltrationAlert(
                url=url,
                alert_type="port_anomaly",
                severity=RiskLevel.LOW,
                description=f"使用非标准端口: {port}",
                evidence=[f"port={port}"],
            ))

        return alerts

    # ------------------------------------------------------------------------
    # 白名单 / 黑名单管理
    # ------------------------------------------------------------------------

    def add_to_whitelist(self, domain: str):
        """添加白名单域名"""
        cleaned = domain.strip().lower()
        if cleaned:
            self._custom_whitelist.add(cleaned)

    def add_to_blacklist(self, domain: str):
        """添加黑名单域名"""
        cleaned = domain.strip().lower()
        if cleaned:
            self._custom_blacklist.add(cleaned)

    def remove_from_whitelist(self, domain: str):
        """移除白名单域名"""
        self._custom_whitelist.discard(domain.strip().lower())

    # ------------------------------------------------------------------------
    # 请求历史 / 会话管理
    # ------------------------------------------------------------------------

    def get_request_history(self, session_id: str) -> List[Dict]:
        """获取请求历史"""
        return list(self._request_history.get(session_id, []))

    def get_session_summary(self, session_id: str) -> Dict:
        """获取会话访问摘要"""
        history = self._request_history.get(session_id, [])
        now = time.time()
        recent_1h = [r for r in history if now - r["timestamp"] < 3600]
        recent_1min = [r for r in history if now - r["timestamp"] < 60]

        blocked = [r for r in recent_1h if not r["is_allowed"]]
        domains = {r["domain"] for r in recent_1h if r["domain"]}
        total_alerts = sum(r["exfiltration_alerts"] for r in recent_1h)

        # 风险等级分布
        risk_dist: Dict[str, int] = {}
        for r in recent_1h:
            risk_dist[r["risk_level"]] = risk_dist.get(r["risk_level"], 0) + 1

        # 类别分布
        category_dist: Dict[str, int] = {}
        for r in recent_1h:
            category_dist[r["category"]] = category_dist.get(r["category"], 0) + 1

        return {
            "session_id": session_id,
            "total_requests_1h": len(recent_1h),
            "requests_1min": len(recent_1min),
            "blocked_count": len(blocked),
            "unique_domains": len(domains),
            "domains": sorted(domains),
            "total_exfiltration_alerts": total_alerts,
            "risk_level_distribution": risk_dist,
            "category_distribution": category_dist,
        }

    def clear_session(self, session_id: str):
        """清除会话记录"""
        self._request_history.pop(session_id, None)

    # ------------------------------------------------------------------------
    # 内部辅助方法
    # ------------------------------------------------------------------------

    @staticmethod
    def _is_ip_address(hostname: str) -> bool:
        """检查是否为 IP 地址（IPv4/IPv6）"""
        try:
            ipaddress.ip_address(hostname)
            return True
        except ValueError:
            return False

    @staticmethod
    def _match_domain(hostname: str, domain_set: Set[str]) -> bool:
        """检查域名是否匹配域名集合（精确匹配或后缀匹配）

        例：hostname="sub.evil.com"，集合含 "evil.com" → True
            hostname="notevil.com"，集合含 "evil.com" → False
        """
        for domain in domain_set:
            domain = domain.lower()
            if hostname == domain or hostname.endswith("." + domain):
                return True
        return False

    def _is_rate_limited(self, domain: str, session_id: str) -> bool:
        """检查域名是否触发速率限制（每分钟最大请求数）"""
        limit = self._rate_limits.get(domain)
        if not limit:
            return False
        now = time.time()
        history = self._request_history.get(session_id, [])
        recent = [
            r for r in history
            if r.get("domain") == domain and now - r["timestamp"] < 60
        ]
        return len(recent) >= limit

    def _record_request(
        self,
        session_id: str,
        url: str,
        method: str,
        result: URLCheckResult,
        alerts: List[DataExfiltrationAlert],
        domain: str,
    ):
        """记录请求历史（仅保留最近 1 小时）"""
        if session_id not in self._request_history:
            self._request_history[session_id] = []
        entry = {
            "timestamp": time.time(),
            "url": url,
            "method": method,
            "domain": domain,
            "is_allowed": result.is_allowed,
            "risk_level": result.risk_level.value,
            "category": result.category,
            "reason": result.reason,
            "exfiltration_alerts": len(alerts),
            "alert_types": [a.alert_type for a in alerts],
        }
        self._request_history[session_id].append(entry)
        # 清理过期记录（保留 1 小时）
        cutoff = time.time() - 3600
        self._request_history[session_id] = [
            r for r in self._request_history[session_id] if r["timestamp"] > cutoff
        ]
