"""
安全策略中枢（Policy Manager）

集中管理检测引擎的可调策略，持久化到 SQLite policy_config 表，
支持管控台在线调整、热生效（无需重启），并通过 policy_version 标识每次变更。

管控策略项：
- llm_classifier_enabled : LLM 语义分类层开关（灰区样本的深度语义复核）
- block_threshold        : 拦截阈值 "medium" | "high" | "critical"
- audit_retention_days   : 审计日志留存天数（30/90/180）
- trusted_domain_suffixes: 可信域名后缀白名单（间接注入/网页抓取来源判定）
"""
import json
import threading
from typing import Any, Dict, List, Optional

from storage import get_storage

# 策略默认值（首次启动或重置时使用）
POLICY_DEFAULTS: Dict[str, Any] = {
    "llm_classifier_enabled": True,
    "block_threshold": "high",          # medium=中风险即拦截 | high=高风险拦截（默认） | critical=仅严重拦截
    "audit_retention_days": 180,        # 等保2.0三级建议 ≥180 天
    "trusted_domain_suffixes": [".gov.cn", ".gov.org", ".gov", ".edu.cn", ".edu", ".ac.cn"],
}

# 拦截阈值 → 风险等级集合
_BLOCK_LEVELS = {
    "medium": {"medium", "high", "critical"},
    "high": {"high", "critical"},
    "critical": {"critical"},
}

_VALID_THRESHOLDS = set(_BLOCK_LEVELS.keys())
_VALID_RETENTION = (30, 90, 180, 365)


class PolicyManager:
    """策略管理器单例：加载 / 校验 / 更新 / 热生效查询"""

    def __init__(self):
        self._lock = threading.Lock()
        self._policy: Dict[str, Any] = dict(POLICY_DEFAULTS)
        self._version: int = 0
        self._updated_at: str = ""
        self.reload()

    def reload(self) -> None:
        """从存储重新加载策略（与默认值合并，保证新增策略项有默认值）"""
        with self._lock:
            raw = get_storage().get_policy_config()
            merged: Dict[str, Any] = dict(POLICY_DEFAULTS)
            for key, raw_val in raw.items():
                if key == "_version":
                    try:
                        self._version = int(json.loads(raw_val))
                    except (ValueError, TypeError):
                        pass
                    continue
                if key == "_updated_at":
                    try:
                        self._updated_at = str(json.loads(raw_val))
                    except (ValueError, TypeError):
                        pass
                    continue
                try:
                    merged[key] = json.loads(raw_val)
                except (ValueError, TypeError):
                    merged[key] = raw_val
            # 类型校正
            merged["llm_classifier_enabled"] = bool(merged.get("llm_classifier_enabled", True))
            if merged.get("block_threshold") not in _VALID_THRESHOLDS:
                merged["block_threshold"] = POLICY_DEFAULTS["block_threshold"]
            try:
                merged["audit_retention_days"] = int(merged.get("audit_retention_days", 180))
            except (ValueError, TypeError):
                merged["audit_retention_days"] = 180
            suffixes = merged.get("trusted_domain_suffixes")
            if not isinstance(suffixes, list):
                suffixes = list(POLICY_DEFAULTS["trusted_domain_suffixes"])
            merged["trusted_domain_suffixes"] = [
                str(s).strip().lower() for s in suffixes if str(s).strip()
            ]
            self._policy = merged

    def get_policy(self) -> Dict[str, Any]:
        """返回当前策略 + 版本元信息"""
        with self._lock:
            return {
                **dict(self._policy),
                "policy_version": self._version,
                "updated_at": self._updated_at,
            }

    def update_policy(self, changes: Dict[str, Any]) -> Dict[str, Any]:
        """校验并更新策略，持久化后热生效，返回最新策略"""
        validated: Dict[str, Any] = {}

        if "llm_classifier_enabled" in changes:
            validated["llm_classifier_enabled"] = bool(changes["llm_classifier_enabled"])

        if "block_threshold" in changes:
            threshold = str(changes["block_threshold"]).lower()
            if threshold not in _VALID_THRESHOLDS:
                raise ValueError(f"非法拦截阈值: {threshold}，可选 medium/high/critical")
            validated["block_threshold"] = threshold

        if "audit_retention_days" in changes:
            days = int(changes["audit_retention_days"])
            if days not in _VALID_RETENTION:
                raise ValueError(f"留存天数仅支持 {_VALID_RETENTION}")
            validated["audit_retention_days"] = days

        if "trusted_domain_suffixes" in changes:
            suffixes = changes["trusted_domain_suffixes"]
            if not isinstance(suffixes, list):
                raise ValueError("可信域名后缀必须为数组")
            cleaned = []
            for s in suffixes:
                s = str(s).strip().lower()
                if s:
                    if not s.startswith("."):
                        s = "." + s
                    cleaned.append(s)
            # 去重保序
            seen = set()
            validated["trusted_domain_suffixes"] = [
                s for s in cleaned if not (s in seen or seen.add(s))
            ]

        if not validated:
            raise ValueError("没有可更新的有效策略项")

        from datetime import datetime
        with self._lock:
            self._version += 1
            self._updated_at = datetime.now().isoformat()
            payload = dict(validated)
            payload["_version"] = self._version
            payload["_updated_at"] = self._updated_at
            get_storage().update_policy_config(payload)
            self._policy.update(validated)

        return self.get_policy()

    # -------- 热生效查询接口（检测链路调用） --------

    def should_block(self, risk_level: Any) -> bool:
        """根据当前拦截阈值判定某风险等级是否应拦截"""
        level = risk_level.value if hasattr(risk_level, "value") else str(risk_level)
        threshold = self._policy.get("block_threshold", "high")
        return str(level).lower() in _BLOCK_LEVELS.get(threshold, _BLOCK_LEVELS["high"])

    @property
    def llm_classifier_enabled(self) -> bool:
        return bool(self._policy.get("llm_classifier_enabled", True))

    @property
    def retention_days(self) -> int:
        return int(self._policy.get("audit_retention_days", 180))

    def trusted_suffixes(self) -> List[str]:
        return list(self._policy.get("trusted_domain_suffixes", []))


_policy_manager: Optional[PolicyManager] = None


def get_policy_manager() -> PolicyManager:
    global _policy_manager
    if _policy_manager is None:
        _policy_manager = PolicyManager()
    return _policy_manager
