import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import uuid
import json
import hashlib
import hmac
import secrets
import threading
import contextvars
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from models.schemas import AuditLog, RiskLevel, DetectionResult, ToolRiskResult, PluginScanResult
from storage import get_storage


# 当前请求来源IP（由 main.py 中间件设置，供审计日志记录来源IP要素）
_current_source_ip: contextvars.ContextVar = contextvars.ContextVar(
    "current_source_ip", default=""
)


def set_source_ip(ip: str) -> None:
    """设置当前请求的来源IP（等保2.0审计要素）"""
    _current_source_ip.set(ip or "")


def get_current_source_ip() -> str:
    """获取当前请求的来源IP"""
    return _current_source_ip.get("")


# 等保2.0三级要求：审计日志默认留存6个月（180天）
# 可通过环境变量 AUDIT_RETENTION_DAYS 调整（如 30=1个月 / 90=3个月 / 180=6个月）
AUDIT_RETENTION_DAYS = int(os.getenv("AUDIT_RETENTION_DAYS", "180"))

# 签名密钥文件（首次启动自动生成）
_AUDIT_KEY_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "audit_secret.key",
)


def _load_signing_key() -> bytes:
    """加载/生成日志签名密钥（HMAC-SHA256）"""
    key_dir = os.path.dirname(_AUDIT_KEY_FILE)
    if not os.path.isdir(key_dir):
        os.makedirs(key_dir, exist_ok=True)
    if not os.path.isfile(_AUDIT_KEY_FILE):
        with open(_AUDIT_KEY_FILE, "w") as f:
            f.write(secrets.token_hex(32))
    with open(_AUDIT_KEY_FILE, "r") as f:
        return f.read().strip().encode()


def _parse_extra(data: Dict[str, Any]) -> Dict[str, Any]:
    """解析存储记录中的 extra_data 字段"""
    raw = data.get("extra_data")
    if isinstance(raw, str):
        try:
            return json.loads(raw) if raw else {}
        except (ValueError, TypeError):
            return {}
    return raw if isinstance(raw, dict) else {}


def _canonical_content(d: Dict[str, Any], prev_hash: str) -> str:
    """构造日志哈希的规范化内容（哈希链节点）"""
    extra = _parse_extra(d)
    payload = {
        "log_id": d.get("log_id", ""),
        "timestamp": d.get("timestamp", ""),
        "user_id": d.get("user_id", ""),
        "user_role": d.get("user_role", ""),
        "agent_id": d.get("agent_id", ""),
        "action_type": d.get("action_type", ""),
        "action_details": d.get("action_details", {}) or {},
        "risk_level": d.get("risk_level", "none"),
        "is_blocked": bool(d.get("is_blocked", False)),
        "blocking_reason": d.get("blocking_reason", "") or "",
        "session_id": extra.get("session_id", ""),
        "think_text": extra.get("think_text", ""),
        "return_value": extra.get("return_value", ""),
        "source_ip": extra.get("source_ip", ""),
        "operation_subject": extra.get("operation_subject", ""),
        "operation_object": extra.get("operation_object", ""),
        "operation_result": extra.get("operation_result", ""),
        "prev_hash": prev_hash,
    }
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)


class AuditLogger:
    """审计日志记录器（等保2.0合规）

    特性：
    1. 等保2.0审计要素：操作主体/客体/时间/结果/来源IP
    2. 日志留存策略：默认6个月（180天），超期自动清理
    3. 日志防篡改：SHA-256 哈希链 + HMAC-SHA256 签名
    """

    def __init__(self):
        self.storage = get_storage()
        self._signing_key = _load_signing_key()
        self._lock = threading.Lock()
        # 启动时按留存策略清理过期日志（尽力而为，不影响启动）
        try:
            self.apply_retention_policy()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 日志创建（含哈希链 + 签名 + 等保2.0要素）
    # ------------------------------------------------------------------

    def create_log(self, user_id: str, user_role: str, agent_id: str,
                   action_type: str, action_details: Dict[str, Any] = {},
                   risk_level: RiskLevel = RiskLevel.NONE,
                   detection_result: Optional[DetectionResult] = None,
                   tool_call_result: Optional[ToolRiskResult] = None,
                   plugin_scan_result: Optional[PluginScanResult] = None,
                   approval_status: Optional[str] = None,
                   is_blocked: bool = False,
                   blocking_reason: Optional[str] = None,
                   session_id: str = "",
                   think_text: str = "",
                   return_value: str = "",
                   source_ip: str = "",
                   operation_subject: str = "",
                   operation_object: str = "",
                   operation_result: str = "") -> AuditLog:

        log_id = str(uuid.uuid4())
        timestamp = datetime.now()

        # 来源IP：优先显式传入，否则取当前请求上下文
        if not source_ip:
            source_ip = get_current_source_ip()

        # ---- 等保2.0要素自动推导 ----
        if not operation_subject:
            operation_subject = f"{user_id}/{user_role}"
        if not operation_object:
            operation_object = (action_details or {}).get("tool_name", "") or \
                               (action_details or {}).get("url", "") or \
                               (action_details or {}).get("input", "")
        if not operation_result:
            if is_blocked:
                operation_result = "blocked"
            elif approval_status in ("pending", "approved"):
                operation_result = "approved"
            else:
                operation_result = "success"

        # ---- 哈希链：链接上一条日志的哈希 ----
        with self._lock:
            last = self.storage.get_last_audit_log()
            prev_hash = _parse_extra(last).get("log_hash", "") if last else ""
            # 构造待哈希内容（规范序列化）
            content = json.dumps({
                "log_id": log_id,
                "timestamp": timestamp.isoformat(),
                "user_id": user_id,
                "user_role": user_role,
                "agent_id": agent_id,
                "action_type": action_type,
                "action_details": action_details or {},
                "risk_level": risk_level.value if isinstance(risk_level, RiskLevel) else str(risk_level),
                "is_blocked": is_blocked,
                "blocking_reason": blocking_reason or "",
                "session_id": session_id,
                "think_text": think_text,
                "return_value": return_value,
                "source_ip": source_ip,
                "operation_subject": operation_subject,
                "operation_object": operation_object,
                "operation_result": operation_result,
                "prev_hash": prev_hash,
            }, sort_keys=True, ensure_ascii=False, default=str)
            log_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
            signature = hmac.new(self._signing_key, log_hash.encode(), hashlib.sha256).hexdigest()

            extra_data = {
                "session_id": session_id,
                "think_text": think_text,
                "return_value": return_value,
                "source_ip": source_ip,
                "operation_subject": operation_subject,
                "operation_object": operation_object,
                "operation_result": operation_result,
                "log_hash": log_hash,
                "prev_hash": prev_hash,
                "signature": signature,
            }

            log = AuditLog(
                log_id=log_id,
                timestamp=timestamp,
                user_id=user_id,
                user_role=user_role,
                agent_id=agent_id,
                action_type=action_type,
                action_details=action_details or {},
                risk_level=risk_level,
                detection_result=detection_result,
                tool_call_result=tool_call_result,
                plugin_scan_result=plugin_scan_result,
                approval_status=approval_status,
                is_blocked=is_blocked,
                blocking_reason=blocking_reason,
                session_id=session_id,
                think_text=think_text,
                return_value=return_value,
                source_ip=source_ip,
                operation_subject=operation_subject,
                operation_object=operation_object,
                operation_result=operation_result,
                log_hash=log_hash,
                prev_hash=prev_hash,
                signature=signature,
            )

            self.storage.save_audit_log({
                "id": log_id,
                "timestamp": log.timestamp.isoformat(),
                "user_id": user_id,
                "user_role": user_role,
                "agent_id": agent_id,
                "action_type": action_type,
                "action_details": action_details or {},
                "risk_level": risk_level.value if isinstance(risk_level, RiskLevel) else str(risk_level),
                "detection_result": detection_result.model_dump() if detection_result else {},
                "tool_call_result": tool_call_result.model_dump() if tool_call_result else {},
                "approval_status": approval_status or "",
                "is_blocked": is_blocked,
                "blocking_reason": blocking_reason or "",
                "extra_data": extra_data,
            })

        return log

    # ------------------------------------------------------------------
    # 日志留存策略（等保2.0三级：默认6个月）
    # ------------------------------------------------------------------

    def apply_retention_policy(self, days: int = AUDIT_RETENTION_DAYS) -> int:
        """按留存策略清理超期日志，返回删除条数"""
        return self.storage.delete_audit_logs_older_than(days)

    # ------------------------------------------------------------------
    # 日志防篡改校验（哈希链 + 签名）
    # ------------------------------------------------------------------

    def verify_chain(self) -> Dict[str, Any]:
        """校验整条审计日志哈希链与签名完整性

        返回:
            {
                "ok": bool,             # 是否全部通过
                "total": int,           # 总日志数
                "checked": int,         # 参与校验（有哈希）的日志数
                "legacy": int,          # 无哈希的旧记录数（不参与校验）
                "tampered": [...],      # 被篡改的记录
            }
        """
        logs = self.storage.get_audit_logs_ordered()
        prev_hash = ""
        checked = 0
        legacy = 0
        tampered: List[Dict[str, Any]] = []

        for d in logs:
            extra = _parse_extra(d)
            stored_hash = extra.get("log_hash", "")
            if not stored_hash:
                legacy += 1
                continue

            # 重算哈希
            recomputed = hashlib.sha256(
                _canonical_content(d, prev_hash).encode("utf-8")
            ).hexdigest()
            if recomputed != stored_hash:
                tampered.append({
                    "log_id": d.get("log_id", ""),
                    "type": "hash_mismatch",
                    "expected": recomputed,
                    "found": stored_hash,
                })

            # 校验签名
            stored_sig = extra.get("signature", "")
            if stored_sig:
                expected_sig = hmac.new(
                    self._signing_key, stored_hash.encode(), hashlib.sha256
                ).hexdigest()
                if not hmac.compare_digest(expected_sig, stored_sig):
                    tampered.append({
                        "log_id": d.get("log_id", ""),
                        "type": "signature_mismatch",
                    })

            prev_hash = stored_hash
            checked += 1

        return {
            "ok": len(tampered) == 0,
            "total": len(logs),
            "checked": checked,
            "legacy": legacy,
            "tampered": tampered,
            "retention_days": AUDIT_RETENTION_DAYS,
        }

    def get_chain_head(self) -> Dict[str, str]:
        """返回哈希链头（最新日志哈希），用于审计追溯"""
        last = self.storage.get_last_audit_log()
        if not last:
            return {"log_hash": "", "signature": "", "timestamp": ""}
        extra = _parse_extra(last)
        return {
            "log_hash": extra.get("log_hash", ""),
            "signature": extra.get("signature", ""),
            "timestamp": last.get("timestamp", ""),
            "log_id": last.get("log_id", ""),
        }

    # ------------------------------------------------------------------
    # 查询
    # ------------------------------------------------------------------

    def get_log(self, log_id: str) -> Optional[AuditLog]:
        data = self.storage.get_audit_log_by_id(log_id)
        return self._dict_to_log(data) if data else None

    def get_logs_by_user(self, user_id: str) -> List[AuditLog]:
        results = self.storage.search_audit_logs({"user_id": user_id}, limit=1000)
        return [self._dict_to_log(d) for d in results]

    def get_logs_by_agent(self, agent_id: str) -> List[AuditLog]:
        results = self.storage.search_audit_logs({"agent_id": agent_id}, limit=1000)
        return [self._dict_to_log(d) for d in results]

    def get_recent_logs(self, limit: int = 100) -> List[AuditLog]:
        results = self.storage.get_audit_logs_recent(limit=limit)
        return [self._dict_to_log(d) for d in results]

    def get_logs_page(self, page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        """分页查询审计日志（按时间倒序），返回总数与分页数据"""
        total = self.storage.count_audit_logs()
        results = self.storage.get_audit_logs_page(page=page, page_size=page_size)
        total_pages = (total + page_size - 1) // page_size if page_size > 0 else 0
        return {
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "logs": [self._dict_to_log(d) for d in results],
        }

    def search_logs(self, user_id: Optional[str] = None,
                    agent_id: Optional[str] = None,
                    risk_level: Optional[RiskLevel] = None,
                    action_type: Optional[str] = None,
                    start_time: Optional[datetime] = None,
                    end_time: Optional[datetime] = None,
                    is_blocked: Optional[bool] = None) -> List[AuditLog]:

        filters = {}
        if user_id:
            filters["user_id"] = user_id
        if agent_id:
            filters["agent_id"] = agent_id
        if risk_level:
            filters["risk_level"] = risk_level.value
        if action_type:
            filters["action_type"] = action_type
        if is_blocked is not None:
            filters["is_blocked"] = is_blocked

        results = self.storage.search_audit_logs(filters, limit=1000)

        # 时间过滤在 Python 中完成（start_time/end_time 暂不入库）
        logs = []
        for data in results:
            log = self._dict_to_log(data)
            if start_time and log.timestamp < start_time:
                continue
            if end_time and log.timestamp > end_time:
                continue
            logs.append(log)

        logs.sort(key=lambda x: x.timestamp, reverse=True)
        return logs

    def export_logs(self, logs: List[AuditLog]) -> str:
        export_lines = []
        export_lines.append("=" * 80)
        export_lines.append("政企大模型智能体安全审计报告")
        export_lines.append(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        export_lines.append(f"记录总数: {len(logs)}")
        export_lines.append("=" * 80)

        for i, log in enumerate(logs, 1):
            export_lines.append(f"\n--- 记录 #{i} ---")
            export_lines.append(f"日志ID: {log.log_id}")
            export_lines.append(f"时间: {log.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
            export_lines.append(f"用户ID: {log.user_id}")
            export_lines.append(f"用户角色: {log.user_role}")
            export_lines.append(f"智能体ID: {log.agent_id}")
            export_lines.append(f"操作类型: {log.action_type}")
            export_lines.append(f"会话ID: {log.session_id}")
            export_lines.append(f"来源IP: {log.source_ip or '-'}")
            export_lines.append(f"操作主体: {log.operation_subject or '-'}")
            export_lines.append(f"操作客体: {log.operation_object or '-'}")
            export_lines.append(f"操作结果: {log.operation_result or '-'}")
            if hasattr(log.risk_level, 'value'):
                export_lines.append(f"风险等级: {log.risk_level.value}")
            else:
                export_lines.append(f"风险等级: {log.risk_level}")
            export_lines.append(f"是否阻断: {'是' if log.is_blocked else '否'}")
            if log.blocking_reason:
                export_lines.append(f"阻断原因: {log.blocking_reason}")
            if log.approval_status:
                export_lines.append(f"审批状态: {log.approval_status}")
            if log.think_text:
                export_lines.append(f"Think推理: {log.think_text[:200]}")
            export_lines.append(f"日志哈希: {log.log_hash[:32]}...")
            export_lines.append(f"哈希签名: {log.signature[:32]}...")

        export_lines.append("\n" + "=" * 80)
        export_lines.append("报告结束")

        return "\n".join(export_lines)

    @staticmethod
    def _dict_to_log(data: Dict[str, Any]) -> AuditLog:
        try:
            extra = _parse_extra(data)

            log = AuditLog(
                log_id=data.get("log_id", ""),
                timestamp=datetime.fromisoformat(data.get("timestamp", "")) if data.get("timestamp") else datetime.now(),
                user_id=data.get("user_id", ""),
                user_role=data.get("user_role", "user"),
                agent_id=data.get("agent_id", ""),
                action_type=data.get("action_type", ""),
                action_details=data.get("action_details", {}) or {},
                risk_level=RiskLevel(data.get("risk_level", "none")),
                approval_status=data.get("approval_status"),
                is_blocked=data.get("is_blocked", False),
                blocking_reason=data.get("blocking_reason"),
                session_id=extra.get("session_id", "") or data.get("session_id", ""),
                think_text=extra.get("think_text", "") or data.get("think_text", ""),
                return_value=extra.get("return_value", "") or data.get("return_value", ""),
                source_ip=extra.get("source_ip", "") or data.get("source_ip", ""),
                operation_subject=extra.get("operation_subject", "") or data.get("operation_subject", ""),
                operation_object=extra.get("operation_object", "") or data.get("operation_object", ""),
                operation_result=extra.get("operation_result", "") or data.get("operation_result", ""),
                log_hash=extra.get("log_hash", "") or data.get("log_hash", ""),
                prev_hash=extra.get("prev_hash", "") or data.get("prev_hash", ""),
                signature=extra.get("signature", "") or data.get("signature", ""),
            )
            return log
        except Exception:
            return AuditLog(
                log_id=data.get("log_id", "") or str(uuid.uuid4()),
                timestamp=datetime.now(),
                user_id=data.get("user_id", ""),
                agent_id=data.get("agent_id", ""),
                action_type=data.get("action_type", ""),
            )
