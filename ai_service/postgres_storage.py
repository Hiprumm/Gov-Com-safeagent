# -*- coding: utf-8 -*-
"""PostgreSQL 存储后端（可选）

面向真实政企部署：解决单文件 SQLite 在**并发写入、高可用、容量、集中运维**上的瓶颈。
通过 `STORAGE_BACKEND=postgres` 启用，与 `storage.Storage`（SQLite）实现同一套公开方法，
上层调用方（main/auth/gov_agent/approval_engine/audit_logger…）**无需改动**。

差异处理：
- 占位符 `%s`；布尔列用 BOOLEAN；审计表增加 `seq BIGSERIAL` 以保证确定性插入序（对应 SQLite 的 rowid）；
- upsert 用 `ON CONFLICT ... DO UPDATE`；自增主键用 BIGSERIAL + `RETURNING id`。

依赖：`psycopg[binary]`（psycopg 3）。未安装时本模块可被导入，但实例化会给出明确报错。
"""
import json
import uuid
from datetime import datetime, timedelta
from threading import Lock
from typing import Any, Dict, List, Optional
from contextlib import contextmanager

# psycopg 为可选依赖：缺失时不影响 SQLite 路径
try:
    import psycopg
    from psycopg.rows import dict_row
    from psycopg.errors import UniqueViolation
    PSYCOPG_AVAILABLE = True
except Exception:  # pragma: no cover
    psycopg = None
    dict_row = None
    UniqueViolation = Exception
    PSYCOPG_AVAILABLE = False


def _build_dsn() -> str:
    try:
        from config import settings
    except Exception:
        settings = None
    dsn = str(getattr(settings, "POSTGRES_DSN", "") or "").strip()
    if dsn:
        return dsn
    return (
        f"host={getattr(settings, 'POSTGRES_HOST', 'localhost')} "
        f"port={int(getattr(settings, 'POSTGRES_PORT', 5432) or 5432)} "
        f"dbname={getattr(settings, 'POSTGRES_DB', 'safeagent')} "
        f"user={getattr(settings, 'POSTGRES_USER', 'safeagent')} "
        f"password={getattr(settings, 'POSTGRES_PASSWORD', '')}"
    )


_SCHEMA_STATEMENTS = [
    """CREATE TABLE IF NOT EXISTS audit_logs (
        seq BIGSERIAL,
        log_id TEXT PRIMARY KEY,
        timestamp TEXT NOT NULL,
        user_id TEXT,
        user_role TEXT,
        agent_id TEXT,
        action_type TEXT,
        action_details TEXT,
        risk_level TEXT,
        detection_result TEXT,
        tool_call_result TEXT,
        approval_status TEXT,
        is_blocked BOOLEAN DEFAULT FALSE,
        blocking_reason TEXT,
        extra_data TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS approval_requests (
        request_id TEXT PRIMARY KEY,
        tool_name TEXT NOT NULL,
        tool_args TEXT,
        risk_level TEXT NOT NULL,
        requester_id TEXT,
        requester_role TEXT DEFAULT 'user',
        required_role TEXT DEFAULT 'admin',
        approver_id TEXT,
        approver_role TEXT,
        status TEXT DEFAULT 'pending',
        reason TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT
    )""",
    """CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        user_id TEXT,
        title TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        message_count INTEGER DEFAULT 0
    )""",
    """CREATE TABLE IF NOT EXISTS conversation_history (
        id BIGSERIAL PRIMARY KEY,
        session_id TEXT NOT NULL,
        role TEXT NOT NULL,
        content TEXT,
        type TEXT DEFAULT 'text',
        timestamp TEXT NOT NULL,
        FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
    )""",
    """CREATE TABLE IF NOT EXISTS notifications (
        id BIGSERIAL PRIMARY KEY,
        type TEXT NOT NULL,
        title TEXT NOT NULL,
        message TEXT,
        level TEXT DEFAULT 'info',
        read BOOLEAN DEFAULT FALSE,
        created_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS policy_config (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS sys_departments (
        id BIGSERIAL PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        created_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS sys_users (
        username TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        display_name TEXT NOT NULL,
        role TEXT NOT NULL,
        department TEXT DEFAULT '',
        position TEXT DEFAULT '',
        status TEXT DEFAULT 'active',
        note TEXT DEFAULT '',
        totp_secret TEXT DEFAULT '',
        mfa_enabled BOOLEAN DEFAULT FALSE,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_audit_risk ON audit_logs(risk_level)",
    "CREATE INDEX IF NOT EXISTS idx_approval_status ON approval_requests(status)",
    "CREATE INDEX IF NOT EXISTS idx_conv_session ON conversation_history(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_updated ON sessions(updated_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications(created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_users_role ON sys_users(role)",
]


class PostgresStorage:
    """PostgreSQL 存储后端（与 storage.Storage 同一公开接口）。"""

    def __init__(self, dsn: Optional[str] = None):
        if not PSYCOPG_AVAILABLE:
            raise RuntimeError(
                "已选择 PostgreSQL 存储后端，但未安装 psycopg。请先安装：pip install 'psycopg[binary]'"
            )
        self._lock = Lock()
        self._dsn = dsn or _build_dsn()
        self._init_db()

    # ------------------------------------------------------------------
    # 基础设施
    # ------------------------------------------------------------------
    @property
    def db_path(self) -> Optional[str]:
        """PostgreSQL 无文件路径概念，返回 None。"""
        return None

    @property
    def is_file_backed(self) -> bool:
        return False

    @contextmanager
    def _get_conn(self):
        conn = psycopg.connect(self._dsn, row_factory=dict_row)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self):
        with self._get_conn() as conn:
            with conn.cursor() as cur:
                for stmt in _SCHEMA_STATEMENTS:
                    cur.execute(stmt)
                # 迁移：为历史库补充 MFA(TOTP) 列（幂等）
                cur.execute("ALTER TABLE sys_users ADD COLUMN IF NOT EXISTS totp_secret TEXT DEFAULT ''")
                cur.execute("ALTER TABLE sys_users ADD COLUMN IF NOT EXISTS mfa_enabled BOOLEAN DEFAULT FALSE")

    @staticmethod
    def _row_to_dict(row: Any) -> Dict[str, Any]:
        """与 SQLite 后端保持一致的 JSON 列解析（额外丢弃 PG 专用的 seq 列）。"""
        d = dict(row)
        d.pop("seq", None)
        for key in ("action_details", "detection_result", "tool_call_result", "tool_args", "extra_data"):
            if key in d and isinstance(d[key], str):
                try:
                    d[key] = json.loads(d[key])
                except (json.JSONDecodeError, TypeError):
                    pass
        d["is_blocked"] = bool(d.get("is_blocked"))
        return d

    # ==================== 审计日志 ====================
    def save_audit_log(self, log_data: Dict[str, Any]):
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """INSERT INTO audit_logs
                    (log_id, timestamp, user_id, user_role, agent_id, action_type,
                     action_details, risk_level, detection_result, tool_call_result,
                     approval_status, is_blocked, blocking_reason, extra_data)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                    (
                        log_data.get("id", log_data.get("log_id", "")),
                        log_data.get("timestamp", datetime.now().isoformat()),
                        log_data.get("user_id", ""),
                        log_data.get("user_role", "user"),
                        log_data.get("agent_id", ""),
                        log_data.get("action_type", ""),
                        json.dumps(log_data.get("action_details", {}), ensure_ascii=False),
                        log_data.get("risk_level", "none"),
                        json.dumps(log_data.get("detection_result", {}), ensure_ascii=False),
                        json.dumps(log_data.get("tool_call_result", {}), ensure_ascii=False),
                        log_data.get("approval_status", ""),
                        bool(log_data.get("is_blocked")),
                        log_data.get("blocking_reason", ""),
                        json.dumps(log_data.get("extra_data", {}), ensure_ascii=False),
                    ),
                )

    def get_audit_logs_recent(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT %s", (limit,)
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_audit_logs_page(self, page: int = 1, page_size: int = 20) -> List[Dict[str, Any]]:
        offset = max(0, (page - 1) * page_size)
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_logs ORDER BY timestamp DESC, seq DESC LIMIT %s OFFSET %s",
                (page_size, offset),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def count_audit_logs(self) -> int:
        with self._get_conn() as conn:
            row = conn.execute("SELECT COUNT(*) AS c FROM audit_logs").fetchone()
        return int(row["c"]) if row else 0

    def count_approvals(self) -> int:
        with self._get_conn() as conn:
            row = conn.execute("SELECT COUNT(*) AS c FROM approval_requests").fetchone()
        return int(row["c"]) if row else 0

    def get_audit_log_by_id(self, log_id: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM audit_logs WHERE log_id = %s", (log_id,)).fetchone()
        return self._row_to_dict(row) if row else None

    def search_audit_logs(self, filters: Dict[str, Any], limit: int = 50) -> List[Dict[str, Any]]:
        query = "SELECT * FROM audit_logs WHERE 1=1"
        params: List[Any] = []
        if filters.get("user_id"):
            query += " AND user_id = %s"; params.append(filters["user_id"])
        if filters.get("agent_id"):
            query += " AND agent_id = %s"; params.append(filters["agent_id"])
        if filters.get("risk_level"):
            query += " AND risk_level = %s"; params.append(filters["risk_level"])
        if filters.get("action_type"):
            query += " AND action_type = %s"; params.append(filters["action_type"])
        if filters.get("is_blocked") is not None:
            query += " AND is_blocked = %s"; params.append(bool(filters["is_blocked"]))
        query += " ORDER BY timestamp DESC LIMIT %s"
        params.append(limit)
        with self._get_conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def delete_audit_logs_older_than(self, days: int) -> int:
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute("DELETE FROM audit_logs WHERE timestamp < %s", (cutoff,))
                return cur.rowcount

    def get_last_audit_log(self) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM audit_logs ORDER BY timestamp DESC, seq DESC LIMIT 1"
            ).fetchone()
        return self._row_to_dict(row) if row else None

    def get_audit_logs_ordered(self, limit: int = 100000) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_logs ORDER BY timestamp ASC, seq ASC LIMIT %s", (limit,)
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_audit_logs_before(self, cutoff_iso: str, limit: int = 200000) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_logs WHERE timestamp < %s ORDER BY timestamp ASC, seq ASC LIMIT %s",
                (cutoff_iso, limit),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ==================== 审批记录 ====================
    def create_approval(self, approval_data: Dict[str, Any]):
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """INSERT INTO approval_requests
                    (request_id, tool_name, tool_args, risk_level, requester_id, requester_role,
                     required_role, status, reason, created_at, updated_at)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                    ON CONFLICT(request_id) DO UPDATE SET
                        tool_name = EXCLUDED.tool_name, tool_args = EXCLUDED.tool_args,
                        risk_level = EXCLUDED.risk_level, requester_id = EXCLUDED.requester_id,
                        requester_role = EXCLUDED.requester_role, required_role = EXCLUDED.required_role,
                        status = EXCLUDED.status, reason = EXCLUDED.reason,
                        updated_at = EXCLUDED.updated_at""",
                    (
                        approval_data.get("request_id", ""),
                        approval_data.get("tool_name", ""),
                        json.dumps(approval_data.get("tool_args", {}), ensure_ascii=False),
                        approval_data.get("risk_level", "low"),
                        approval_data.get("requester_id", ""),
                        approval_data.get("requester_role", "user"),
                        approval_data.get("required_role", "admin"),
                        approval_data.get("status", "pending"),
                        approval_data.get("reason", ""),
                        approval_data.get("created_at", datetime.now().isoformat()),
                        approval_data.get("updated_at", datetime.now().isoformat()),
                    ),
                )

    def get_approval(self, request_id: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM approval_requests WHERE request_id = %s", (request_id,)).fetchone()
        return self._row_to_dict(row) if row else None

    def update_approval(self, request_id: str, status: str, approver_id: str = "",
                        approver_role: str = "", reason: str = ""):
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """UPDATE approval_requests
                    SET status = %s, approver_id = %s, approver_role = %s, reason = %s, updated_at = %s
                    WHERE request_id = %s""",
                    (status, approver_id, approver_role, reason, datetime.now().isoformat(), request_id),
                )

    def list_pending_approvals(self) -> list:
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM approval_requests WHERE status = 'pending' ORDER BY created_at DESC"
                ).fetchall()
                return [self._row_to_dict(r) for r in rows]

    def list_recent_approvals(self, limit: int = 50) -> list:
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM approval_requests ORDER BY updated_at DESC LIMIT %s", (limit,)
                ).fetchall()
                return [self._row_to_dict(r) for r in rows]

    # ==================== 会话管理 ====================
    def create_session(self, user_id: str = None) -> str:
        session_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    "INSERT INTO sessions (session_id, user_id, created_at, updated_at) VALUES (%s,%s,%s,%s)",
                    (session_id, user_id, now, now),
                )
        return session_id

    def ensure_session(self, session_id: str, user_id: str = None) -> str:
        if not session_id:
            return self.create_session(user_id)
        now = datetime.now().isoformat()
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    "INSERT INTO sessions (session_id, user_id, created_at, updated_at) VALUES (%s,%s,%s,%s) ON CONFLICT (session_id) DO NOTHING",
                    (session_id, user_id, now, now),
                )
        return session_id

    def add_message(self, session_id: str, role: str, content: str, message_type: str = "text"):
        now = datetime.now().isoformat()
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    "INSERT INTO conversation_history (session_id, role, content, type, timestamp) VALUES (%s,%s,%s,%s,%s)",
                    (session_id, role, content, message_type, now),
                )
                conn.execute(
                    "UPDATE sessions SET updated_at = %s, message_count = message_count + 1 WHERE session_id = %s",
                    (now, session_id),
                )

    def get_history(self, session_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT id, role, content, type, timestamp FROM conversation_history WHERE session_id = %s ORDER BY id ASC LIMIT %s",
                (session_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    def list_sessions(self, user_id: str = None) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            if user_id:
                rows = conn.execute(
                    "SELECT session_id, title, created_at, updated_at, message_count FROM sessions WHERE message_count > 0 AND user_id = %s ORDER BY updated_at DESC",
                    (user_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT session_id, title, created_at, updated_at, message_count FROM sessions WHERE message_count > 0 ORDER BY updated_at DESC"
                ).fetchall()
        return [dict(r) for r in rows]

    def cleanup_empty_sessions(self) -> int:
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute("DELETE FROM sessions WHERE message_count = 0")
                return cur.rowcount

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT session_id, user_id, title, created_at, updated_at, message_count FROM sessions WHERE session_id = %s",
                (session_id,),
            ).fetchone()
        return dict(row) if row else None

    def clear_session(self, session_id: str):
        with self._lock:
            with self._get_conn() as conn:
                conn.execute("DELETE FROM conversation_history WHERE session_id = %s", (session_id,))
                conn.execute(
                    "UPDATE sessions SET updated_at = %s, message_count = 0 WHERE session_id = %s",
                    (datetime.now().isoformat(), session_id),
                )

    def truncate_messages_from(self, session_id: str, message_id: int) -> int:
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute(
                    "DELETE FROM conversation_history WHERE session_id = %s AND id >= %s",
                    (session_id, message_id),
                )
                remaining = conn.execute(
                    "SELECT COUNT(*) AS c FROM conversation_history WHERE session_id = %s", (session_id,)
                ).fetchone()["c"]
                conn.execute(
                    "UPDATE sessions SET updated_at = %s, message_count = %s WHERE session_id = %s",
                    (datetime.now().isoformat(), int(remaining), session_id),
                )
                return cur.rowcount

    def delete_session(self, session_id: str):
        with self._lock:
            with self._get_conn() as conn:
                conn.execute("DELETE FROM sessions WHERE session_id = %s", (session_id,))

    def rename_session(self, session_id: str, title: str) -> bool:
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute(
                    "UPDATE sessions SET title = %s, updated_at = updated_at WHERE session_id = %s",
                    (title.strip() or None, session_id),
                )
                return cur.rowcount > 0

    # ==================== 站内通知 ====================
    def add_notification(self, type_: str, title: str, message: str = "", level: str = "info") -> Optional[int]:
        with self._lock:
            with self._get_conn() as conn:
                row = conn.execute(
                    "INSERT INTO notifications (type, title, message, level, created_at) VALUES (%s,%s,%s,%s,%s) RETURNING id",
                    (type_, title, message or "", level, datetime.now().isoformat()),
                ).fetchone()
                return int(row["id"]) if row else None

    def list_notifications(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM notifications ORDER BY id DESC LIMIT %s", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def count_unread_notifications(self) -> int:
        with self._get_conn() as conn:
            row = conn.execute("SELECT COUNT(*) AS c FROM notifications WHERE read = FALSE").fetchone()
        return int(row["c"]) if row else 0

    def mark_notifications_read(self, notif_id: Optional[int] = None):
        with self._lock:
            with self._get_conn() as conn:
                if notif_id is not None:
                    conn.execute("UPDATE notifications SET read = TRUE WHERE id = %s", (notif_id,))
                else:
                    conn.execute("UPDATE notifications SET read = TRUE WHERE read = FALSE")

    def clear_notifications(self):
        with self._lock:
            with self._get_conn() as conn:
                conn.execute("DELETE FROM notifications")

    # ==================== 通用键值设置 ====================
    def get_setting(self, key: str, default: Any = None) -> Any:
        with self._get_conn() as conn:
            row = conn.execute("SELECT value FROM policy_config WHERE key = %s", (key,)).fetchone()
        if not row:
            return default
        try:
            return json.loads(row["value"])
        except (ValueError, TypeError):
            return row["value"]

    def set_setting(self, key: str, value: Any):
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """INSERT INTO policy_config (key, value, updated_at) VALUES (%s,%s,%s)
                       ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at""",
                    (key, json.dumps(value, ensure_ascii=False), datetime.now().isoformat()),
                )

    # ==================== 安全策略配置 ====================
    def get_policy_config(self) -> Dict[str, str]:
        with self._get_conn() as conn:
            rows = conn.execute("SELECT key, value FROM policy_config").fetchall()
        return {r["key"]: r["value"] for r in rows}

    def update_policy_config(self, items: Dict[str, Any]) -> None:
        now = datetime.now().isoformat()
        with self._lock:
            with self._get_conn() as conn:
                for key, value in items.items():
                    conn.execute(
                        """INSERT INTO policy_config (key, value, updated_at) VALUES (%s,%s,%s)
                           ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at""",
                        (key, json.dumps(value, ensure_ascii=False), now),
                    )

    # ==================== 组织 / 用户管理 ====================
    def user_exists(self, username: str) -> bool:
        with self._get_conn() as conn:
            return conn.execute("SELECT 1 FROM sys_users WHERE username = %s", (username,)).fetchone() is not None

    def count_users(self) -> int:
        with self._get_conn() as conn:
            row = conn.execute("SELECT COUNT(*) AS c FROM sys_users").fetchone()
        return int(row["c"]) if row else 0

    def upsert_user(self, username: str, password_hash: str, salt: str, display_name: str,
                    role: str, department: str = "", position: str = "",
                    status: str = "active", note: str = "") -> None:
        now = datetime.now().isoformat()
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """INSERT INTO sys_users (username, password_hash, salt, display_name, role,
                                               department, position, status, note, created_at, updated_at)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                       ON CONFLICT (username) DO UPDATE SET
                         password_hash = EXCLUDED.password_hash, salt = EXCLUDED.salt,
                         display_name = EXCLUDED.display_name, role = EXCLUDED.role,
                         department = EXCLUDED.department, position = EXCLUDED.position,
                         status = EXCLUDED.status, note = EXCLUDED.note,
                         updated_at = EXCLUDED.updated_at""",
                    (username, password_hash, salt, display_name, role, department,
                     position, status, note, now, now),
                )

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM sys_users WHERE username = %s", (username,)).fetchone()
        return dict(row) if row else None

    def get_user_password(self, username: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT username, password_hash, salt, display_name, role, department, position, status FROM sys_users WHERE username = %s",
                (username,),
            ).fetchone()
        return dict(row) if row else None

    def list_users(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT username, display_name, role, department, position, status, note, mfa_enabled, created_at, updated_at FROM sys_users ORDER BY role, username"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_user_mfa(self, username: str) -> Dict[str, Any]:
        """返回用户的 MFA 信息（totp_secret 在库中为密文，此处透明解密）。"""
        from security.secret_box import decrypt_secret
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT totp_secret, mfa_enabled FROM sys_users WHERE username = %s", (username,)
            ).fetchone()
        if not row:
            return {"totp_secret": "", "mfa_enabled": False}
        return {"totp_secret": decrypt_secret(row["totp_secret"] or ""),
                "mfa_enabled": bool(row["mfa_enabled"])}

    def set_user_mfa(self, username: str, secret: str, enabled: bool) -> bool:
        """设置用户的 TOTP 密钥与启用状态（入库前加密）"""
        from security.secret_box import encrypt_secret
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute(
                    "UPDATE sys_users SET totp_secret = %s, mfa_enabled = %s, updated_at = %s WHERE username = %s",
                    (encrypt_secret(secret or ""), bool(enabled),
                     datetime.now().isoformat(), username),
                )
                return cur.rowcount > 0

    def update_user_profile(self, username: str, display_name: str = None, role: str = None,
                            department: str = None, position: str = None,
                            status: str = None, note: str = None) -> bool:
        sets, vals = [], []
        if display_name is not None: sets.append("display_name = %s"); vals.append(display_name)
        if role is not None: sets.append("role = %s"); vals.append(role)
        if department is not None: sets.append("department = %s"); vals.append(department)
        if position is not None: sets.append("position = %s"); vals.append(position)
        if status is not None: sets.append("status = %s"); vals.append(status)
        if note is not None: sets.append("note = %s"); vals.append(note)
        if not sets:
            return False
        sets.append("updated_at = %s")
        vals.append(datetime.now().isoformat())
        vals.append(username)
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute(f"UPDATE sys_users SET {', '.join(sets)} WHERE username = %s", vals)
                return cur.rowcount > 0

    def update_user_password(self, username: str, password_hash: str, salt: str) -> bool:
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute(
                    "UPDATE sys_users SET password_hash = %s, salt = %s, updated_at = %s WHERE username = %s",
                    (password_hash, salt, datetime.now().isoformat(), username),
                )
                return cur.rowcount > 0

    def delete_user(self, username: str) -> bool:
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute("DELETE FROM sys_users WHERE username = %s", (username,))
                return cur.rowcount > 0

    # ---- 部门 ----
    def list_departments(self) -> List[str]:
        with self._get_conn() as conn:
            rows = conn.execute("SELECT name FROM sys_departments ORDER BY id").fetchall()
        return [r["name"] for r in rows]

    def add_department(self, name: str) -> bool:
        now = datetime.now().isoformat()
        with self._lock:
            with self._get_conn() as conn:
                try:
                    conn.execute("INSERT INTO sys_departments (name, created_at) VALUES (%s,%s)",
                                 (name.strip(), now))
                    return True
                except UniqueViolation:
                    return False

    def remove_department(self, name: str) -> bool:
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute("DELETE FROM sys_departments WHERE name = %s", (name,))
                return cur.rowcount > 0
