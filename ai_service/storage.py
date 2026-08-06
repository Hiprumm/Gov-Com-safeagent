"""
SQLite 持久化存储模块
替换原有的内存 dict 存储，提供审计日志、审批记录、会话历史的持久化。
"""
import sqlite3
import json
import os
from datetime import datetime
from typing import Dict, Any, List, Optional
from threading import Lock
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "safeagent.db")


class Storage:
    """统一持久化存储，基于 SQLite"""

    def __init__(self, db_path: str = DB_PATH):
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._db_path = db_path
        self._lock = Lock()
        self._init_db()

    @contextmanager
    def _get_conn(self):
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
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
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS audit_logs (
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
                    is_blocked INTEGER DEFAULT 0,
                    blocking_reason TEXT,
                    extra_data TEXT
                );

                CREATE TABLE IF NOT EXISTS approval_requests (
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
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    title TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    message_count INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS conversation_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT,
                    type TEXT DEFAULT 'text',
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
                );

                CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
                CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);
                CREATE INDEX IF NOT EXISTS idx_audit_risk ON audit_logs(risk_level);
                CREATE INDEX IF NOT EXISTS idx_approval_status ON approval_requests(status);
                CREATE INDEX IF NOT EXISTS idx_conv_session ON conversation_history(session_id);
                CREATE INDEX IF NOT EXISTS idx_sessions_updated ON sessions(updated_at DESC);
            """)

    # ==================== 审计日志 ====================

    def save_audit_log(self, log_data: Dict[str, Any]):
        with self._lock:
            with self._get_conn() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO audit_logs
                    (log_id, timestamp, user_id, user_role, agent_id,
                     action_type, action_details, risk_level,
                     detection_result, tool_call_result, approval_status,
                     is_blocked, blocking_reason, extra_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
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
                    1 if log_data.get("is_blocked") else 0,
                    log_data.get("blocking_reason", ""),
                    json.dumps(log_data.get("extra_data", {}), ensure_ascii=False),
                ))

    def get_audit_logs_recent(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_audit_log_by_id(self, log_id: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM audit_logs WHERE log_id = ?", (log_id,)
            ).fetchone()
        return self._row_to_dict(row) if row else None

    def search_audit_logs(self, filters: Dict[str, Any], limit: int = 50) -> List[Dict[str, Any]]:
        query = "SELECT * FROM audit_logs WHERE 1=1"
        params = []
        if filters.get("user_id"):
            query += " AND user_id = ?"
            params.append(filters["user_id"])
        if filters.get("agent_id"):
            query += " AND agent_id = ?"
            params.append(filters["agent_id"])
        if filters.get("risk_level"):
            query += " AND risk_level = ?"
            params.append(filters["risk_level"])
        if filters.get("action_type"):
            query += " AND action_type = ?"
            params.append(filters["action_type"])
        if filters.get("is_blocked") is not None:
            query += " AND is_blocked = ?"
            params.append(1 if filters["is_blocked"] else 0)
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        with self._get_conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ==================== 审批记录 ====================

    def create_approval(self, approval_data: Dict[str, Any]):
        with self._lock:
            with self._get_conn() as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO approval_requests
                    (request_id, tool_name, tool_args, risk_level,
                     requester_id, requester_role, required_role,
                     status, reason, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
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
                ))

    def get_approval(self, request_id: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM approval_requests WHERE request_id = ?", (request_id,)
            ).fetchone()
        return self._row_to_dict(row) if row else None

    def update_approval(self, request_id: str, status: str, approver_id: str = "",
                        approver_role: str = "", reason: str = ""):
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """UPDATE approvals
                    SET status = ?, approver_id = ?, approver_role = ?,
                        reason = ?, updated_at = ?
                    WHERE request_id = ?
                """, (status, approver_id, approver_role, reason,
                      datetime.now().isoformat(), request_id))

    def list_pending_approvals(self) -> list:
        """获取所有待审批的请求"""
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM approvals WHERE status = 'pending' ORDER BY created_at DESC"
                ).fetchall()
                return [dict(r) for r in rows]

    def list_approvals_by_session(self, session_id: str) -> list:
        """获取指定会话的所有审批记录"""
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM approvals WHERE session_id = ? ORDER BY created_at DESC",
                    (session_id,)
                ).fetchall()
                return [dict(r) for r in rows]

    # ==================== 会话管理 ====================

    def create_session(self) -> str:
        import uuid
        session_id = str(uuid.uuid4())
        now = datetime.now().isoformat()
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    "INSERT INTO sessions (session_id, created_at, updated_at) VALUES (?, ?, ?)",
                    (session_id, now, now)
                )
        return session_id

    def add_message(self, session_id: str, role: str, content: str, message_type: str = "text"):
        now = datetime.now().isoformat()
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    "INSERT INTO conversation_history (session_id, role, content, type, timestamp) VALUES (?, ?, ?, ?, ?)",
                    (session_id, role, content, message_type, now)
                )
                conn.execute(
                    "UPDATE sessions SET updated_at = ?, message_count = message_count + 1 WHERE session_id = ?",
                    (now, session_id)
                )

    def get_history(self, session_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT role, content, type, timestamp FROM conversation_history WHERE session_id = ? ORDER BY id ASC LIMIT ?",
                (session_id, limit)
            ).fetchall()
        return [dict(r) for r in rows]

    def list_sessions(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT session_id, title, created_at, updated_at, message_count FROM sessions WHERE message_count > 0 ORDER BY updated_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def cleanup_empty_sessions(self) -> int:
        """清理所有 message_count 为 0 的空会话，返回清理数量"""
        with self._lock:
            with self._get_conn() as conn:
                cursor = conn.execute(
                    "DELETE FROM sessions WHERE message_count = 0"
                )
                return cursor.rowcount

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT session_id, title, created_at, updated_at, message_count FROM sessions WHERE session_id = ?",
                (session_id,)
            ).fetchone()
        return dict(row) if row else None

    def clear_session(self, session_id: str):
        with self._lock:
            with self._get_conn() as conn:
                conn.execute("DELETE FROM conversation_history WHERE session_id = ?", (session_id,))
                conn.execute(
                    "UPDATE sessions SET updated_at = ?, message_count = 0 WHERE session_id = ?",
                    (datetime.now().isoformat(), session_id)
                )

    def delete_session(self, session_id: str):
        with self._lock:
            with self._get_conn() as conn:
                conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))

    # ==================== 工具方法 ====================

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        for key in ("action_details", "detection_result", "tool_call_result", "tool_args", "extra_data"):
            if key in d and isinstance(d[key], str):
                try:
                    d[key] = json.loads(d[key])
                except (json.JSONDecodeError, TypeError):
                    pass
        d["is_blocked"] = bool(d.get("is_blocked"))
        return d


_storage_instance: Optional[Storage] = None


def get_storage() -> Storage:
    global _storage_instance
    if _storage_instance is None:
        _storage_instance = Storage()
    return _storage_instance
