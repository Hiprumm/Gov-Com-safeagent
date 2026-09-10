"""
SQLite 持久化存储模块
替换原有的内存 dict 存储，提供审计日志、审批记录、会话历史的持久化。
"""
import sqlite3
import json
import os
from datetime import datetime, timedelta
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

    @property
    def db_path(self) -> str:
        """当前数据库文件路径（供审计保护/归档等维护模块使用）"""
        return self._db_path

    @property
    def is_file_backed(self) -> bool:
        """是否为文件型数据库（SQLite）。PostgreSQL 后端为 False。"""
        return True

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

                CREATE TABLE IF NOT EXISTS notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    message TEXT,
                    level TEXT DEFAULT 'info',
                    read INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS policy_config (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sys_departments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS sys_users (
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
                    mfa_enabled INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);
                CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);
                CREATE INDEX IF NOT EXISTS idx_audit_risk ON audit_logs(risk_level);
                CREATE INDEX IF NOT EXISTS idx_approval_status ON approval_requests(status);
                CREATE INDEX IF NOT EXISTS idx_conv_session ON conversation_history(session_id);
                CREATE INDEX IF NOT EXISTS idx_sessions_updated ON sessions(updated_at DESC);
                CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_users_role ON sys_users(role);
            """)
            # 迁移：为历史库补充 MFA(TOTP) 列（幂等）
            try:
                cols = {r["name"] for r in conn.execute("PRAGMA table_info(sys_users)").fetchall()}
                if "totp_secret" not in cols:
                    conn.execute("ALTER TABLE sys_users ADD COLUMN totp_secret TEXT DEFAULT ''")
                if "mfa_enabled" not in cols:
                    conn.execute("ALTER TABLE sys_users ADD COLUMN mfa_enabled INTEGER DEFAULT 0")
            except Exception:
                pass

    # ==================== 审计日志 ====================

    def save_audit_log(self, log_data: Dict[str, Any]):
        """写入审计日志（**只追加**，不覆盖；配合 WORM 触发器实现物理不可篡改）"""
        with self._lock:
            with self._get_conn() as conn:
                conn.execute("""
                    INSERT INTO audit_logs
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

    def get_audit_logs_page(self, page: int = 1, page_size: int = 20) -> List[Dict[str, Any]]:
        """分页查询审计日志（按时间倒序），page 从 1 开始"""
        offset = max(0, (page - 1) * page_size)
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_logs ORDER BY timestamp DESC, rowid DESC LIMIT ? OFFSET ?",
                (page_size, offset)
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def count_audit_logs(self) -> int:
        """统计审计日志总条数"""
        with self._get_conn() as conn:
            row = conn.execute("SELECT COUNT(*) FROM audit_logs").fetchone()
        return row[0] if row else 0

    def count_approvals(self) -> int:
        """统计审批请求总条数"""
        with self._get_conn() as conn:
            row = conn.execute("SELECT COUNT(*) FROM approval_requests").fetchone()
        return row[0] if row else 0

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

    def delete_audit_logs_older_than(self, days: int) -> int:
        """按等保2.0留存策略删除超过留存期限的审计日志，返回删除条数"""
        with self._lock:
            with self._get_conn() as conn:
                cutoff = (datetime.now() - timedelta(days=days)).isoformat()
                cur = conn.execute(
                    "DELETE FROM audit_logs WHERE timestamp < ?", (cutoff,)
                )
                return cur.rowcount

    def get_last_audit_log(self) -> Optional[Dict[str, Any]]:
        """获取最近一条审计日志（用于哈希链链接）"""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM audit_logs ORDER BY timestamp DESC, rowid DESC LIMIT 1"
            ).fetchone()
        return self._row_to_dict(row) if row else None

    def get_audit_logs_ordered(self, limit: int = 100000) -> List[Dict[str, Any]]:
        """按时间正序获取全部审计日志（用于哈希链完整性校验）"""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_logs ORDER BY timestamp ASC, rowid ASC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_audit_logs_before(self, cutoff_iso: str, limit: int = 200000) -> List[Dict[str, Any]]:
        """按时间正序取早于 cutoff 的审计日志（用于留存归档后再清理）"""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_logs WHERE timestamp < ? ORDER BY timestamp ASC, rowid ASC LIMIT ?",
                (cutoff_iso, limit),
            ).fetchall()
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
                    """UPDATE approval_requests
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
                    "SELECT * FROM approval_requests WHERE status = 'pending' ORDER BY created_at DESC"
                ).fetchall()
                # _row_to_dict 解析 tool_args 等 JSON 列（裸 dict 会留 JSON 字符串，
                # 导致 ApprovalRequest 校验失败）
                return [self._row_to_dict(r) for r in rows]

    def list_recent_approvals(self, limit: int = 50) -> list:
        """获取最近的审批记录（全部状态），供审批中心历史列表使用"""
        with self._lock:
            with self._get_conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM approval_requests ORDER BY updated_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
                return [self._row_to_dict(r) for r in rows]

    # ==================== 会话管理 ====================

    def ensure_session(self, session_id: str) -> str:
        """幂等确保会话存在：不存在则创建，存在则原样返回。

        统一入口，替代此前外部直接调用数据库私有连接 + SQLite 专有 SQL 的做法。
        """
        if not session_id:
            return self.create_session()
        now = datetime.now().isoformat()
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    "INSERT OR IGNORE INTO sessions (session_id, created_at, updated_at) VALUES (?, ?, ?)",
                    (session_id, now, now),
                )
        return session_id

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
                "SELECT id, role, content, type, timestamp FROM conversation_history WHERE session_id = ? ORDER BY id ASC LIMIT ?",
                (session_id, limit)
            ).fetchall()
        return [dict(r) for r in rows]

    def list_sessions(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT session_id, title, created_at, updated_at, message_count FROM sessions WHERE message_count > 0 ORDER BY updated_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    # ==================== 站内通知 ====================

    def add_notification(self, type_: str, title: str, message: str = "", level: str = "info") -> Optional[int]:
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute(
                    "INSERT INTO notifications (type, title, message, level, created_at) VALUES (?, ?, ?, ?, ?)",
                    (type_, title, message or "", level, datetime.now().isoformat()),
                )
                return cur.lastrowid

    def list_notifications(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM notifications ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def count_unread_notifications(self) -> int:
        with self._get_conn() as conn:
            row = conn.execute("SELECT COUNT(*) FROM notifications WHERE read = 0").fetchone()
        return row[0] if row else 0

    def mark_notifications_read(self, notif_id: Optional[int] = None):
        with self._lock:
            with self._get_conn() as conn:
                if notif_id is not None:
                    conn.execute("UPDATE notifications SET read = 1 WHERE id = ?", (notif_id,))
                else:
                    conn.execute("UPDATE notifications SET read = 1 WHERE read = 0")

    def clear_notifications(self):
        with self._lock:
            with self._get_conn() as conn:
                conn.execute("DELETE FROM notifications")

    # ==================== 通用键值设置（policy_config 表，如 webhook/模型接入配置） ====================

    def get_setting(self, key: str, default: Any = None) -> Any:
        with self._get_conn() as conn:
            row = conn.execute("SELECT value FROM policy_config WHERE key = ?", (key,)).fetchone()
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
                    "INSERT OR REPLACE INTO policy_config (key, value, updated_at) VALUES (?, ?, ?)",
                    (key, json.dumps(value, ensure_ascii=False), datetime.now().isoformat()),
                )

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

    def truncate_messages_from(self, session_id: str, message_id: int):
        """删除指定ID及之后的所有消息（用于撤回/编辑）"""
        with self._lock:
            with self._get_conn() as conn:
                cursor = conn.execute(
                    "DELETE FROM conversation_history WHERE session_id = ? AND id >= ?",
                    (session_id, message_id)
                )
                remaining = conn.execute(
                    "SELECT COUNT(*) FROM conversation_history WHERE session_id = ?",
                    (session_id,)
                ).fetchone()[0]
                conn.execute(
                    "UPDATE sessions SET updated_at = ?, message_count = ? WHERE session_id = ?",
                    (datetime.now().isoformat(), remaining, session_id)
                )
                return cursor.rowcount

    def delete_session(self, session_id: str):
        with self._lock:
            with self._get_conn() as conn:
                conn.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))

    def rename_session(self, session_id: str, title: str) -> bool:
        """重命名会话（title 为空字符串时恢复为未命名 NULL）"""
        with self._lock:
            with self._get_conn() as conn:
                cursor = conn.execute(
                    "UPDATE sessions SET title = ?, updated_at = updated_at WHERE session_id = ?",
                    (title.strip() or None, session_id),
                )
                return cursor.rowcount > 0

    # ==================== 安全策略配置 ====================

    def get_policy_config(self) -> Dict[str, str]:
        """读取全部策略配置（value 为 JSON 字符串，由调用方解析）"""
        with self._get_conn() as conn:
            rows = conn.execute("SELECT key, value FROM policy_config").fetchall()
        return {r["key"]: r["value"] for r in rows}

    def update_policy_config(self, items: Dict[str, Any]) -> None:
        """批量 upsert 策略配置（value 自动 JSON 序列化）"""
        now = datetime.now().isoformat()
        with self._lock:
            with self._get_conn() as conn:
                for key, value in items.items():
                    conn.execute(
                        """INSERT INTO policy_config (key, value, updated_at) VALUES (?, ?, ?)
                           ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at""",
                        (key, json.dumps(value, ensure_ascii=False), now),
                    )

    # ==================== 组织 / 用户管理 ====================

    def user_exists(self, username: str) -> bool:
        with self._get_conn() as conn:
            return conn.execute("SELECT 1 FROM sys_users WHERE username = ?", (username,)).fetchone() is not None

    def count_users(self) -> int:
        with self._get_conn() as conn:
            return conn.execute("SELECT COUNT(*) FROM sys_users").fetchone()[0]

    def upsert_user(self, username: str, password_hash: str, salt: str, display_name: str,
                    role: str, department: str = "", position: str = "",
                    status: str = "active", note: str = "") -> None:
        now = datetime.now().isoformat()
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """INSERT INTO sys_users (username, password_hash, salt, display_name, role,
                                               department, position, status, note, created_at, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                       ON CONFLICT(username) DO UPDATE SET
                         password_hash = excluded.password_hash,
                         salt = excluded.salt,
                         display_name = excluded.display_name,
                         role = excluded.role,
                         department = excluded.department,
                         position = excluded.position,
                         status = excluded.status,
                         note = excluded.note,
                         updated_at = excluded.updated_at""",
                    (username, password_hash, salt, display_name, role, department,
                     position, status, note, now, now),
                )

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM sys_users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None

    def get_user_password(self, username: str) -> Optional[Dict[str, Any]]:
        """返回 password_hash 与 salt，用于登录校验"""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT username, password_hash, salt, display_name, role, department, position, status FROM sys_users WHERE username = ?",
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
        """返回用户的 MFA 信息：{totp_secret, mfa_enabled}

        totp_secret 在库中为密文（security.secret_box），此处透明解密为明文返回。
        """
        from security.secret_box import decrypt_secret
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT totp_secret, mfa_enabled FROM sys_users WHERE username = ?", (username,)
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
                    "UPDATE sys_users SET totp_secret = ?, mfa_enabled = ?, updated_at = ? WHERE username = ?",
                    (encrypt_secret(secret or ""), 1 if enabled else 0,
                     datetime.now().isoformat(), username),
                )
                return cur.rowcount > 0

    def update_user_profile(self, username: str, display_name: str = None, role: str = None,
                            department: str = None, position: str = None,
                            status: str = None, note: str = None) -> bool:
        sets, vals = [], []
        if display_name is not None: sets.append("display_name = ?"); vals.append(display_name)
        if role is not None: sets.append("role = ?"); vals.append(role)
        if department is not None: sets.append("department = ?"); vals.append(department)
        if position is not None: sets.append("position = ?"); vals.append(position)
        if status is not None: sets.append("status = ?"); vals.append(status)
        if note is not None: sets.append("note = ?"); vals.append(note)
        if not sets:
            return False
        sets.append("updated_at = ?")
        vals.append(datetime.now().isoformat())
        vals.append(username)
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute(f"UPDATE sys_users SET {', '.join(sets)} WHERE username = ?", vals)
                return cur.rowcount > 0

    def update_user_password(self, username: str, password_hash: str, salt: str) -> bool:
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute(
                    "UPDATE sys_users SET password_hash = ?, salt = ?, updated_at = ? WHERE username = ?",
                    (password_hash, salt, datetime.now().isoformat(), username),
                )
                return cur.rowcount > 0

    def delete_user(self, username: str) -> bool:
        """物理删除用户（真实生产建议仅禁用 status=disabled）"""
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute("DELETE FROM sys_users WHERE username = ?", (username,))
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
                    conn.execute("INSERT INTO sys_departments (name, created_at) VALUES (?, ?)", (name.strip(), now))
                    return True
                except sqlite3.IntegrityError:
                    return False

    def remove_department(self, name: str) -> bool:
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute("DELETE FROM sys_departments WHERE name = ?", (name,))
                return cur.rowcount > 0

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


_storage_instance: Optional[Any] = None


def get_storage() -> Any:
    """存储单例工厂：依据配置选择后端（SQLite 默认 / PostgreSQL 可选）。

    通过环境变量/.env 的 `STORAGE_BACKEND=sqlite|postgres` 切换。
    - 默认 sqlite：零依赖，行为与历史一致；
    - postgres：需安装 `psycopg`，连接参数见 POSTGRES_* / POSTGRES_DSN。
    两种后端实现同一套公开方法（见 Storage / PostgresStorage），上层调用方无需改动。
    """
    global _storage_instance
    if _storage_instance is not None:
        return _storage_instance
    backend = "sqlite"
    try:
        from config import settings
        backend = str(getattr(settings, "STORAGE_BACKEND", "sqlite") or "sqlite").lower()
    except Exception:
        backend = "sqlite"
    if backend in ("postgres", "postgresql", "pg"):
        from postgres_storage import PostgresStorage  # 延迟导入，避免循环依赖
        _storage_instance = PostgresStorage()
    else:
        _storage_instance = Storage()
    return _storage_instance
