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
import os
import uuid
import time
from datetime import datetime, timedelta
from threading import Lock, Thread
from typing import Any, Dict, List, Optional
from contextlib import contextmanager

from storage_base import StorageBackend

# psycopg 为可选依赖：缺失时不影响 SQLite 路径
try:
    import psycopg
    from psycopg.rows import dict_row
    from psycopg.errors import UniqueViolation, OperationalError
    PSYCOPG_AVAILABLE = True
except Exception:  # pragma: no cover
    psycopg = None
    dict_row = None
    UniqueViolation = Exception
    OperationalError = Exception
    PSYCOPG_AVAILABLE = False

# psycopg_pool 连接池（生产级改造：复用连接 + checkout 前健康检查，等效 pool_pre_ping）
try:
    from psycopg_pool import ConnectionPool
    POOL_AVAILABLE = True
except Exception:  # pragma: no cover
    ConnectionPool = None
    POOL_AVAILABLE = False

# 会话标题长度上限（缩略显示）
AUTO_TITLE_MAX = 30


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
    # 审计日志：按月分区（生产级改造，防单表膨胀）。分区键 log_date 须入主键；
    # 存量非分区表由 _init_db 的迁移逻辑自动转换为分区表
    """CREATE TABLE IF NOT EXISTS audit_logs (
        seq BIGSERIAL,
        log_id TEXT NOT NULL,
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
        extra_data TEXT,
        log_date DATE NOT NULL DEFAULT CURRENT_DATE,
        PRIMARY KEY (log_id, log_date)
    ) PARTITION BY RANGE (log_date)""",
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
    # ---- 治理中心：应急联动（全局熔断 / 账号封锁 / IP 封锁）----
    """CREATE TABLE IF NOT EXISTS emergency_controls (
        id BIGSERIAL PRIMARY KEY,
        control_type TEXT NOT NULL,
        target TEXT,
        enabled INTEGER DEFAULT 1,
        operator TEXT DEFAULT '',
        reason TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        removed_at TEXT
    )""",
    """CREATE INDEX IF NOT EXISTS idx_emergency_active ON emergency_controls(enabled)""",
    # ---- 治理中心：开放生态（调用方 / Token 哈希 / 限流配额 / 调用日志）----
    """CREATE TABLE IF NOT EXISTS api_clients (
        client_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        token_hash TEXT NOT NULL,
        enabled INTEGER DEFAULT 1,
        rate_limit INTEGER DEFAULT 60,
        quota INTEGER DEFAULT 0,
        used INTEGER DEFAULT 0,
        created_by TEXT DEFAULT '',
        description TEXT DEFAULT '',
        created_at TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS api_call_logs (
        id BIGSERIAL PRIMARY KEY,
        client_id TEXT NOT NULL,
        name TEXT NOT NULL,
        path TEXT DEFAULT '',
        status INTEGER DEFAULT 200,
        remote_ip TEXT DEFAULT '',
        created_at TEXT NOT NULL
    )""",
    """CREATE INDEX IF NOT EXISTS idx_api_calls_client ON api_call_logs(client_id)""",
    # ---- 全局流量限制（滑动窗口，落库保证多 worker 配额一致）----
    """CREATE TABLE IF NOT EXISTS rate_limit_hits (
        id BIGSERIAL PRIMARY KEY,
        key TEXT NOT NULL,
        hit_time DOUBLE PRECISION NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS idx_rate_key_time ON rate_limit_hits(key, hit_time)",
    # ---- 治理中心：PIPL 合规台账 ----
    """CREATE TABLE IF NOT EXISTS pipl_records (
        id BIGSERIAL PRIMARY KEY,
        session_id TEXT NOT NULL DEFAULT '',
        username TEXT NOT NULL DEFAULT '',
        pii_type TEXT NOT NULL,
        masked_value TEXT NOT NULL,
        source TEXT DEFAULT 'chat',
        legal_basis TEXT DEFAULT '',
        assessment TEXT DEFAULT 'pending',
        noted_by TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT
    )""",
    """CREATE INDEX IF NOT EXISTS idx_pipl_type ON pipl_records(pii_type)""",
    # ---- 生产级改造：API Key 多版本并存/过期/灰度轮换（P0-2）----
    """CREATE TABLE IF NOT EXISTS api_keys (
        key_id TEXT PRIMARY KEY,
        key_hash TEXT NOT NULL,
        version INTEGER NOT NULL DEFAULT 1,
        label TEXT DEFAULT '',
        status TEXT DEFAULT 'active',
        expires_at TEXT DEFAULT '',
        created_by TEXT DEFAULT '',
        created_at TEXT NOT NULL
    )""",
    """CREATE INDEX IF NOT EXISTS idx_api_keys_status ON api_keys(status, version)""",
    # ---- 生产级改造：检测规则版本化（热更新/回滚，P0-5）----
    """CREATE TABLE IF NOT EXISTS rule_definitions (
        id BIGSERIAL PRIMARY KEY,
        version INTEGER NOT NULL,
        category TEXT NOT NULL,
        pattern TEXT NOT NULL,
        weight DOUBLE PRECISION DEFAULT 1.0,
        enabled BOOLEAN DEFAULT TRUE,
        changed_by TEXT DEFAULT '',
        change_note TEXT DEFAULT '',
        created_at TEXT NOT NULL
    )""",
    """CREATE INDEX IF NOT EXISTS idx_rules_version ON rule_definitions(version, enabled)""",
    # ---- 生产级改造：检测误报标记（待审核队列，P0-5）----
    """CREATE TABLE IF NOT EXISTS detection_feedback (
        id BIGSERIAL PRIMARY KEY,
        log_id TEXT NOT NULL DEFAULT '',
        session_id TEXT DEFAULT '',
        content_sample TEXT DEFAULT '',
        detected_as TEXT DEFAULT '',
        user_comment TEXT DEFAULT '',
        status TEXT DEFAULT 'pending',
        submitted_by TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        reviewed_at TEXT DEFAULT '',
        reviewed_by TEXT DEFAULT ''
    )""",
    """CREATE INDEX IF NOT EXISTS idx_feedback_status ON detection_feedback(status)""",
    "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp)",
    "CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id)",
    "CREATE INDEX IF NOT EXISTS idx_audit_risk ON audit_logs(risk_level)",
    "CREATE INDEX IF NOT EXISTS idx_approval_status ON approval_requests(status)",
    "CREATE INDEX IF NOT EXISTS idx_conv_session ON conversation_history(session_id)",
    "CREATE INDEX IF NOT EXISTS idx_sessions_updated ON sessions(updated_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications(created_at DESC)",
    "CREATE INDEX IF NOT EXISTS idx_users_role ON sys_users(role)",
]


class PostgresStorage(StorageBackend):
    """PostgreSQL 存储后端（与 storage.Storage 同一公开接口）。"""

    # PostgreSQL SQL 占位符
    _ph = "%s"

    def __init__(self, dsn: Optional[str] = None):
        if not PSYCOPG_AVAILABLE:
            raise RuntimeError(
                "已选择 PostgreSQL 存储后端，但未安装 psycopg。请先安装：pip install 'psycopg[binary]'"
            )
        self._lock = Lock()
        self._dsn = dsn or _build_dsn()
        # ======== 生产级改造：连接池（psycopg_pool）========
        # min 2 / max 10；check_connection 在每次 checkout 前做 SELECT 1 健康检查
        # （等效 SQLAlchemy pool_pre_ping），坏连接自动重建
        self._pool = None
        if POOL_AVAILABLE:
            try:
                self._pool = ConnectionPool(
                    self._dsn,
                    min_size=2,
                    max_size=10,
                    kwargs={"row_factory": dict_row},
                    check=ConnectionPool.check_connection,
                    timeout=10.0,
                    open=True,
                )
            except Exception as e:  # noqa: BLE001 - 池创建失败退回逐次连接
                print(f"[PG][WARN] 连接池创建失败（{e}），退回逐次连接模式")
                self._pool = None
        # ======== 生产级改造：只读降级（主库不可用）========
        self._readonly = False
        self._wal_lock = Lock()
        self._replay_thread: Optional[Thread] = None
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self._wal_buffer_path = os.path.join(base_dir, "data", "pg_wal_buffer.jsonl")
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

    def is_readonly(self) -> bool:
        """主库连接是否处于降级只读状态（审计写本地 WAL 缓冲中）。"""
        return self._readonly

    def _mark_readonly_and_buffer(self, log_data: Dict[str, Any]) -> None:
        """主库不可用：置只读标记，审计写本地 WAL 缓冲，并启动后台补写线程。"""
        self._readonly = True
        os.makedirs(os.path.dirname(self._wal_buffer_path), exist_ok=True)
        try:
            with self._wal_lock, open(self._wal_buffer_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_data, ensure_ascii=False) + "\n")
            print(f"[PG][WARN] 主库不可用，审计日志已写本地 WAL 缓冲 {self._wal_buffer_path}")
        except Exception as e:  # noqa: BLE001
            print(f"[PG][ERROR] WAL 缓冲写入失败（审计日志可能丢失）: {e}")
        self._ensure_replay_thread()

    def _ensure_replay_thread(self) -> None:
        """启动（仅一次）后台重放线程：主库恢复后将 WAL 缓冲补写入库。"""
        if self._replay_thread is not None and self._replay_thread.is_alive():
            return
        self._replay_thread = Thread(target=self._replay_wal_buffer, daemon=True,
                                     name="pg-wal-replay")
        self._replay_thread.start()

    def _replay_wal_buffer(self) -> None:
        """后台循环：探测主库恢复 → 重放 WAL 缓冲 → 清空缓冲 → 解除只读。"""
        while True:
            time.sleep(5.0)
            try:
                with self._get_conn() as conn:
                    conn.execute("SELECT 1").fetchone()
            except Exception:  # noqa: BLE001 - 尚未恢复，继续等
                continue
            # 主库已恢复：重放缓冲
            try:
                if not os.path.isfile(self._wal_buffer_path):
                    self._readonly = False
                    print("[PG] 主库已恢复，WAL 缓冲为空，解除只读降级")
                    return
                with self._wal_lock, open(self._wal_buffer_path, "r", encoding="utf-8") as f:
                    lines = [ln for ln in (l.strip() for l in f) if ln]
                replayed = 0
                for ln in lines:
                    try:
                        data = json.loads(ln)
                        with self._get_conn() as conn:
                            conn.execute(
                                """INSERT INTO audit_logs
                                (log_id, timestamp, user_id, user_role, agent_id, action_type,
                                 action_details, risk_level, detection_result, tool_call_result,
                                 approval_status, is_blocked, blocking_reason, extra_data, log_date)
                                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                                ON CONFLICT DO NOTHING""",
                                (
                                    data.get("id", data.get("log_id", "")),
                                    data.get("timestamp", datetime.now().isoformat()),
                                    data.get("user_id", ""),
                                    data.get("user_role", "user"),
                                    data.get("agent_id", ""),
                                    data.get("action_type", ""),
                                    json.dumps(data.get("action_details", {}), ensure_ascii=False),
                                    data.get("risk_level", "none"),
                                    json.dumps(data.get("detection_result", {}), ensure_ascii=False),
                                    json.dumps(data.get("tool_call_result", {}), ensure_ascii=False),
                                    data.get("approval_status", ""),
                                    bool(data.get("is_blocked")),
                                    data.get("blocking_reason", ""),
                                    json.dumps(data.get("extra_data", {}), ensure_ascii=False),
                                    str(data.get("timestamp", datetime.now().isoformat()))[:10],
                                ),
                            )
                        replayed += 1
                    except Exception:  # noqa: BLE001 - 单条失败跳过，保留其余
                        continue
                with self._wal_lock, open(self._wal_buffer_path, "w", encoding="utf-8"):
                    pass  # 清空已重放的缓冲
                self._readonly = False
                print(f"[PG] 主库已恢复，WAL 缓冲补写完成（{replayed}/{len(lines)} 条），解除只读降级")
                return
            except Exception as e:  # noqa: BLE001 - 重放过程出错，下一轮重试
                print(f"[PG][WARN] WAL 重放出错，5s 后重试: {e}")

    @contextmanager
    def _get_conn(self):
        """取连接：优先连接池（自动 commit/rollback/归还），退回逐次连接。"""
        if self._pool is not None:
            # pool.connection() 上下文管理器：正常退出 commit，异常 rollback 并归还
            with self._pool.connection() as conn:
                yield conn
        else:
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
                # 迁移：conversation_history 补充 metadata 列（"思考中"过程等结构化元数据持久化，幂等）
                cur.execute("ALTER TABLE conversation_history ADD COLUMN IF NOT EXISTS metadata TEXT")
                # 迁移：sys_users 补充 force_mfa 列（生产级改造：admin/operator/auditor 强制 MFA）
                cur.execute("ALTER TABLE sys_users ADD COLUMN IF NOT EXISTS force_mfa BOOLEAN DEFAULT FALSE")
                # 迁移：audit_logs 老表补 log_date 分区键列（后续若触发分区迁移需要）
                cur.execute("ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS log_date DATE")
                self._migrate_audit_partition(cur)
                self._ensure_month_partitions(cur)

    @staticmethod
    def _migrate_audit_partition(cur) -> None:
        """存量非分区 audit_logs → 按月分区表迁移（建新表→INSERT SELECT→改名）。

        幂等：已是分区表则直接返回。迁移前建议已有 pg_dump 备份
        （deploy/backup/backup.sh 每日全量）。
        """
        cur.execute(
            "SELECT COUNT(*) AS c FROM pg_partitioned_table pt "
            "JOIN pg_class c ON c.oid = pt.partrelid WHERE c.relname = 'audit_logs'"
        )
        row = cur.fetchone()
        if row and int(row["c"]) > 0:
            return  # 已是分区表
        cur.execute(
            "SELECT COUNT(*) AS c FROM information_schema.tables "
            "WHERE table_name = 'audit_logs'"
        )
        row = cur.fetchone()
        if not row or int(row["c"]) == 0:
            return  # 表不存在（_SCHEMA_STATEMENTS 刚建的就是分区版）
        # 存量非分区表 → 迁移
        print("[PG][MIGRATE] 检测到非分区 audit_logs，开始按月分区迁移（旧表保留为 audit_logs_legacy）")
        cur.execute("ALTER TABLE audit_logs RENAME TO audit_logs_legacy")
        # 重建为分区表（与 _SCHEMA_STATEMENTS 同构）
        cur.execute("""
            CREATE TABLE audit_logs (
                seq BIGSERIAL,
                log_id TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                user_id TEXT, user_role TEXT, agent_id TEXT, action_type TEXT,
                action_details TEXT, risk_level TEXT, detection_result TEXT,
                tool_call_result TEXT, approval_status TEXT,
                is_blocked BOOLEAN DEFAULT FALSE,
                blocking_reason TEXT, extra_data TEXT,
                log_date DATE NOT NULL DEFAULT CURRENT_DATE,
                PRIMARY KEY (log_id, log_date)
            ) PARTITION BY RANGE (log_date)
        """)
        # 存量数据搬移：log_date 取 timestamp 前 10 位（isoformat 日期）；异常日期落 DEFAULT 分区
        cur.execute("""
            INSERT INTO audit_logs
                (seq, log_id, timestamp, user_id, user_role, agent_id, action_type,
                 action_details, risk_level, detection_result, tool_call_result,
                 approval_status, is_blocked, blocking_reason, extra_data, log_date)
            SELECT seq, log_id, timestamp, user_id, user_role, agent_id, action_type,
                   action_details, risk_level, detection_result, tool_call_result,
                   approval_status, is_blocked, blocking_reason, extra_data,
                   CASE WHEN timestamp ~ '^\\d{4}-\\d{2}-\\d{2}'
                        THEN substring(timestamp from 1 for 10)::date
                        ELSE DATE '1970-01-01' END
            FROM audit_logs_legacy
        """)
        cur.execute("DROP TABLE audit_logs_legacy")
        # 分区父表上重建索引（跟随 rename 的旧索引已随旧表删除）
        for idx in ("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp)",
                    "CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id)",
                    "CREATE INDEX IF NOT EXISTS idx_audit_risk ON audit_logs(risk_level)"):
            cur.execute(idx)
        print("[PG][MIGRATE] audit_logs 分区迁移完成")

    @staticmethod
    def _ensure_month_partitions(cur) -> None:
        """预建当月与未来 2 个月的月分区 + DEFAULT 兜底分区（捕获异常日期）。"""
        from datetime import date
        today = date.today()
        # 兜底分区（重复创建会报错，先判断存在性；用 SAVEPOINT 防并发竞争毒化事务）
        cur.execute(
            "SELECT COUNT(*) AS c FROM pg_class WHERE relname = 'audit_logs_default'"
        )
        if not cur.fetchone()["c"]:
            cur.execute("SAVEPOINT sp_default")
            try:
                cur.execute(
                    "CREATE TABLE audit_logs_default PARTITION OF audit_logs DEFAULT")
                cur.execute("RELEASE SAVEPOINT sp_default")
            except Exception:  # noqa: BLE001 - 并发创建竞争时回滚到保存点
                cur.execute("ROLLBACK TO SAVEPOINT sp_default")
        for i in range(0, 3):
            first = date(today.year, today.month, 1)
            for _ in range(i):
                first = (date(first.year, first.month, 28) + timedelta(days=8)).replace(day=1)
            nxt = (date(first.year, first.month, 28) + timedelta(days=8)).replace(day=1)
            name = f"audit_logs_{first.year}{first.month:02d}"
            cur.execute("SELECT COUNT(*) AS c FROM pg_class WHERE relname = %s", (name,))
            if not cur.fetchone()["c"]:
                cur.execute(
                    f"CREATE TABLE {name} PARTITION OF audit_logs "
                    f"FOR VALUES FROM ('{first.isoformat()}') TO ('{nxt.isoformat()}')"
                )

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
        ts = log_data.get("timestamp", datetime.now().isoformat())
        try:
            with self._lock:
                with self._get_conn() as conn:
                    conn.execute(
                        """INSERT INTO audit_logs
                        (log_id, timestamp, user_id, user_role, agent_id, action_type,
                         action_details, risk_level, detection_result, tool_call_result,
                         approval_status, is_blocked, blocking_reason, extra_data, log_date)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                        (
                            log_data.get("id", log_data.get("log_id", "")),
                            ts,
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
                            str(ts)[:10],  # 分区键：isoformat 日期部分
                        ),
                    )
        except OperationalError:
            # 生产级改造：主库不可用 → 降级写本地 WAL 缓冲，恢复后后台补写
            self._mark_readonly_and_buffer(log_data)

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

    def add_message(self, session_id: str, role: str, content: str, message_type: str = "text",
                    metadata: Optional[str] = None):
        now = datetime.now().isoformat()
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    "INSERT INTO conversation_history (session_id, role, content, type, timestamp, metadata) VALUES (%s,%s,%s,%s,%s,%s)",
                    (session_id, role, content, message_type, now, metadata),
                )
                conn.execute(
                    "UPDATE sessions SET updated_at = %s, message_count = message_count + 1 WHERE session_id = %s",
                    (now, session_id),
                )
                # 首次对话自动生成标题：用第一条用户消息内容缩略（已存在标题则不覆盖）
                if role == "user":
                    title = self._auto_title(content)
                    conn.execute(
                        "UPDATE sessions SET title = COALESCE(title, %s) WHERE session_id = %s AND title IS NULL",
                        (title, session_id),
                    )

    def get_history(self, session_id: str, limit: int = 20) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT id, role, content, type, timestamp, metadata FROM conversation_history WHERE session_id = %s ORDER BY id ASC LIMIT %s",
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

    def delete_message(self, session_id: str, message_id: int) -> int:
        """仅删除单条消息（不影响该条之前/之后的其它消息）"""
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute(
                    "DELETE FROM conversation_history WHERE session_id = %s AND id = %s",
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

    # ==================== 治理中心：应急联动（与 storage.Storage 同一接口） ====================

    def add_emergency_control(self, control_type: str, target: str, operator: str = "", reason: str = "") -> int:
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    "UPDATE emergency_controls SET enabled = 0, removed_at = %s WHERE control_type = %s AND target = %s AND enabled = 1",
                    (datetime.now().isoformat(), control_type, target),
                )
                row = conn.execute(
                    "INSERT INTO emergency_controls (control_type, target, enabled, operator, reason, created_at) "
                    "VALUES (%s,%s,1,%s,%s,%s) RETURNING id",
                    (control_type, target, operator, reason, datetime.now().isoformat()),
                ).fetchone()
                return int(row["id"]) if row else 0

    def release_emergency_control(self, control_type: str, target: str) -> None:
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    "UPDATE emergency_controls SET enabled = 0, removed_at = %s WHERE control_type = %s AND target = %s AND enabled = 1",
                    (datetime.now().isoformat(), control_type, target),
                )

    def active_emergency_controls(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM emergency_controls WHERE enabled = 1 ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

    def emergency_history(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM emergency_controls ORDER BY id DESC LIMIT %s", (int(limit),)).fetchall()
        return [dict(r) for r in rows]

    # ==================== 全局流量限制（滑动窗口，落库保证多 worker 配额一致） ====================

    def rate_limit_check(self, key: str, max_req: int, window: float, now: Optional[float] = None) -> bool:
        now = time.time() if now is None else now
        if max_req <= 0:
            return True
        with self._lock:
            with self._get_conn() as conn:
                conn.execute("DELETE FROM rate_limit_hits WHERE hit_time <= %s", (now - window,))
                cur = conn.execute(
                    "SELECT COUNT(*) AS c FROM rate_limit_hits WHERE key = %s AND hit_time > %s",
                    (key, now - window),
                )
                count = cur.fetchone()["c"]
                if count >= max_req:
                    return True
                conn.execute("INSERT INTO rate_limit_hits (key, hit_time) VALUES (%s, %s)", (key, now))
                return False

    def rate_limit_reset(self, key: str) -> None:
        with self._lock:
            with self._get_conn() as conn:
                conn.execute("DELETE FROM rate_limit_hits WHERE key = %s", (key,))

    # ==================== 治理中心：开放生态（调用方 / Token / 调用日志） ====================

    def upsert_api_client(self, client_id: str, name: str, token_hash: str, enabled: int,
                          rate_limit: int, quota: int, created_by: str, description: str = "") -> None:
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    """INSERT INTO api_clients
                       (client_id, name, token_hash, enabled, rate_limit, quota, used, created_by, description, created_at)
                       VALUES (%s,%s,%s,%s,%s,%s,0,%s,%s,%s)
                       ON CONFLICT (client_id) DO UPDATE SET
                         name = EXCLUDED.name, token_hash = EXCLUDED.token_hash, enabled = EXCLUDED.enabled,
                         rate_limit = EXCLUDED.rate_limit, quota = EXCLUDED.quota, description = EXCLUDED.description""",
                    (client_id, name, token_hash, int(enabled), int(rate_limit), int(quota),
                     created_by, description, datetime.now().isoformat()),
                )

    def list_api_clients(self) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute("SELECT * FROM api_clients ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

    def get_api_client(self, client_id: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            row = conn.execute("SELECT * FROM api_clients WHERE client_id = %s", (client_id,)).fetchone()
        return dict(row) if row else None

    def delete_api_client(self, client_id: str) -> None:
        with self._lock:
            with self._get_conn() as conn:
                conn.execute("DELETE FROM api_call_logs WHERE client_id = %s", (client_id,))
                conn.execute("DELETE FROM api_clients WHERE client_id = %s", (client_id,))

    def record_api_call(self, client_id: str, name: str, path: str, status: int, remote_ip: str = "") -> None:
        with self._lock:
            with self._get_conn() as conn:
                conn.execute("UPDATE api_clients SET used = used + 1 WHERE client_id = %s", (client_id,))
                conn.execute(
                    "INSERT INTO api_call_logs (client_id, name, path, status, remote_ip, created_at) "
                    "VALUES (%s,%s,%s,%s,%s,%s)",
                    (client_id, name, path, int(status), remote_ip, datetime.now().isoformat()),
                )

    def list_api_call_logs(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM api_call_logs ORDER BY id DESC LIMIT %s", (int(limit),)).fetchall()
        return [dict(r) for r in rows]

    # ==================== 治理中心：PIPL 合规台账 ====================

    def add_pipl_record(self, session_id: str, username: str, pii_type: str, masked_value: str,
                        source: str = "chat") -> Optional[int]:
        with self._lock:
            with self._get_conn() as conn:
                dup = conn.execute(
                    "SELECT id FROM pipl_records WHERE source = %s AND pii_type = %s AND masked_value = %s AND session_id = %s LIMIT 1",
                    (source, pii_type, masked_value, session_id),
                ).fetchone()
                if dup:
                    return int(dup["id"]) if dup["id"] is not None else None
                row = conn.execute(
                    "INSERT INTO pipl_records (session_id, username, pii_type, masked_value, source, created_at) "
                    "VALUES (%s,%s,%s,%s,%s,%s) RETURNING id",
                    (session_id, username, pii_type, masked_value, source, datetime.now().isoformat()),
                ).fetchone()
                return int(row["id"]) if row else None

    def list_pipl_records(self, limit: int = 200) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM pipl_records ORDER BY id DESC LIMIT %s", (int(limit),)).fetchall()
        return [dict(r) for r in rows]

    def update_pipl_record(self, record_id: int, legal_basis: str, assessment: str, noted_by: str = "") -> None:
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    "UPDATE pipl_records SET legal_basis = %s, assessment = %s, noted_by = %s, updated_at = %s WHERE id = %s",
                    (legal_basis, assessment, noted_by, datetime.now().isoformat(), int(record_id)),
                )

    def pipl_stats(self) -> Dict[str, Any]:
        with self._get_conn() as conn:
            total = conn.execute("SELECT COUNT(*) AS c FROM pipl_records").fetchone()["c"]
            pending = conn.execute("SELECT COUNT(*) AS c FROM pipl_records WHERE assessment = 'pending'").fetchone()["c"]
            rows = conn.execute(
                "SELECT pii_type, COUNT(*) AS c FROM pipl_records GROUP BY pii_type ORDER BY c DESC").fetchall()
        return {"total": int(total), "pending": int(pending),
                "by_type": {r["pii_type"]: int(r["c"]) for r in rows}}

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
                if cur.rowcount == 0:
                    return False
                conn.execute("UPDATE sys_users SET department = '' WHERE department = %s", (name,))
                return True

    def rename_department(self, old_name: str, new_name: str) -> bool:
        new_name = (new_name or "").strip()
        if not new_name:
            return False
        with self._lock:
            with self._get_conn() as conn:
                try:
                    cur = conn.execute(
                        "UPDATE sys_departments SET name = %s WHERE name = %s",
                        (new_name, old_name),
                    )
                    if cur.rowcount == 0:
                        return False
                    conn.execute(
                        "UPDATE sys_users SET department = %s WHERE department = %s",
                        (new_name, old_name),
                    )
                    return True
                except UniqueViolation:
                    return False
