-- ====================================================================
-- safeagent 数据库建库初始化脚本
-- 自动生成于: 2026-09-23 08:42:08（schema 取自 ai_service/data/safeagent.db，为运行库 1:1 结构）
-- 三段式：FastAPI AI(8080) + SpringBoot biz(8300) + 网关(8090)，两者共享同一 SQLite
-- 内容：全部表/索引/触发器结构 + 核心种子账户（口令 admin123，PBKDF2-SHA256/200k）
-- 不含任何业务/审计数据。
--
-- 建议在全新库执行；同名表已存在时会报错，属预期（幂等导入请先 DROP 对应表）。
-- 执行方式示例：
--   python -c "import sqlite3;c=sqlite3.connect('D:/your/path/safeagent.db');c.executescript(open('sql/init_all_tables.sql',encoding='utf-8').read());c.commit();c.close()"
-- ====================================================================

PRAGMA foreign_keys = OFF;
BEGIN;

-- [table] api_call_logs
CREATE TABLE api_call_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    client_id TEXT,
                    name TEXT DEFAULT '',
                    path TEXT,
                    status INTEGER,
                    remote_ip TEXT,
                    created_at TEXT NOT NULL
                );

-- [table] api_clients
CREATE TABLE api_clients (
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
                );

-- [table] approval_requests
CREATE TABLE approval_requests (
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

-- [table] audit_logs
CREATE TABLE audit_logs (
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

-- [table] conversation_history
CREATE TABLE conversation_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT,
                    type TEXT DEFAULT 'text',
                    timestamp TEXT NOT NULL, image_data TEXT, metadata TEXT,
                    FOREIGN KEY (session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
                );

-- [table] emergency_controls
CREATE TABLE emergency_controls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    control_type TEXT NOT NULL,
                    target TEXT,
                    enabled INTEGER DEFAULT 1,
                    operator TEXT DEFAULT '',
                    reason TEXT DEFAULT '',
                    created_at TEXT NOT NULL,
                    removed_at TEXT
                );

-- [table] notifications
CREATE TABLE notifications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT NOT NULL,
                    title TEXT NOT NULL,
                    message TEXT,
                    level TEXT DEFAULT 'info',
                    read INTEGER DEFAULT 0,
                    created_at TEXT NOT NULL
                );

-- [table] opt_attack_samples
CREATE TABLE opt_attack_samples (
                    id TEXT PRIMARY KEY,
                    content TEXT,
                    attack_type TEXT,
                    source TEXT,
                    created_at TEXT,
                    in_use INTEGER DEFAULT 1
                );

-- [table] opt_feedback
CREATE TABLE opt_feedback (
                    id TEXT PRIMARY KEY,
                    sample_text TEXT,
                    source TEXT,
                    predicted_label TEXT,
                    predicted_risk TEXT,
                    annotator_label TEXT,
                    annotator_comment TEXT,
                    status TEXT,
                    created_at TEXT
                );

-- [table] opt_regression_runs
CREATE TABLE opt_regression_runs (
                    id TEXT PRIMARY KEY,
                    run_at TEXT,
                    total INTEGER,
                    accuracy REAL,
                    false_positive_rate REAL,
                    false_negative_rate REAL,
                    detected_attacks INTEGER,
                    keyword_count INTEGER,
                    note TEXT
                );

-- [table] opt_threat_iocs
CREATE TABLE opt_threat_iocs (
                    id TEXT PRIMARY KEY,
                    indicator TEXT,
                    ioc_type TEXT,
                    source TEXT,
                    imported_at TEXT,
                    applied INTEGER DEFAULT 0
                );

-- [table] opt_versions
CREATE TABLE opt_versions (
                    id TEXT PRIMARY KEY,
                    version INTEGER,
                    change_type TEXT,
                    description TEXT,
                    keywords_added TEXT,
                    keywords_removed TEXT,
                    applied INTEGER DEFAULT 0,
                    applied_at TEXT,
                    created_at TEXT
                );

-- [table] pipl_records
CREATE TABLE pipl_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT,
                    username TEXT,
                    pii_type TEXT,
                    masked_value TEXT,
                    source TEXT DEFAULT 'chat',
                    legal_basis TEXT DEFAULT '',
                    assessment TEXT DEFAULT 'pending',
                    noted_by TEXT DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT
                );

-- [table] policy_config
CREATE TABLE policy_config (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

-- [table] rate_limit_hits
CREATE TABLE rate_limit_hits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT NOT NULL,
                    hit_time REAL NOT NULL
                );

-- [table] sessions
CREATE TABLE sessions (
                    session_id TEXT PRIMARY KEY,
                    title TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    message_count INTEGER DEFAULT 0
                , user_id TEXT, terminated INTEGER DEFAULT 0, terminated_reason TEXT, terminated_at TEXT);

-- [table] sys_departments
CREATE TABLE sys_departments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    created_at TEXT NOT NULL
                );

-- [table] sys_users
CREATE TABLE sys_users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    display_name TEXT NOT NULL,
                    role TEXT NOT NULL,
                    department TEXT DEFAULT '',
                    position TEXT DEFAULT '',
                    status TEXT DEFAULT 'active',
                    note TEXT DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                , totp_secret TEXT DEFAULT '', mfa_enabled INTEGER DEFAULT 0,
                token_version INTEGER NOT NULL DEFAULT 0);

-- [table] tool_management
CREATE TABLE tool_management (id INTEGER PRIMARY KEY AUTOINCREMENT,key TEXT UNIQUE,value TEXT,updated_at TEXT);

-- [index] idx_api_calls_client
CREATE INDEX idx_api_calls_client ON api_call_logs(client_id);

-- [index] idx_approval_status
CREATE INDEX idx_approval_status ON approval_requests(status);

-- [index] idx_audit_risk
CREATE INDEX idx_audit_risk ON audit_logs(risk_level);

-- [index] idx_audit_timestamp
CREATE INDEX idx_audit_timestamp ON audit_logs(timestamp);

-- [index] idx_audit_user
CREATE INDEX idx_audit_user ON audit_logs(user_id);

-- [index] idx_conv_session
CREATE INDEX idx_conv_session ON conversation_history(session_id);

-- [index] idx_emergency_type
CREATE INDEX idx_emergency_type ON emergency_controls(control_type, enabled);

-- [index] idx_notifications_created
CREATE INDEX idx_notifications_created ON notifications(created_at DESC);

-- [index] idx_pipl_created
CREATE INDEX idx_pipl_created ON pipl_records(created_at DESC);

-- [index] idx_pipl_user
CREATE INDEX idx_pipl_user ON pipl_records(username);

-- [index] idx_rate_key_time
CREATE INDEX idx_rate_key_time ON rate_limit_hits(key, hit_time);

-- [index] idx_sessions_updated
CREATE INDEX idx_sessions_updated ON sessions(updated_at DESC);

-- [index] idx_users_role
CREATE INDEX idx_users_role ON sys_users(role);

-- [trigger] trg_audit_worm_no_delete
CREATE TRIGGER trg_audit_worm_no_delete
BEFORE DELETE ON audit_logs
BEGIN
  SELECT RAISE(ABORT, 'audit_logs is append-only (WORM): DELETE denied');
END;

-- [trigger] trg_audit_worm_no_update
CREATE TRIGGER trg_audit_worm_no_update
BEFORE UPDATE ON audit_logs
BEGIN
  SELECT RAISE(ABORT, 'audit_logs is append-only (WORM): UPDATE denied');
END;

-- ===================== 种子账户（默认口令 admin123，请登录后尽快修改） =====================
INSERT INTO "sys_users" ("username", "password_hash", "salt", "display_name", "role", "department", "position", "status", "note", "created_at", "updated_at", "totp_secret", "mfa_enabled") VALUES ('admin', '1f3c89c93a7b993bc124bb8f58879bb37a763e824229e5894169a4866f91415f', '9bd39f55353cfdc831a043b4d75064cd', '系统管理员', 'admin', '信息化与网络安全处', '安全管理员', 'active', '', '2026-09-23T08:42:08.951167', '2026-09-23T08:42:08.951167', '', 0);
INSERT INTO "sys_users" ("username", "password_hash", "salt", "display_name", "role", "department", "position", "status", "note", "created_at", "updated_at", "totp_secret", "mfa_enabled") VALUES ('operator', '4ab5d9ac7a557ea64b47c55b6eb7e54584b07edc7b6e239ba826f7ccf411706b', 'd279534b604ffedbb329e90f2e8033d0', '安全运维员', 'operator', '信息化与网络安全处', '安全运维', 'active', '', '2026-09-23T08:42:08.951167', '2026-09-23T08:42:08.951167', '', 0);
INSERT INTO "sys_users" ("username", "password_hash", "salt", "display_name", "role", "department", "position", "status", "note", "created_at", "updated_at", "totp_secret", "mfa_enabled") VALUES ('auditor', '9385180c322a9006614a7b24362f581c14083060ffff9633be7ceaeed2f6bacd', '1d4cbcbde07766c3be93589b3107dbc4', '合规审计员', 'auditor', '法务与合规部', '合规审计', 'active', '', '2026-09-23T08:42:08.951167', '2026-09-23T08:42:08.951167', '', 0);
INSERT INTO "sys_users" ("username", "password_hash", "salt", "display_name", "role", "department", "position", "status", "note", "created_at", "updated_at", "totp_secret", "mfa_enabled") VALUES ('user', '9a145b3747ca858849726d41ecf4861a5fe39ee749372bee29280b049bbd707b', '6995448c3f4cd6adab55eaa7e64bd04f', '业务用户', 'user', '综合办公室', '业务经办', 'active', '', '2026-09-23T08:42:08.951167', '2026-09-23T08:42:08.951167', '', 0);
INSERT INTO "sys_users" ("username", "password_hash", "salt", "display_name", "role", "department", "position", "status", "note", "created_at", "updated_at", "totp_secret", "mfa_enabled") VALUES ('dept_mgr', 'f05759dcde23beb58001e5995806989ebc55cf0a49df5269a2ee357d70e964b7', '7527eab715ca5d3f6b168510f699dd00', '综合办负责人', 'manager', '综合办公室', '处长', 'active', '', '2026-09-23T08:42:08.951167', '2026-09-23T08:42:08.951167', '', 0);
COMMIT;