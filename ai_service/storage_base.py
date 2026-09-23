# -*- coding: utf-8 -*-
"""存储后端公共基类（P0-2 双轨收敛）

SQLite（storage.Storage）与 PostgreSQL（postgres_storage.PostgresStorage）
两套后端共享的公共逻辑收敛于此：TOTP 密钥加解密（security.secret_box）与
MFA 读写、会话标题生成。子类只需提供 `_get_conn()` 与 `_ph`（SQL 占位符）。

占位符差异：SQLite 用 `?`，PostgreSQL 用 `%s`，由子类覆盖 `_ph`。

生产级改造新增（方言中性的 DML，两后端共用）：
- API Key 多版本并存/过期/轮换（api_keys）
- 检测规则版本化热更新/回滚（rule_definitions）
- 检测误报标记待审核队列（detection_feedback）
"""
from datetime import datetime
from typing import Any, Dict, List, Optional


class StorageBackend:
    """存储后端公共基类：收敛 secret_box 加解密与 MFA 读写等重复逻辑。"""

    # SQL 占位符：SQLite 用 ?，PostgreSQL 用 %s（子类覆盖）
    _ph = "?"

    @staticmethod
    def _auto_title(content: str) -> str:
        """由消息内容生成缩略会话标题：压缩空白 + 截断 30 字。"""
        text = " ".join(content.strip().split())
        return text[:30]

    def _encrypt_secret(self, secret: str) -> str:
        from security.secret_box import encrypt_secret
        return encrypt_secret(secret)

    def _decrypt_secret(self, secret: str) -> str:
        from security.secret_box import decrypt_secret
        return decrypt_secret(secret)

    def get_user_mfa(self, username: str) -> Dict[str, Any]:
        """返回用户的 MFA 信息：{totp_secret, mfa_enabled}

        totp_secret 在库中为密文（security.secret_box），此处透明解密为明文返回。
        """
        with self._get_conn() as conn:
            row = conn.execute(
                f"SELECT totp_secret, mfa_enabled FROM sys_users WHERE username = {self._ph}",
                (username,),
            ).fetchone()
        if not row:
            return {"totp_secret": "", "mfa_enabled": False}
        return {"totp_secret": self._decrypt_secret(row["totp_secret"] or ""),
                "mfa_enabled": bool(row["mfa_enabled"])}

    def set_user_mfa(self, username: str, secret: str, enabled: bool) -> bool:
        """设置用户的 TOTP 密钥与启用状态（入库前加密）"""
        from datetime import datetime
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute(
                    f"UPDATE sys_users SET totp_secret = {self._ph}, mfa_enabled = {self._ph}, "
                    f"updated_at = {self._ph} WHERE username = {self._ph}",
                    (self._encrypt_secret(secret or ""), bool(enabled),
                     datetime.now().isoformat(), username),
                )
                return cur.rowcount > 0

    # ================================================================
    # 生产级改造：API Key 多版本并存/过期/轮换（P0-2）
    # ================================================================
    def create_api_key(self, key_id: str, key_hash: str, version: int, label: str = "",
                       expires_at: str = "", created_by: str = "") -> None:
        """新增一个 API Key 版本（多版本并存；旧版本不删，靠 status 控制）"""
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    f"INSERT INTO api_keys (key_id, key_hash, version, label, status, "
                    f"expires_at, created_by, created_at) "
                    f"VALUES ({self._ph},{self._ph},{self._ph},{self._ph},'active',"
                    f"{self._ph},{self._ph},{self._ph})",
                    (key_id, key_hash, int(version), label, expires_at,
                     created_by, datetime.now().isoformat()),
                )

    def list_api_keys(self) -> List[Dict[str, Any]]:
        """列出全部 API Key 版本（不含 key_hash 本体，只给指纹提示）"""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT key_id, version, label, status, expires_at, created_by, created_at "
                "FROM api_keys ORDER BY version DESC, created_at DESC"
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["expired"] = bool(d.get("expires_at") and d["expires_at"] < datetime.now().isoformat())
            out.append(d)
        return out

    def revoke_api_key(self, key_id: str) -> bool:
        """吊销指定版本的 API Key"""
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute(
                    f"UPDATE api_keys SET status = 'revoked' WHERE key_id = {self._ph}",
                    (key_id,),
                )
                return cur.rowcount > 0

    def verify_api_key_hash(self, key_hash: str) -> Optional[Dict[str, Any]]:
        """按哈希校验 API Key：存在 active 且未过期的版本则返回其元信息。

        过期判定：expires_at 非空且早于当前时间 → 视同失效。
        """
        with self._get_conn() as conn:
            row = conn.execute(
                f"SELECT key_id, version, label, status, expires_at FROM api_keys "
                f"WHERE key_hash = {self._ph} AND status = 'active' LIMIT 1",
                (key_hash,),
            ).fetchone()
        if not row:
            return None
        d = dict(row)
        if d.get("expires_at") and d["expires_at"] < datetime.now().isoformat():
            return None  # 已过期
        return d

    def get_active_api_key_hashes(self) -> List[str]:
        """全部有效的 API Key 哈希（网关启动时批量加载）"""
        now = datetime.now().isoformat()
        with self._get_conn() as conn:
            rows = conn.execute(
                f"SELECT key_hash FROM api_keys WHERE status = 'active' "
                f"AND (expires_at = '' OR expires_at IS NULL OR expires_at >= {self._ph})",
                (now,),
            ).fetchall()
        return [r["key_hash"] for r in rows]

    # ================================================================
    # 生产级改造：检测规则版本化（热更新/回滚，P0-5）
    # ================================================================
    def save_rules_version(self, rules: List[Dict[str, Any]], version: int,
                           changed_by: str = "", change_note: str = "") -> int:
        """保存一个新版本的规则集（rules: [{category, pattern, weight, enabled}]）"""
        now = datetime.now().isoformat()
        with self._lock:
            with self._get_conn() as conn:
                for r in rules:
                    conn.execute(
                        f"INSERT INTO rule_definitions "
                        f"(version, category, pattern, weight, enabled, changed_by, change_note, created_at) "
                        f"VALUES ({self._ph},{self._ph},{self._ph},{self._ph},{self._ph},{self._ph},{self._ph},{self._ph})",
                        (int(version), r.get("category", ""), r.get("pattern", ""),
                         float(r.get("weight", 1.0)), bool(r.get("enabled", True)),
                         changed_by, change_note, now),
                    )
                return int(version)

    def get_rules(self, version: Optional[int] = None) -> List[Dict[str, Any]]:
        """取规则集：未指定版本取最新版本（空表返回 []，调用方走内置兜底）"""
        with self._get_conn() as conn:
            if version is None:
                row = conn.execute(
                    "SELECT MAX(version) AS v FROM rule_definitions"
                ).fetchone()
                if not row or row["v"] is None:
                    return []
                version = int(row["v"])
            rows = conn.execute(
                f"SELECT version, category, pattern, weight, enabled, changed_by, "
                f"change_note, created_at FROM rule_definitions WHERE version = {self._ph}",
                (int(version),),
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["enabled"] = bool(d.get("enabled"))
            d["weight"] = float(d.get("weight") or 1.0)
            out.append(d)
        return out

    def list_rule_versions(self) -> List[Dict[str, Any]]:
        """规则版本清单：[{version, rule_count, changed_by, change_note, created_at}]"""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT version, changed_by, change_note, created_at, "
                "COUNT(*) AS rule_count FROM rule_definitions GROUP BY version "
                "ORDER BY version DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_latest_rule_version(self) -> int:
        """最新规则版本号（无规则返回 0）"""
        with self._get_conn() as conn:
            row = conn.execute("SELECT MAX(version) AS v FROM rule_definitions").fetchone()
        return int(row["v"]) if row and row["v"] is not None else 0

    # ================================================================
    # 生产级改造：检测误报标记（待审核队列，P0-5）
    # ================================================================
    def add_detection_feedback(self, log_id: str, session_id: str, content_sample: str,
                               detected_as: str, user_comment: str = "",
                               submitted_by: str = "") -> bool:
        """提交一条误报标记（进入待审核队列）"""
        with self._lock:
            with self._get_conn() as conn:
                conn.execute(
                    f"INSERT INTO detection_feedback "
                    f"(log_id, session_id, content_sample, detected_as, user_comment, "
                    f"status, submitted_by, created_at) "
                    f"VALUES ({self._ph},{self._ph},{self._ph},{self._ph},{self._ph},"
                    f"'pending',{self._ph},{self._ph})",
                    (log_id, session_id, content_sample[:2000], detected_as,
                     user_comment, submitted_by, datetime.now().isoformat()),
                )
                return True

    def list_detection_feedback(self, status: Optional[str] = None,
                                limit: int = 100) -> List[Dict[str, Any]]:
        """误报标记列表（status 过滤：pending/approved/rejected）"""
        with self._get_conn() as conn:
            if status:
                rows = conn.execute(
                    f"SELECT * FROM detection_feedback WHERE status = {self._ph} "
                    f"ORDER BY created_at DESC LIMIT {int(limit)}",
                    (status,),
                ).fetchall()
            else:
                rows = conn.execute(
                    f"SELECT * FROM detection_feedback ORDER BY created_at DESC LIMIT {int(limit)}"
                ).fetchall()
        return [dict(r) for r in rows]

    def review_detection_feedback(self, feedback_id: int, status: str,
                                  reviewed_by: str = "") -> bool:
        """审核误报标记（approved=确认误报 / rejected=维持原判）"""
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute(
                    f"UPDATE detection_feedback SET status = {self._ph}, "
                    f"reviewed_by = {self._ph}, reviewed_at = {self._ph} "
                    f"WHERE id = {self._ph}",
                    (status, reviewed_by, datetime.now().isoformat(), int(feedback_id)),
                )
                return cur.rowcount > 0

    def get_user_force_mfa(self, username: str) -> bool:
        """用户是否被标记强制 MFA（admin/operator/auditor）"""
        with self._get_conn() as conn:
            row = conn.execute(
                f"SELECT force_mfa FROM sys_users WHERE username = {self._ph}",
                (username,),
            ).fetchone()
        return bool(row and row["force_mfa"])

    def set_user_force_mfa(self, username: str, forced: bool) -> bool:
        """设置/取消强制 MFA 标记"""
        with self._lock:
            with self._get_conn() as conn:
                cur = conn.execute(
                    f"UPDATE sys_users SET force_mfa = {self._ph}, "
                    f"updated_at = {self._ph} WHERE username = {self._ph}",
                    (bool(forced), datetime.now().isoformat(), username),
                )
                return cur.rowcount > 0
