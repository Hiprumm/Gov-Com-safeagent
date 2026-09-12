# -*- coding: utf-8 -*-
"""存储后端公共基类（P0-2 双轨收敛）

SQLite（storage.Storage）与 PostgreSQL（postgres_storage.PostgresStorage）
两套后端共享的公共逻辑收敛于此：TOTP 密钥加解密（security.secret_box）与
MFA 读写、会话标题生成。子类只需提供 `_get_conn()` 与 `_ph`（SQL 占位符）。

占位符差异：SQLite 用 `?`，PostgreSQL 用 `%s`，由子类覆盖 `_ph`。
"""
from typing import Any, Dict, Optional


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
