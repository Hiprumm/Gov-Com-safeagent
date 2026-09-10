# -*- coding: utf-8 -*-
"""敏感字段加密（MFA TOTP 密钥等）

解决的问题：TOTP 密钥此前以**明文**存于 `sys_users.totp_secret`——拿到数据库文件
即可自行生成动态验证码，MFA 形同虚设。

方案：
- 使用 **Fernet**（AES-128-CBC + HMAC-SHA256 认证加密）加密后再入库；
- 密钥来源优先级：`.env` 的 `AUTH_MFA_SECRET_KEY` → `data/mfa_key.key`（自动生成，权限 0600）；
- 兼容历史明文数据：解密函数对**不带前缀**的值原样返回，下次写入时自动升级为密文；
- `cryptography` 不可用时降级为明文并在启动/首次使用时告警，保证系统可用。

密文格式：`enc:v1:<fernet-token>`；空字符串保持空串（表示未绑定）。
"""
import base64
import hashlib
import os
from typing import Optional

_PREFIX = "enc:v1:"
_fernet = None
_init_done = False


def _warn(msg: str) -> None:
    try:
        print(msg)
    except Exception:
        pass


def _derive_key(raw: str) -> bytes:
    """把任意长度口令派生为 Fernet 需要的 32 字节 urlsafe base64 密钥。"""
    digest = hashlib.sha256(raw.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def _load_key() -> Optional[bytes]:
    try:
        from config import settings
    except Exception:
        settings = None

    raw = str(getattr(settings, "AUTH_MFA_SECRET_KEY", "") or "").strip()
    if raw:
        return _derive_key(raw)

    try:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(base, "data", "mfa_key.key")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        if os.path.exists(path):
            with open(path, "rb") as f:
                data = f.read().strip()
            if data:
                return data
        from cryptography.fernet import Fernet
        gen = Fernet.generate_key()
        with open(path, "wb") as f:
            f.write(gen)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
        _warn("[SECRET] 已生成并持久化敏感字段加密密钥 data/mfa_key.key"
              "（生产建议改用 AUTH_MFA_SECRET_KEY 以便多实例共享）")
        return gen
    except Exception as e:
        _warn(f"[SECRET][WARN] 无法准备加密密钥（{type(e).__name__}: {e}）")
        return None


def _get_fernet():
    """惰性初始化 Fernet；不可用时返回 None（调用方降级为明文）。"""
    global _fernet, _init_done
    if _init_done:
        return _fernet
    _init_done = True
    try:
        from cryptography.fernet import Fernet
    except Exception:
        _warn("[SECRET][WARN] 未安装 cryptography，敏感字段将明文存储（建议 pip install cryptography）")
        _fernet = None
        return None
    key = _load_key()
    if not key:
        _fernet = None
        return None
    try:
        _fernet = Fernet(key)
    except Exception as e:
        _warn(f"[SECRET][WARN] 加密密钥无效，敏感字段将明文存储（{e}）")
        _fernet = None
    return _fernet


def encryption_available() -> bool:
    return _get_fernet() is not None


def encrypt_secret(plain: str) -> str:
    """加密敏感值；空串原样返回；加密不可用或失败时原样返回（降级）。"""
    value = plain or ""
    if not value:
        return ""
    if value.startswith(_PREFIX):     # 已是密文，避免二次加密
        return value
    f = _get_fernet()
    if f is None:
        return value
    try:
        token = f.encrypt(value.encode("utf-8")).decode("ascii")
        return f"{_PREFIX}{token}"
    except Exception as e:
        _warn(f"[SECRET][WARN] 加密失败，按明文存储：{e}")
        return value


def decrypt_secret(stored: str) -> str:
    """解密敏感值；历史明文（无前缀）原样返回。"""
    value = stored or ""
    if not value:
        return ""
    if not value.startswith(_PREFIX):
        return value                  # 历史明文 / 降级模式
    f = _get_fernet()
    if f is None:
        return ""                     # 有密文但无法解密（密钥缺失）
    try:
        return f.decrypt(value[len(_PREFIX):].encode("ascii")).decode("utf-8")
    except Exception as e:
        _warn(f"[SECRET][WARN] 解密失败（密钥不匹配？）：{e}")
        return ""


def is_encrypted(stored: str) -> bool:
    """判断存储值是否为密文（供巡检/测试使用）。"""
    return bool(stored) and stored.startswith(_PREFIX)
