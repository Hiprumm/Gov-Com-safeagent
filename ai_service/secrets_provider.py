# -*- coding: utf-8 -*-
"""统一密钥供给器（生产级改造：密钥不落盘）

取值链路（优先级从高到低）：
1. 环境变量 / .env（生产推荐：容器编排或 CI 注入，如 docker compose --env-file）
2. KMS 适配器（Vault / 云 KMS，通过 register_provider 注册后启用；本项目预留接口）
3. 演示模式兜底：data/ 下的落盘密钥文件（仅 ENV!=production 允许，
   生产模式直接报错，对齐 docs/改进.md P0-2「禁止密钥落盘到 data/」）

用法：
    from secrets_provider import get_secret
    key = get_secret("GRADED_HMAC_KEY", fallback_file="data/graded_hmac.key")
"""
from __future__ import annotations

import os
import secrets as _secrets
import threading
from typing import Dict, Optional, Protocol


class KmsProvider(Protocol):
    """KMS 适配器协议：接入 Vault / 阿里云 KMS / AWS KMS 时实现此接口。

    要求：get(name) 返回密钥字符串；找不到时返回 None（不抛错，
    由调用方继续走下一优先级）。
    """

    def get(self, name: str) -> Optional[str]: ...


class _SecretsRegistry:
    def __init__(self) -> None:
        self._providers: list = []
        self._lock = threading.Lock()

    def register_provider(self, provider: KmsProvider) -> None:
        """注册 KMS 适配器（如 VaultAppRoleProvider / AliyunKmsProvider）。"""
        with self._lock:
            self._providers.append(provider)

    def resolve(self, name: str) -> Optional[str]:
        """按注册顺序询问各 KMS 适配器。"""
        with self._lock:
            providers = list(self._providers)
        for p in providers:
            try:
                val = p.get(name)
                if val:
                    return val.strip()
            except Exception:  # noqa: BLE001 - KMS 故障时降级到下一优先级
                continue
        return None


_REGISTRY = _SecretsRegistry()

# 环境变量名 → 演示模式兜底文件（相对 ai_service/）
_FALLBACK_FILES: Dict[str, str] = {
    "AUTH_JWT_SECRET": os.path.join("data", "jwt_secret.key"),
    "GRADED_HMAC_KEY": os.path.join("data", "graded_hmac.key"),
    "ZKP_PROVING_KEY": os.path.join("data", "zkp_proving.key"),
    "AUTH_MFA_SECRET_KEY": os.path.join("data", "mfa_key.key"),
}

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def register_provider(provider: KmsProvider) -> None:
    _REGISTRY.register_provider(provider)


def _is_production() -> bool:
    try:
        from config import settings
        return settings.is_production()
    except Exception:  # noqa: BLE001
        # 配置不可用时保守视为生产（拒绝落盘兜底）
        return True


def _load_fallback_file(path: str) -> Optional[str]:
    full = path if os.path.isabs(path) else os.path.join(_BASE_DIR, path)
    if os.path.isfile(full):
        try:
            with open(full, "r", encoding="utf-8") as f:
                data = f.read().strip()
            return data or None
        except Exception:  # noqa: BLE001
            return None
    return None


def _write_fallback_file(path: str, value: str) -> None:
    full = path if os.path.isabs(path) else os.path.join(_BASE_DIR, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8") as f:
        f.write(value)
    try:
        os.chmod(full, 0o600)
    except Exception:  # noqa: BLE001 - Windows 无 POSIX 权限
        pass


def get_secret(name: str, fallback_file: Optional[str] = None,
               generate: bool = True, min_len: int = 32) -> str:
    """取密钥：env → KMS → 演示模式落盘文件（不存在则生成并落盘）。

    Args:
        name: 约定密钥名（同时作为环境变量名，如 GRADED_HMAC_KEY）
        fallback_file: 演示模式兜底文件路径（缺省查 _FALLBACK_FILES 映射）
        generate: 全链路取不到时是否生成随机密钥（False 则返回空串）
        min_len: env 注入密钥的最小长度（低于则告警但仍接受）

    生产模式（ENV=production）：不落盘；env/KMS 均未提供且 generate=True 时
    直接抛错（防止多实例各自随机生成导致签名互不认可）。
    """
    # 1) 环境变量 / .env
    val = os.environ.get(name, "").strip()
    source = "env"
    # 2) KMS 适配器
    if not val:
        val = _REGISTRY.resolve(name) or ""
        if val:
            source = "kms"
    if val:
        if len(val) < min_len:
            print(f"[SECRETS][WARN] {name} 仅 {len(val)} 字符（建议 ≥{min_len}，"
                  f"如 openssl rand -hex 32），来源={source}")
        return val

    fallback = fallback_file or _FALLBACK_FILES.get(name)

    # 3a) 生产模式：禁止落盘兜底 → 报错
    if _is_production():
        if not generate:
            return ""
        raise RuntimeError(
            f"密钥 {name} 未通过环境变量或 KMS 注入；生产模式禁止生成并落盘到 data/。"
            f"请在部署环境显式注入（如 docker compose env_file 或 Vault）。"
        )

    # 3b) 演示模式：data/ 文件兜底（不存在则生成）
    if fallback:
        existing = _load_fallback_file(fallback)
        if existing:
            return existing
        if not generate:
            return ""
        generated = _secrets.token_hex(32)
        _write_fallback_file(fallback, generated)
        print(f"[SECRETS][WARN] {name} 未配置，已生成并持久化到 {fallback}（仅限演示模式；"
              f"生产请用环境变量/KMS 注入）")
        return generated

    # 无兜底文件且未取到
    if not generate:
        return ""
    print(f"[SECRETS][WARN] {name} 未配置且无兜底文件，使用进程内临时密钥（重启后失效）")
    return _secrets.token_hex(32)
