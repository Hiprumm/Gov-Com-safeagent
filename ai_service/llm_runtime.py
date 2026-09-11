# -*- coding: utf-8 -*-
"""模型接入运行时配置（P2-6：内网/离线部署的 LLM 服务接入）

- 默认接入：智谱 GLM（ZHIPU_API_KEY，open.bigmodel.cn）
- 可通过界面配置覆盖为任意 OpenAI 兼容端点（内网 vLLM / Ollama / 私有化网关）：
  provider / api_key / base_url / model，持久化于 policy_config(llm_runtime)
- 修改即时热生效（分类层 classify 使用），无需重启服务
"""
import json
import urllib.request
import urllib.error
from config import settings
from storage import get_storage

STORE_KEY = "llm_runtime"
DEFAULT_ZHIPU_BASE = "https://open.bigmodel.cn/api/paas/v4"
DEFAULT_MODEL = "glm-4-flash"


def completions_url(base_url: str) -> str:
    b = (base_url or "").rstrip("/")
    if b.endswith("/chat/completions"):
        return b
    return b + "/chat/completions"


def default_config() -> dict:
    return {
        "provider": "zhipu",
        "api_key": settings.ZHIPU_API_KEY or "",
        "base_url": DEFAULT_ZHIPU_BASE,
        "model": DEFAULT_MODEL,
        # 备用模型（多供应商容灾）：主模型故障/超时自动切换
        "backup_provider": "openai",
        "backup_api_key": "",
        "backup_base_url": "",
        "backup_model": "",
    }


def load_config() -> dict:
    """合并默认（env）与数据库覆盖配置"""
    cfg = default_config()
    try:
        over = get_storage().get_setting(STORE_KEY) or {}
    except Exception:
        over = {}
    if over:
        if over.get("api_key"):
            cfg["api_key"] = over["api_key"]
        for k in ("provider", "base_url", "model"):
            if over.get(k):
                cfg[k] = over[k]
        if over.get("backup_provider"):
            cfg["backup_provider"] = over["backup_provider"]
        if "backup_api_key" in over:
            cfg["backup_api_key"] = over.get("backup_api_key") or ""
        if over.get("backup_base_url"):
            cfg["backup_base_url"] = over["backup_base_url"]
        if over.get("backup_model"):
            cfg["backup_model"] = over["backup_model"]
    return cfg


def save_config(provider: str, api_key: str, base_url: str, model: str,
                overwrite_key: bool = True,
                backup_provider: str | None = None,
                backup_api_key: str | None = None,
                backup_base_url: str | None = None,
                backup_model: str | None = None) -> dict:
    """保存模型接入覆盖配置。api_key 为空表示清除已存 Key（回到 .env）。

    备用模型参数为 None 时不修改；backup_api_key 传 '' 表示清除备用 Key。
    """
    cfg = load_config()
    if provider in ("zhipu", "openai"):
        cfg["provider"] = provider
    if base_url and base_url.startswith(("http://", "https://")):
        cfg["base_url"] = base_url.rstrip("/")
    if model:
        cfg["model"] = model
    if api_key is not None:  # None 表示不修改（前端留空不清除）
        cfg["api_key"] = api_key

    if backup_provider in ("zhipu", "openai"):
        cfg["backup_provider"] = backup_provider
    if backup_base_url is not None and backup_base_url.startswith(("http://", "https://")):
        cfg["backup_base_url"] = backup_base_url.rstrip("/")
    if backup_model is not None:
        cfg["backup_model"] = backup_model
    if backup_api_key is not None:
        cfg["backup_api_key"] = backup_api_key

    get_storage().set_setting(STORE_KEY, {
        "provider": cfg["provider"],
        "api_key": cfg["api_key"],
        "base_url": cfg["base_url"],
        "model": cfg["model"],
        "backup_provider": cfg["backup_provider"],
        "backup_api_key": cfg["backup_api_key"],
        "backup_base_url": cfg["backup_base_url"],
        "backup_model": cfg["backup_model"],
    })
    # 写后读校验：确认配置已真正持久化（而非仅停留在内存），失败即抛错由调用方反馈
    persisted = get_storage().get_setting(STORE_KEY) or {}
    if persisted.get("api_key", "") != (cfg["api_key"] or ""):
        raise RuntimeError("模型配置写入失败：存储中的 api_key 与本次保存不一致")
    if persisted.get("model", "") != (cfg["model"] or ""):
        raise RuntimeError("模型配置写入失败：存储中的 model 与本次保存不一致")
    return cfg


def runtime_status() -> dict:
    """当前生效配置摘要（不回显完整 Key）"""
    cfg = load_config()
    env_key = bool(settings.ZHIPU_API_KEY)
    return {
        "provider": cfg["provider"],
        "model": cfg["model"],
        "base_url": cfg["base_url"],
        "completions_url": completions_url(cfg["base_url"]),
        "has_key": bool(cfg["api_key"]),
        "env_key_present": env_key,
        "stored_override": bool(get_storage().get_setting(STORE_KEY)),
        "backup_provider": cfg.get("backup_provider", "openai"),
        "backup_base_url": cfg.get("backup_base_url", ""),
        "backup_model": cfg.get("backup_model", ""),
        "backup_has_key": bool(cfg.get("backup_api_key")),
    }


def test_connection(provider: str, api_key: str, base_url: str, model: str) -> tuple:
    """连通性测试（同步）。返回 (ok, detail)"""
    try:
        url = completions_url(base_url or DEFAULT_ZHIPU_BASE)
        payload = json.dumps({
            "model": model or DEFAULT_MODEL,
            "messages": [{"role": "user", "content": "ping"}],
            "max_tokens": 1,
            "stream": False,
        }).encode("utf-8")
        req = urllib.request.Request(
            url, data=payload, method="POST",
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {api_key or ''}"},
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            body = resp.read().decode("utf-8", "replace")[:200]
            return True, f"连通成功（HTTP {resp.status}）"
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:160] if hasattr(e, "read") else str(e)
        return False, f"HTTP {e.code}: {detail}"
    except Exception as e:  # noqa: BLE001
        return False, str(e)[:160]
