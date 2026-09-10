# -*- coding: utf-8 -*-
"""LLM 供应商适配（P2-6：多供应商接入对话主链）

- zhipu   : 智谱 GLM（langchain_community ChatZhipuAI）
- openai  : OpenAI 兼容端点（langchain_openai ChatOpenAI，支持内网 vLLM/Ollama/私有网关）

依赖 llm_runtime 解析出的运行时配置（provider/api_key/base_url/model），
返回 LangChain BaseChatModel（与现有 LCEL 链 prompt_template | llm | parser 兼容）。
"""
import logging

logger = logging.getLogger("llm_providers")


def build_chat_model(cfg: dict):
    """按运行时配置构建对话主链模型；无法构建（未配 Key / 依赖缺失）返回 None"""
    provider = (cfg or {}).get("provider", "zhipu")
    api_key = (cfg or {}).get("api_key", "")
    model = (cfg or {}).get("model") or ""
    base_url = ((cfg or {}).get("base_url") or "").rstrip("/")
    if not api_key:
        return None

    try:
        if provider == "openai":
            from langchain_openai import ChatOpenAI
            return ChatOpenAI(
                model=model or "gpt-4o-mini",
                temperature=0,
                api_key=api_key,
                base_url=base_url or None,
            )
        # 默认：智谱 GLM
        from langchain_community.chat_models import ChatZhipuAI
        return ChatZhipuAI(
            model=model or "glm-4",
            temperature=0,
            zhipuai_api_key=api_key,
        )
    except Exception as e:  # noqa: BLE001
        logger.warning("构建对话主链模型失败（provider=%s）: %s", provider, e)
        return None
