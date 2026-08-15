"""
AIGC 内容标识模块 (AIGC Content Labeling)
==========================================

对接《生成式人工智能服务管理暂行办法》和 GB/T 45654-2025 要求：
1. 显式标识：输出内容中附加可见的 AI 生成声明
2. 隐式标识：在响应元数据中嵌入模型信息、服务提供者、生成时间、内容ID
3. 元数据嵌入：为下游溯源/备案提供结构化信息

使用方式：
    from security.aigc_labeling import build_aigc_label, build_aigc_metadata, apply_aigc_label

    metadata = build_aigc_metadata(model="gov-agent-1.0", session_id="sess-1")
    response = apply_aigc_label("生成的内容...", metadata)
"""

import hashlib
import uuid
from datetime import datetime
from typing import Dict, Any


# 服务提供者与备案信息（示例配置，可按实际部署修改）
SERVICE_PROVIDER = "政企大模型智能体安全平台"
SERVICE_PROVIDER_CODE = "CN-GOV-AGENT-SEC"
MODEL_NAME = "gov-agent-1.0"
MODEL_VERSION = "1.0.0"
MODEL_TYPE = "generative_ai_agent"
ICP_BEIAN = "备案号：粤ICP备XXXXXXXX号"
ALGORITHM_FILING = "算法备案号：T-2026-XXXX"
AIGC_FILING = "大模型备案号：T-2026-XXXX"

# 显式标识文案
EXPLICIT_LABEL_TEMPLATE = (
    "【AI生成内容】本内容由{MODEL_NAME}生成，仅供参考，请注意甄别。"
    "{ICP} {ALG} {AIGC} 生成时间：{TIME}"
)

# 隐式标识（HTML注释，不影响正常显示，便于机器识别）
IMPLICIT_MARKER_PREFIX = "\u200B<!-- AIGC-META:"


def build_aigc_metadata(model: str = MODEL_NAME,
                        provider: str = SERVICE_PROVIDER,
                        provider_code: str = SERVICE_PROVIDER_CODE,
                        session_id: str = "",
                        content: str = "") -> Dict[str, Any]:
    """构建 AIGC 内容标识元数据

    元数据包含：模型信息、服务提供者、备案信息、生成时间、内容指纹、内容ID
    """
    now = datetime.now()
    content_id = uuid.uuid4().hex[:16]
    # 内容指纹（隐式标识校验用）
    content_hash = hashlib.sha256(
        f"{content_id}:{model}:{now.isoformat()}:{content}".encode("utf-8")
    ).hexdigest()[:32] if content else ""

    return {
        "content_id": content_id,
        "model_name": model,
        "model_version": MODEL_VERSION,
        "model_type": MODEL_TYPE,
        "provider": provider,
        "provider_code": provider_code,
        "icp_beian": ICP_BEIAN,
        "algorithm_filing": ALGORITHM_FILING,
        "aigc_filing": AIGC_FILING,
        "generated_at": now.isoformat(),
        "session_id": session_id,
        "content_hash": content_hash,
        "aigc": True,
    }


def build_explicit_label(metadata: Dict[str, Any]) -> str:
    """生成显式 AI 生成标识文本"""
    return EXPLICIT_LABEL_TEMPLATE.format(
        MODEL_NAME=metadata.get("model_name", MODEL_NAME),
        ICP=metadata.get("icp_beian", ICP_BEIAN),
        ALG=metadata.get("algorithm_filing", ALGORITHM_FILING),
        AIGC=metadata.get("aigc_filing", AIGC_FILING),
        TIME=datetime.fromisoformat(metadata["generated_at"]).strftime("%Y-%m-%d %H:%M:%S")
        if metadata.get("generated_at") else datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )


def build_implicit_marker(metadata: Dict[str, Any]) -> str:
    """生成隐式标识（不可见的元数据标记，嵌入输出内容）"""
    payload = {
        "content_id": metadata.get("content_id", ""),
        "model": metadata.get("model_name", ""),
        "provider": metadata.get("provider_code", ""),
        "time": metadata.get("generated_at", ""),
        "hash": metadata.get("content_hash", ""),
    }
    marker = IMPLICIT_MARKER_PREFIX + repr(payload) + " -->\u200B"
    return marker


def apply_aigc_label(content: str, metadata: Dict[str, Any],
                     include_implicit: bool = True) -> Dict[str, Any]:
    """为生成内容应用 AIGC 标识（显式 + 隐式）

    返回: {
        "labeled_content": 添加显式标识后的正文,
        "content_with_marker": 含隐式元数据标记的完整内容,
        "explicit_label": 显式标识文本,
        "implicit_marker": 隐式标识文本,
        "metadata": 元数据,
    }
    """
    explicit = build_explicit_label(metadata)
    labeled = f"{explicit}\n\n{content}"
    if include_implicit:
        implicit = build_implicit_marker(metadata)
        full = labeled + "\n" + implicit
    else:
        implicit = ""
        full = labeled
    return {
        "labeled_content": labeled,
        "content_with_marker": full,
        "explicit_label": explicit,
        "implicit_marker": implicit,
        "metadata": metadata,
    }


def verify_implicit_marker(text: str) -> Dict[str, Any]:
    """校验内容中是否含隐式 AIGC 标识，并解析元数据"""
    start = text.find(IMPLICIT_MARKER_PREFIX)
    if start == -1:
        return {"found": False, "metadata": None}
    end = text.find(" -->\u200B", start)
    if end == -1:
        return {"found": False, "metadata": None}
    try:
        payload = eval(text[start + len(IMPLICIT_MARKER_PREFIX):end].strip())
        return {"found": True, "metadata": payload if isinstance(payload, dict) else None}
    except Exception:
        return {"found": True, "metadata": None}


def get_aigc_config() -> Dict[str, Any]:
    """返回 AIGC 标识配置（用于前端展示与合规检查）"""
    return {
        "provider": SERVICE_PROVIDER,
        "provider_code": SERVICE_PROVIDER_CODE,
        "model_name": MODEL_NAME,
        "model_version": MODEL_VERSION,
        "model_type": MODEL_TYPE,
        "icp_beian": ICP_BEIAN,
        "algorithm_filing": ALGORITHM_FILING,
        "aigc_filing": AIGC_FILING,
        "explicit_label_enabled": True,
        "implicit_marker_enabled": True,
    }
