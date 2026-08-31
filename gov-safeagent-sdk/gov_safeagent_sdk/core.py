"""
核心定位与懒加载 —— SDK 与安全核心（ai_service/security）的桥梁

安全核心模块（input_detector / capability_token / operation_guard /
sequence_risk_evaluator / output_filter / audit_logger）仍然是唯一实现，
SDK 通过定位 ai_service 目录加载它们，不复制代码（单一事实来源）。

定位顺序：
1. 环境变量 GOV_SAFEAGENT_CORE（指向 ai_service 目录）
2. 从当前工作目录逐级向上查找 ai_service/security/input_detector.py
3. 从 SDK 包安装位置逐级向上查找（源码部署 / pip install -e 场景）
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Optional

_MARKER = ("security", "input_detector.py")


def _looks_like_core(root: Path) -> bool:
    return (root / _MARKER[0] / _MARKER[1]).is_file()


def find_core_path(explicit: Optional[str] = None) -> Path:
    """定位安全核心所在的 ai_service 目录"""
    candidates: list[Path] = []

    if explicit:
        candidates.append(Path(explicit).resolve())

    env_path = os.environ.get("GOV_SAFEAGENT_CORE")
    if env_path:
        candidates.append(Path(env_path).resolve())

    # 从 cwd 向上找（应用代码在仓库内运行）
    cwd = Path.cwd()
    for base in [cwd, *cwd.parents]:
        candidates.append(base / "ai_service")
        if _looks_like_core(base / "ai_service"):
            break

    # 从 SDK 包位置向上找（pip install -e / 源码部署）
    pkg_dir = Path(__file__).resolve().parent
    for base in [pkg_dir, *pkg_dir.parents]:
        candidates.append(base / "ai_service")

    for cand in candidates:
        if _looks_like_core(cand):
            return cand.resolve()

    raise RuntimeError(
        "gov-safeagent-sdk: 未找到安全核心（ai_service/security）。"
        "请设置环境变量 GOV_SAFEAGENT_CORE 指向 ai_service 目录。"
        f" 已尝试: {[str(c) for c in candidates[:8]]}"
    )


_LOADED = False


def load_core(explicit: Optional[str] = None) -> None:
    """把安全核心目录加入 sys.path 并完成导入（幂等）"""
    global _LOADED
    if _LOADED:
        return
    core = find_core_path(explicit)
    core_str = str(core)
    if core_str not in sys.path:
        sys.path.insert(0, core_str)
    # 触发导入，尽早暴露核心侧的导入错误
    import security.input_detector  # noqa: F401
    import security.capability_token  # noqa: F401
    import security.operation_guard  # noqa: F401
    import security.sequence_risk_evaluator  # noqa: F401
    import security.output_filter  # noqa: F401
    _LOADED = True
