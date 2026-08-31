# -*- coding: utf-8 -*-
"""形态 1（SDK 嵌入）quickstart —— <10 行接入任意 Agent 进程"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # pip install 后可省略

from gov_safeagent_sdk import SecurityGuard

guard = SecurityGuard()                                    # ① 初始化（定位安全核心）

verdict = guard.detect_sync("帮我查询公积金政策")            # ② 输入检测
if not verdict.allowed:                                     # ③ 攻击输入 → 拒绝
    print("拦截:", verdict.reason)

tool = guard.check_tool("sess-1", "export_data", {"query": "SELECT * FROM t"})  # ④ 工具治理
print("export_data:", tool.allowed, "|", tool.reason[:50])

answer = guard.filter_output("手机号13812345678")            # ⑤ 输出脱敏
print("脱敏:", answer.sanitized)
