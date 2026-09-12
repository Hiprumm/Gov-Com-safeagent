# -*- coding: utf-8 -*-
"""P1-1 路由按域拆分脚本（一次性工具）

将 ai_service/main.py 中的路由函数按业务域原样搬运到 routers/*.py：
- 仅移动函数定义，逻辑逐字节保留（仅装饰器 @app. → @router.）；
- 保持各域内路由原始注册顺序（FastAPI 路由顺序敏感：特定端点先于参数化端点）；
- main.py 保留：装配入口 / 中间件 / 启动初始化 / 看板 / 系统 / 指标 / WS / KB 路由；
- 跨域共享单例收敛至 app_deps.py，守卫函数收敛至 routers/auth.py。

用法：python tools/split_routers.py
边界用断言保护：若 main.py 行号与预期不符则中止，不会产生半成品。
"""
import os
import re
import sys

SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ai_service", "main.py")
AI = os.path.dirname(os.path.abspath(__file__)) + os.sep + ".." + os.sep + "ai_service"
ROUTERS = os.path.join(AI, "routers")

lines = open(SRC, encoding="utf-8").read().split("\n")
N = len(lines)


def L(n):  # 1-indexed -> text
    return lines[n - 1] if 1 <= n <= N else "<EOF>"


def assert_line(n, prefix):
    if not L(n).lstrip().startswith(prefix):
        print(f"[FATAL] 边界断言失败: 第{n}行应为 '{prefix}...'，实际: {L(n)!r}")
        sys.exit(1)


# ---------------- 边界断言（防止行号漂移导致误切） ----------------
assert_line(388, '@app.post("/api/security/detect_input"')
assert_line(1069, "# =")
assert_line(1100, '@app.get("/api/audit/logs/recent")')
assert_line(1202, '@app.get("/api/audit/forward")')
assert_line(1237, '@app.get("/api/audit/anchor")')
assert_line(1315, '@app.get("/api/audit/forward/history")')
assert_line(1324, '@app.get("/api/audit/logs/verify")')
assert_line(1543, "# =")
assert_line(1544, "# 安全管控台：风险看板聚合接口")
assert_line(1706, "# =")
assert_line(1707, "# 安全管控台：安全策略中心")
assert_line(1782, "# =")
assert_line(1783, "# T5 合规标准对接")
assert_line(1856, '@app.get("/api/aigc/label")')
assert_line(1874, "def _optimization_write_guard")
assert_line(2081, '@app.post("/api/agent/run")')
assert_line(2426, '@app.get("/api/health")')
assert_line(2438, '@app.post("/api/auth/login")')
assert_line(2777, '@app.get("/api/admin/users")')
assert_line(2969, '@app.post("/api/security/approval/approve')
assert_line(3123, '@app.post("/api/security/kb_poisoning/detect_pdf")')
assert_line(3436, '@app.get("/api/scenarios")')
assert_line(3575, '@app.post("/api/replay/record")')
assert_line(3701, '@app.get("/api/evaluation/report")')
assert_line(3758, '@app.get("/api/model/config")')
assert_line(3835, '@app.get("/api/notifications")')
assert_line(3989, "_SERVICE_START = datetime.now()")
assert_line(4153, "def _operator(req: Request) -> str:")
assert_line(4308, "# ---- 合规对标报告 ----")

# ---------------- 域 -> (start, end) 区间（1-indexed，含端点） ----------------
# 顺序为文件内出现顺序；同一域内多段按此顺序拼接
DOMAINS = {
    "security": [
        (388, 1068),   # 检测 / 工具 / 审批查看 / 扫描
        (1873, 2080),  # 优化闭环 + eval_calc
        (2968, 3122),  # 审批 approve / reject / status
        (3123, 3435),  # KB 投毒 / 会话风险 / 跨源 / 绕测 / PSSU
        (3436, 3574),  # 场景
        (3575, 3700),  # 回放
        (3701, 3757),  # 评测
    ],
    "audit": [
        (1069, 1201),  # 审计日志 / 保护 / 留存（审计外发切走）
        (1237, 1314),  # anchor / tsa / archives
        (1324, 1540),  # 链校验 / 检索 / 导出 / 统计
    ],
    "agent": [(2081, 2425)],
    "auth": [(2438, 2776)],  # 认证 + 共享守卫（_admin_guard 等）
    "admin": [(2777, 2967)],
    "config": [
        (1202, 1236),  # 审计外发（读/改/测试）
        (1315, 1323),  # 审计外发历史
        (1706, 1781),  # 安全策略（含段首横幅）
        (1855, 1872),  # AIGC 标识配置
        (3758, 3821),  # 模型接入
        (3835, 3988),  # 通知
    ],
    "governance": [
        (1782, 1854),  # 合规报告 / 关键词 / 内容安全
        (4153, 4306),  # 应急 / 生态 / 开放 / PIPL
        (4308, 4316),  # 合规对标报告（第二条）
    ],
}

# 校验区间互不重叠且均在文件内
covered = []
for dom, ranges in DOMAINS.items():
    for s, e in ranges:
        assert 1 <= s <= e <= N, f"{dom} 区间越界: {s}-{e}"
        for cs, ce in covered:
            assert not (s <= ce and cs <= e), f"区间重叠: {dom} {s}-{e} 与 {cs}-{ce}"
        covered.append((s, e))
covered.sort()

print(f"[OK] 共 {len(covered)} 段将被搬运，main.py 总行数 {N}")

HEADER_COMMON = '''# -*- coding: utf-8 -*-
"""{title} 路由模块 —— P1-1 按业务域拆分（原 main.py 同域路由收敛）

- URL 与行为与原 main.py 完全一致，仅注册载体由 app 改为 router，由 main.py include_router 装配；
- 共享单例（input_detector / audit_logger / gov_agent …）来自 app_deps.py，与 main 共用同一实例；
- 跨域共享守卫（_admin_guard / _login_guard / _assert_session_owner / _pw_fields / _body / _ROLES）
  收敛于 routers.auth.py。
"""
import sys
import os
import time
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import List, Dict, Any, Optional
from datetime import datetime

from fastapi import APIRouter, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import JSONResponse, FileResponse, StreamingResponse

from models.schemas import (
    DetectionResult, BatchDetectionRequest, BatchDetectionResponse,
    FileDetectionRequest, FileUploadRequest,
    ToolCallRequest, ToolRiskResult,
    PluginScanRequest, PluginScanResult,
    AuditLog, EvaluationMetrics,
    ApprovalRequest, ApprovalResponse,
    RiskLevel,
)

from config import settings
from auth import (
    DEMO_USERS, verify_password, authenticate, create_token, revoke_token,
    get_user_by_token, current_identity, list_demo_accounts,
    check_password_policy, mfa_config, mfa_status, begin_mfa_enroll,
    confirm_mfa_enroll, disable_mfa, create_mfa_ticket, verify_mfa_ticket,
    sso_enabled, sso_header_name, resolve_sso_identity,
    sso_signature_required, sso_ip_restricted,
)
from app_deps import (
    input_detector, tool_evaluator, approval_engine, kb_poisoning_detector,
    cross_source_correlator, bypass_tester, plugin_scanner, mcp_scanner,
    skill_analyzer, combination_detector, operation_guard, audit_logger,
    metrics_calculator, gov_agent, policy_manager, permission_engine,
    _apply_policy_hot,
)
'''

EXTRA = {
    "security": '''import asyncio
from security.session_risk_accumulator import session_risk_accumulator
from security.operation_guard import OperationIntent, ActionType as GuardActionType
from websocket.manager import push_approval_update, push_risk_alert
from routers.auth import _admin_guard, _login_guard, _assert_session_owner, _pw_fields, _body, _ROLES
''',
    "audit": '''from routers.auth import _admin_guard, _login_guard, _assert_session_owner, _pw_fields, _body, _ROLES
''',
    "agent": '''from routers.auth import _admin_guard, _login_guard, _assert_session_owner, _pw_fields, _body, _ROLES
''',
    "auth": '',
    "admin": '''from routers.auth import _admin_guard, _login_guard, _assert_session_owner, _pw_fields, _body, _ROLES
''',
    "config": '''from routers.auth import _admin_guard, _login_guard, _assert_session_owner, _pw_fields, _body, _ROLES
''',
    "governance": '''from audit.audit_logger import AuditLogger
from routers.auth import _admin_guard, _login_guard, _assert_session_owner, _pw_fields, _body, _ROLES
''',
}

TITLES = {
    "security": "安全检测 / 工具管控 / 审批 / 运行时 / 优化闭环 / 场景 / 回放 / 评测",
    "audit": "审计日志 / 审计保护 / 锚点 / TSA / 归档 / 链校验",
    "agent": "智能体问答 / 文件 / 会话管理",
    "auth": "认证 / MFA / SSO / 共享守卫",
    "admin": "用户与组织管理",
    "config": "安全策略 / 模型接入 / 通知通道 / 审计外发 / AIGC 标识",
    "governance": "合规报告 / 应急联动 / 开放生态 / PIPL / 开放问答",
}


def extract(s, e):
    """提取行区间并替换 @app. 装饰器为 @router."""
    chunk = "\n".join(lines[s - 1:e])
    # 仅替换行首装饰器；保留文件内其余 @app. 引用不变
    chunk = re.sub(r'^@app\.(get|post|put|delete|websocket)', r'@router.\1', chunk, flags=re.M)
    return chunk


os.makedirs(ROUTERS, exist_ok=True)
open(os.path.join(ROUTERS, "__init__.py"), "w", encoding="utf-8").write(
    "# -*- coding: utf-8 -*-\n\"\"\"路由包（P1-1 按业务域拆分），由 main.py 统一装配。\"\"\"\n"
)

for dom, ranges in DOMAINS.items():
    body_parts = []
    for s, e in ranges:
        body_parts.append(extract(s, e))
    body = "\n\n\n".join(body_parts)
    header = HEADER_COMMON.format(title=TITLES[dom])
    extra = EXTRA[dom]
    content = header + ("\n" + extra if extra else "") + f"\n\nrouter = APIRouter()\n\n\n{body}\n"
    path = os.path.join(ROUTERS, f"{dom}.py")
    open(path, "w", encoding="utf-8").write(content)
    print(f"[OK] 已生成 routers/{dom}.py（{len(ranges)} 段，{len(body.splitlines())} 行）")

# ---------------- 重写 main.py ----------------
# 1) 单例 + _apply_policy_hot 收敛到 app_deps
SINGLETON_START, SINGLETON_END = 176, 208
assert_line(SINGLETON_START, "input_detector = InputDetectionService()")
assert_line(SINGLETON_END - 8, "def _apply_policy_hot():")
app_deps_import = (
    "# 共享单例（P1-1 收敛至 app_deps.py：main 与 routers/* 共用同一实例）\n"
    "from app_deps import (\n"
    "    input_detector, tool_evaluator, approval_engine, kb_poisoning_detector,\n"
    "    cross_source_correlator, bypass_tester, plugin_scanner, mcp_scanner,\n"
    "    skill_analyzer, combination_detector, operation_guard, audit_logger,\n"
    "    metrics_calculator, gov_agent, policy_manager, permission_engine,\n"
    "    _apply_policy_hot,\n"
    ")\n"
)

moved = {(s, e) for s, e in covered}
marker_by_dom = {}
for dom, ranges in DOMAINS.items():
    for s, e in ranges:
        marker_by_dom[s] = dom

out = []
i = 1
while i <= N:
    if i == SINGLETON_START:
        out.append(app_deps_import)
        i = SINGLETON_END + 1
        continue
    if i in marker_by_dom:
        dom = marker_by_dom[i]
        # 找到该区间
        s, e = next((ss, ee) for ss, ee in DOMAINS[dom] if ss == i)
        out.append(f"\n# ---- P1-1: 本域路由已拆分至 routers/{dom}.py（URL 全兼容） ----\n")
        i = e + 1
        continue
    out.append(lines[i - 1])
    i += 1

assembly = (
    "\n\n# ==================== 路由装配（P1-1 按业务域拆分） ====================\n"
    "# 保持域间顺序与注册顺序一致：特定端点先于参数化端点（既有工程约定）。\n"
    "from routers import security, audit, agent, auth, admin, config, governance\n"
    "app.include_router(security.router)\n"
    "app.include_router(audit.router)\n"
    "app.include_router(agent.router)\n"
    "app.include_router(auth.router)\n"
    "app.include_router(admin.router)\n"
    "app.include_router(config.router)\n"
    "app.include_router(governance.router)\n"
)
out.append(assembly)

new_main = "\n".join(out)
open(SRC, "w", encoding="utf-8").write(new_main)
print(f"[OK] main.py 已重写：{N} 行 -> {len(new_main.splitlines())} 行")
print("[DONE] 请执行 py_compile 与导入冒烟验证")
