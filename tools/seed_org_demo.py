# -*- coding: utf-8 -*-

# P0-1 工程收敛注入：统一路径引导（原脚本逻辑根目录）
import os as _os, sys as _sys
_BASE_DIR = r"x:\ZuoYe\揭榜挂帅26\Gov-Com-safeagent\ai_service"
_sys.path.insert(0, _BASE_DIR)
"""组织级演示数据种子（幂等建号，可重复运行补录审计/审批）。

用途：让“风险看板按角色收敛 / 审批到部门 / 审计到人”能被真实登录演示，而不仅是空看板。
- 建出 2 个业务部门 + 部门负责人(manager) 与业务员(user) 等组织账号（口令统一 admin123）；
- 为 operator / 各业务员 / user 造“今日”检测审计，归属到具体账号与部门；
- 为不同部门造若干条待审批单（requester 落到部门/本人），便于演示部门负责人查看本部门待办。

注意：
- 账号 upsert 幂等；审计/审批每次运行会新增（如需干净重来，可清空 audit_logs / approval_requests 后重跑）。
- 依赖：在 ai_service 目录下运行 `python seed_org_demo.py`。

可直接登录演示的账号（口令均为 admin123）：
  全平台：admin / operator / auditor
  仅本人：user（综合办公室）、biz_li / biz_wang（政务业务处业务员）
  本部门：mgr_sec（信息化与网络安全处负责人）、mgr_biz（政务业务处负责人）
"""
import os, sys, hashlib, secrets
os.chdir(_BASE_DIR)
sys.path.insert(0, os.getcwd())

from storage import get_storage
from models.schemas import RiskLevel

st = get_storage()

# ---------- 1. 补部门 ----------
for d in ["信息化与网络安全处", "政务业务处", "综合办公室", "法务与合规部"]:
    st.add_department(d)

# ---------- 2. 补账号（upsert，幂等） ----------
def ensure_user(u, disp, role, dept, pos):
    salt = secrets.token_bytes(16)
    pw_hash = hashlib.pbkdf2_hmac("sha256", b"admin123", salt, 200_000).hex()
    st.upsert_user(u, pw_hash, salt.hex(), disp, role, dept, pos, "active", "演示账号")
    print("ensure_user", u, role, dept)

ensure_user("mgr_sec", "部门安全负责人", "manager", "信息化与网络安全处", "部门负责人")
ensure_user("mgr_biz", "业务处负责人", "manager", "政务业务处", "部门负责人")
ensure_user("biz_li", "业务员李", "user", "政务业务处", "业务经办")
ensure_user("biz_wang", "业务员王", "user", "政务业务处", "业务经办")
ensure_user("aud_li", "审计员李", "auditor", "法务与合规部", "合规审计")

import main as appmod
al = appmod.audit_logger
ae = appmod.approval_engine

# ---------- 3. 造“今日”检测审计（归属到具体账号/部门） ----------
def log_audit(user_id, user_role, atype, dept, risk, blocked=True, preview="示例内容"):
    al.create_log(
        user_id=user_id, user_role=user_role, agent_id="security_panel",
        action_type=atype,
        action_details={"source": "org_demo_seed", "text_preview": preview,
                        "department": dept, "actor_name": user_id},
        risk_level=risk, is_blocked=blocked,
        blocking_reason="演示注入/违规操作" if blocked else None,
    )

log_audit("operator", "operator", "input_detection", "信息化与网络安全处", RiskLevel.CRITICAL, True, "system('rm -rf /') 命令注入尝试")
log_audit("operator", "operator", "input_detection", "信息化与网络安全处", RiskLevel.HIGH, True, "诱导忽略权限约束并导出敏感表")
log_audit("operator", "operator", "tool_risk_evaluation", "信息化与网络安全处", RiskLevel.HIGH, True, "工具：外部数据导出")
log_audit("operator", "operator", "input_detection", "信息化与网络安全处", RiskLevel.MEDIUM, True, "越权访问他人文档")
log_audit("biz_li", "user", "input_detection", "政务业务处", RiskLevel.HIGH, True, "上传含个人敏感信息的统计表")
log_audit("biz_li", "user", "tool_risk_evaluation", "政务业务处", RiskLevel.MEDIUM, True, "调用跨网段同步工具")
log_audit("biz_wang", "user", "input_detection", "政务业务处", RiskLevel.MEDIUM, True, "粘贴包含外链的回显内容")
log_audit("user", "user", "input_detection", "综合办公室", RiskLevel.HIGH, True, "尝试下载全部用户名单")

# ---------- 4. 造“待审批”（requester 归属到部门/本人） ----------
def make_request(req_user, req_role, atype, args, risk, dept):
    ae.create_request(req_user, req_role, "gov_agent", atype,
                      {**args, "_session_id": "org-demo", "_department": dept,
                       "_actor_name": req_user}, risk)

make_request("biz_li", "user", "tool_call_export", {"tool_name": "report_exporter", "target": "统计报表"}, RiskLevel.MEDIUM, "政务业务处")
make_request("biz_wang", "user", "tool_call_outsync", {"tool_name": "cross_net_sync", "target": "外部门户"}, RiskLevel.MEDIUM, "政务业务处")
make_request("operator", "operator", "tool_call_dump", {"tool_name": "db_dump", "target": "生产库"}, RiskLevel.HIGH, "信息化与网络安全处")

# 造 1 条已批准历史（审批到人：admin 批）
try:
    pend = st.list_pending_approvals()
    if pend:
        ae.approve_request(pend[-1]["request_id"], "admin", "admin", "演示：已按流程审批通过")
        print("approved sample ok")
except Exception as e:
    print("approve skip:", repr(e))

print("SEED_DONE —— 现在可用上述账号在登录页输入 admin123 直接登录演示")
