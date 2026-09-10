# -*- coding: utf-8 -*-
"""账号与角色体系（数据库化 + 组织/岗位）

将账号从“写死的演示账号”升级为“组织级用户库”：
- 用户存于 SQLite `sys_users`（username/display_name/role/department/position/status/…），
  由后台「用户与组织」管理，可新增员工、按岗授权、启停账号、重置密码；
- 密码使用“随机盐 + PBKDF2-SHA256”，不在库中存明文；
- token 以进程内存保存（重启失效）；后续可平滑接入单位统一身份（SSO/AD）；
- 兼容演示：首次启动自动 seed admin/operator/auditor/user 四个账号（口令 admin123），
  后续可在后台修改，供评审与快速体验；真实部署由管理员在后台建账号并分发。

职责分离：admin 管全部；operator 安全运营；auditor 合规审计；user 业务用户。
导航按角色收敛、审批与审计记录到具体账号（人）。
"""
import hashlib
import secrets
import hmac
import threading
from typing import Dict, Optional
from storage import get_storage

# 演示账号 seed 定义（首次建库自动写入，密码统一 admin123，真实部署可改/停用）
DEMO_USERS: Dict[str, Dict] = {
    "admin": {"display_name": "系统管理员", "role": "admin",
              "department": "信息化与网络安全处", "position": "安全管理员", "desc": "全部模块"},
    "operator": {"display_name": "安全运维员", "role": "operator",
                 "department": "信息化与网络安全处", "position": "安全运维", "desc": "检测 / 审批 / 工具 / 运行时"},
    "auditor": {"display_name": "合规审计员", "role": "auditor",
                "department": "法务与合规部", "position": "合规审计", "desc": "看板 / 审计 / 审批查看"},
    "user": {"display_name": "业务用户", "role": "user",
             "department": "综合办公室", "position": "业务经办", "desc": "智能问答 / 风险看板"},
}

ROLES = ("admin", "operator", "auditor", "manager", "user")
_LOCK = threading.Lock()
# token -> username
_TOKENS: Dict[str, str] = {}


def _hash(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000).hex()


def _seed_if_empty() -> None:
    """库内无用户时，自动写入四个演示账号（避免冷启动无账号可登）。"""
    try:
        if get_storage().count_users() > 0:
            return
    except Exception:
        return
    for username, info in DEMO_USERS.items():
        salt = secrets.token_bytes(16)
        _insert_user(username, _hash("admin123", salt), salt.hex(),
                     info["display_name"], info["role"], info["department"], info["position"])


def _insert_user(username, pw_hash, salt_hex, display_name, role,
                 department="", position="", note="") -> None:
    get_storage().upsert_user(
        username, pw_hash, salt_hex, display_name, role,
        department or "", position or "", "active", note,
    )


def verify_password(username: str, password: str) -> bool:
    """校验密码：查库，用该用户自身 salt 做恒定时间比较；用户不存在/被禁用返回 False。"""
    _seed_if_empty()
    row = get_storage().get_user_password(username)
    if not row or row.get("status") != "active":
        return False
    try:
        salt = bytes.fromhex(row["salt"])
    except (ValueError, TypeError):
        return False
    expected = row["password_hash"]
    return hmac.compare_digest(_hash(password, salt), expected)


def create_token(username: str) -> str:
    token = secrets.token_hex(24)
    with _LOCK:
        _TOKENS[token] = username
    return token


def revoke_token(token: str):
    with _LOCK:
        _TOKENS.pop(token, None)


def get_user_by_token(token: Optional[str]) -> Optional[Dict]:
    """根据 token 返回用户信息（实时读库，profile 变更/停用即时生效），无效返回 None"""
    if not token:
        return None
    with _LOCK:
        username = _TOKENS.get(token)
    if not username:
        return None
    row = get_storage().get_user(username)
    if not row or row.get("status") != "active":
        # 用户被删除/停用 → 该 token 一并失效
        with _LOCK:
            _TOKENS.pop(token, None)
        return None
    return {
        "username": row["username"],
        "display_name": row["display_name"],
        "role": row["role"],
        "department": row.get("department", ""),
        "position": row.get("position", ""),
    }


def current_identity(token: Optional[str]) -> Dict:
    """返回当前身份：登录用户；未登录返回空（调用方按访客处理）"""
    user = get_user_by_token(token)
    if user:
        return {
            "username": user["username"],
            "display_name": user["display_name"],
            "role": user["role"],
            "department": user.get("department", ""),
            "position": user.get("position", ""),
        }
    return {}


def list_demo_accounts() -> list:
    """供登录界面展示“演示账号”快捷入口：取库中存在的四个演示账号信息（不含敏感字段）。
    若库为空则返回定义（触发 seed 前的兜底）。"""
    _seed_if_empty()
    out = []
    try:
        users = get_storage().list_users()
    except Exception:
        users = []
    user_map = {u["username"]: u for u in users}
    for username, info in DEMO_USERS.items():
        rec = user_map.get(username)
        out.append({
            "username": username,
            "display_name": (rec["display_name"] if rec else info["display_name"]),
            "role": rec["role"] if rec else info["role"],
            "department": rec.get("department", "") if rec else info.get("department", ""),
            "desc": info["desc"],
        })
    return out
