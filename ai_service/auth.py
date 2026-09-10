# -*- coding: utf-8 -*-
"""账号与角色体系（数据库化 + 组织/岗位 + 认证加固）

将账号从"写死的演示账号"升级为"组织级用户库"：
- 用户存于 SQLite `sys_users`（username/display_name/role/department/position/status/…），
  由后台「用户与组织」管理，可新增员工、按岗授权、启停账号、重置密码；
- 密码使用"随机盐 + PBKDF2-SHA256"，不在库中存明文；
- 令牌（S1 认证加固）：采用自实现的**标准 HS256 JWT**（仅标准库，无需额外依赖），
  具备**签名防篡改 + 有效期(exp) + 服务端可撤销(jti 黑名单)**，弥补原"纯内存 token"的
  重启失效 / 无法撤销 / 无法设过期 等缺陷；
- 登录防护：连续失败达上限后按账号**锁定**一段时间，抵御口令暴力破解；
- 兼容演示：首次启动自动 seed admin/operator/auditor/user 四个账号（口令 admin123），
  后续可在后台修改，供评审与快速体验；真实部署由管理员在后台建账号并分发。

职责分离：admin 管全部；operator 安全运营；auditor 合规审计；manager 部门负责人；user 业务用户。
导航按角色收敛、审批与审计记录到具体账号（人）。

生产建议：
- 在 .env 配置 `AUTH_JWT_SECRET`（否则每次重启随机生成、旧令牌全部失效）；
- 多进程/多副本部署时，将 `jti 黑名单` 与 `登录失败计数` 迁移到共享存储（Redis/DB）。
"""
import base64
import hashlib
import hmac
import json
import secrets
import struct
import threading
import time
from typing import Dict, Optional, Tuple

from storage import get_storage

try:
    from config import settings  # 认证参数来源（可被 .env 覆盖）
except Exception:  # pragma: no cover - 配置缺失时给出安全默认
    settings = None

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

# ------------------------------------------------------------------
# 认证参数（读取配置，缺省给出安全默认）
# ------------------------------------------------------------------
_TOKEN_TTL = int(getattr(settings, "AUTH_TOKEN_TTL_SECONDS", 8 * 3600) or 8 * 3600)
_LOGIN_MAX_FAILS = int(getattr(settings, "AUTH_LOGIN_MAX_FAILS", 5) or 5)
_LOGIN_LOCK_SECONDS = int(getattr(settings, "AUTH_LOGIN_LOCK_SECONDS", 300) or 300)

_JWT_ALG = "HS256"
_LOCK = threading.Lock()


def _load_jwt_secret() -> bytes:
    """加载 JWT 签名密钥：优先 .env 配置；未配置则随机生成并告警（重启后旧令牌失效）。"""
    secret = str(getattr(settings, "AUTH_JWT_SECRET", "") or "")
    if secret:
        return secret.encode("utf-8")
    generated = secrets.token_bytes(32)
    try:
        print("[AUTH][WARN] 未配置 AUTH_JWT_SECRET，已生成临时密钥；"
              "重启后所有令牌失效。生产环境请在 .env 配置固定密钥。")
    except Exception:
        pass
    return generated


_JWT_SECRET: bytes = _load_jwt_secret()

# token 撤销黑名单：jti -> 过期时间戳（到期自动清理）。多进程部署建议迁移到 Redis/DB
_REVOKED_JTI: Dict[str, int] = {}
# 登录失败计数：username -> {"count": int, "lock_until": float}
_LOGIN_FAILS: Dict[str, Dict] = {}


# ==================================================================
# 口令
# ==================================================================
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


# ==================================================================
# 令牌：HS256 JWT（签名 + 过期 + 可撤销）
# ==================================================================
def _b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def _sign(signing_input: bytes) -> str:
    return _b64u_encode(hmac.new(_JWT_SECRET, signing_input, hashlib.sha256).digest())


def _issue_jwt(username: str, scope: str = "access", ttl: Optional[int] = None) -> Tuple[str, str, int]:
    now = int(time.time())
    exp = now + int(ttl if ttl is not None else _TOKEN_TTL)
    jti = secrets.token_hex(16)
    header = {"alg": _JWT_ALG, "typ": "JWT"}
    payload = {"sub": username, "iat": now, "exp": exp, "jti": jti, "scope": scope}
    seg = ".".join([
        _b64u_encode(json.dumps(header, separators=(",", ":"), ensure_ascii=False).encode("utf-8")),
        _b64u_encode(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")),
    ])
    return f"{seg}.{_sign(seg.encode('ascii'))}", jti, exp


def _decode_jwt(token: str) -> Optional[Dict]:
    """校验签名与有效期，返回 payload；任何不合法返回 None。"""
    if not token or token.count(".") != 2:
        return None
    try:
        header_seg, payload_seg, sig = token.split(".")
        expected = _sign(f"{header_seg}.{payload_seg}".encode("ascii"))
        if not hmac.compare_digest(expected, sig):
            return None
        header = json.loads(_b64u_decode(header_seg))
        if header.get("alg") != _JWT_ALG:      # 防算法混淆
            return None
        payload = json.loads(_b64u_decode(payload_seg))
        exp = int(payload.get("exp", 0) or 0)
        if exp and exp < int(time.time()):
            return None
        return payload
    except Exception:
        return None


def _purge_revoked() -> None:
    now = int(time.time())
    for jti in [k for k, v in _REVOKED_JTI.items() if v and v < now]:
        _REVOKED_JTI.pop(jti, None)


def create_token(username: str) -> str:
    """签发访问令牌（JWT，含有效期）。返回 token 字符串。"""
    token, _jti, _exp = _issue_jwt(username, scope="access")
    return token


def revoke_token(token: str) -> None:
    """撤销令牌：将其 jti 加入黑名单（登出/强制下线即时生效）。"""
    payload = _decode_jwt(token)
    if not payload:
        return
    jti = payload.get("jti")
    if not jti:
        return
    with _LOCK:
        _purge_revoked()
        _REVOKED_JTI[jti] = int(payload.get("exp", 0) or 0)


def get_user_by_token(token: Optional[str]) -> Optional[Dict]:
    """根据 token 返回用户信息（实时读库，profile 变更/停用即时生效），无效返回 None。"""
    payload = _decode_jwt(token or "")
    if not payload:
        return None
    # 仅接受"访问令牌"；MFA 临时票据(scope=mfa)不能用于访问业务接口
    if payload.get("scope", "access") != "access":
        return None
    jti = payload.get("jti")
    username = payload.get("sub")
    if not username:
        return None
    with _LOCK:
        if jti and jti in _REVOKED_JTI:
            return None
    row = get_storage().get_user(username)
    if not row or row.get("status") != "active":
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


# ==================================================================
# 登录防护：连续失败锁定
# ==================================================================
def _fail_key(username: str) -> str:
    return (username or "").strip().lower()


def login_locked(username: str) -> Tuple[bool, int]:
    """返回 (是否锁定, 剩余秒数)。"""
    key = _fail_key(username)
    now = time.time()
    with _LOCK:
        rec = _LOGIN_FAILS.get(key)
        if not rec:
            return False, 0
        lock_until = float(rec.get("lock_until", 0) or 0)
        if lock_until and now < lock_until:
            return True, int(lock_until - now) + 1
        if lock_until and now >= lock_until:
            _LOGIN_FAILS.pop(key, None)
    return False, 0


def record_login_failure(username: str) -> None:
    key = _fail_key(username)
    now = time.time()
    with _LOCK:
        rec = _LOGIN_FAILS.get(key) or {"count": 0, "lock_until": 0.0}
        rec["count"] = int(rec.get("count", 0)) + 1
        if rec["count"] >= _LOGIN_MAX_FAILS:
            rec["lock_until"] = now + _LOGIN_LOCK_SECONDS
            rec["count"] = 0
        _LOGIN_FAILS[key] = rec


def clear_login_failures(username: str) -> None:
    with _LOCK:
        _LOGIN_FAILS.pop(_fail_key(username), None)


def authenticate(username: str, password: str) -> Dict:
    """统一登录校验：含锁定判定与失败计数。

    返回 {ok: bool, reason: str, locked: bool, remain: int}
    - reason: ok | empty | locked | invalid
    """
    username = (username or "").strip()
    if not username or not password:
        return {"ok": False, "reason": "empty", "locked": False, "remain": 0}
    locked, remain = login_locked(username)
    if locked:
        return {"ok": False, "reason": "locked", "locked": True, "remain": remain}
    if not verify_password(username, password):
        record_login_failure(username)
        locked2, remain2 = login_locked(username)
        return {"ok": False, "reason": "invalid", "locked": locked2, "remain": remain2}
    clear_login_failures(username)
    return {"ok": True, "reason": "ok", "locked": False, "remain": 0}


def list_demo_accounts() -> list:
    """供登录界面展示"演示账号"快捷入口：取库中存在的四个演示账号信息（不含敏感字段）。
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


# ==================================================================
# 口令强度策略（S1 收尾）
# ==================================================================
_PW_MIN_LEN = int(getattr(settings, "AUTH_PASSWORD_MIN_LEN", 8) or 8)
_PW_REQUIRE_COMPLEXITY = bool(getattr(settings, "AUTH_PASSWORD_REQUIRE_COMPLEXITY", True))
_MFA_ENABLED = bool(getattr(settings, "AUTH_MFA_ENABLED", True))
_MFA_ISSUER = str(getattr(settings, "AUTH_MFA_ISSUER", "SafeAgent") or "SafeAgent")
_MFA_TICKET_TTL = int(getattr(settings, "AUTH_MFA_TICKET_TTL", 300) or 300)
_SSO_TRUSTED_HEADER = str(getattr(settings, "AUTH_SSO_TRUSTED_HEADER", "") or "")


def check_password_policy(password: str) -> Tuple[bool, str]:
    """校验口令强度，返回 (是否通过, 原因)。"""
    import re
    pw = password or ""
    if len(pw) < _PW_MIN_LEN:
        return False, f"口令长度至少 {_PW_MIN_LEN} 位"
    if _PW_REQUIRE_COMPLEXITY:
        cats = [
            bool(re.search(r"[a-z]", pw)),
            bool(re.search(r"[A-Z]", pw)),
            bool(re.search(r"[0-9]", pw)),
            bool(re.search(r"[^A-Za-z0-9]", pw)),
        ]
        if sum(1 for c in cats if c) < 3:
            return False, "口令需包含大写字母、小写字母、数字、符号中的至少三类"
    return True, "ok"


# ==================================================================
# MFA：TOTP（RFC 6238，标准库实现，无需第三方依赖）
# ==================================================================
def _b32_decode(secret: str) -> bytes:
    s = (secret or "").strip().replace(" ", "").upper()
    s += "=" * ((8 - len(s) % 8) % 8)
    return base64.b32decode(s)


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def totp_code(secret: str, for_time: Optional[float] = None, step: int = 30, digits: int = 6) -> str:
    counter = int((for_time if for_time is not None else time.time()) // step)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(_b32_decode(secret), msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def verify_totp(secret: str, code: str, window: int = 1, step: int = 30) -> bool:
    if not secret or not code:
        return False
    code = str(code).strip()
    now = time.time()
    for w in range(-window, window + 1):
        try:
            if hmac.compare_digest(totp_code(secret, now + w * step, step), code):
                return True
        except Exception:
            return False
    return False


def totp_uri(secret: str, username: str) -> str:
    from urllib.parse import quote
    label = quote(f"{_MFA_ISSUER}:{username}")
    return (f"otpauth://totp/{label}?secret={secret}&issuer={quote(_MFA_ISSUER)}"
            f"&algorithm=SHA1&digits=6&period=30")


def mfa_config() -> Dict:
    return {"enabled": _MFA_ENABLED, "issuer": _MFA_ISSUER}


def mfa_status(username: str) -> Dict:
    info = get_storage().get_user_mfa(username)
    return {"mfa_enabled": bool(info.get("mfa_enabled")), "available": _MFA_ENABLED}


def begin_mfa_enroll(username: str) -> Dict:
    """生成 TOTP 密钥（尚未启用），返回密钥与 otpauth URI 供扫码绑定。"""
    secret = generate_totp_secret()
    get_storage().set_user_mfa(username, secret, False)
    return {"secret": secret, "otpauth_uri": totp_uri(secret, username)}


def confirm_mfa_enroll(username: str, code: str) -> Dict:
    info = get_storage().get_user_mfa(username)
    secret = info.get("totp_secret", "")
    if not secret:
        return {"ok": False, "message": "请先获取密钥"}
    if not verify_totp(secret, code):
        return {"ok": False, "message": "验证码不正确"}
    get_storage().set_user_mfa(username, secret, True)
    return {"ok": True, "message": "MFA 已启用"}


def disable_mfa(username: str) -> Dict:
    get_storage().set_user_mfa(username, "", False)
    return {"ok": True, "message": "MFA 已停用"}


def create_mfa_ticket(username: str) -> str:
    """签发二步验证临时票据（scope=mfa，短有效期，不能用于访问业务接口）。"""
    token, _j, _e = _issue_jwt(username, scope="mfa", ttl=_MFA_TICKET_TTL)
    return token


def verify_mfa_ticket(ticket: str) -> Optional[str]:
    payload = _decode_jwt(ticket or "")
    if not payload or payload.get("scope") != "mfa":
        return None
    return payload.get("sub")


# ==================================================================
# SSO：受信网关头（政企常见：由前置 IdP/网关注入已认证用户名）
# ==================================================================
def sso_enabled() -> bool:
    return bool(_SSO_TRUSTED_HEADER)


def sso_header_name() -> str:
    return _SSO_TRUSTED_HEADER


def resolve_sso_identity(headers) -> Optional[Dict]:
    """从受信网关头解析已认证身份并映射到本地账号。未配置/缺失/停用返回 None。"""
    if not _SSO_TRUSTED_HEADER:
        return None
    name = None
    try:
        name = headers.get(_SSO_TRUSTED_HEADER) or headers.get(_SSO_TRUSTED_HEADER.lower())
    except Exception:
        name = None
    if not name:
        return None
    row = get_storage().get_user(str(name).strip())
    if not row or row.get("status") != "active":
        return None
    return {
        "username": row["username"],
        "display_name": row["display_name"],
        "role": row["role"],
        "department": row.get("department", ""),
        "position": row.get("position", ""),
    }
