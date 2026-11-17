"""身份与会话：内网是唯一身份权威。

四条设计约束，每条都对应一个具体的攻击面：

1. **口令只存派生值。** PBKDF2-HMAC-SHA256 + 每账号独立 salt，任何位置不落明文。
   登录失败时用假 salt 跑一次同代价运算，避免"响应快慢"泄露账号是否存在。

2. **会话是"服务端有记录 + 客户端持签名令牌"双轨。** 令牌只携带 sid，
   状态在 sessions 表里。这样吊销立即生效——纯无状态 JWT 做不到这点，
   而"离职坐席的会话还能用到过期"是真实的合规问题。

3. **角色从会话读，不从请求体读。** 前端声明自己是什么角色一律不算数。
   这是本项目相对常见实现最重要的一处修正：原来的 MCP 面板由 body.role
   决定权限，等于把授权交给了调用方。

4. **两个入口在登录时就分流。** 坐席账号进不了管理端，管理员账号也进不了
   坐席工作台。角色不匹配在登录环节拒绝，而不是登录成功后再靠前端隐藏菜单
   ——隐藏菜单不是访问控制。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, Request

from common import audit
from common.config import (
    ALLOWED_LOGIN_NETS, DEVICE_BINDING, LOGIN_LOCK_SECONDS, LOGIN_MAX_FAIL,
    PORTAL_ROLES, SERVICE_TOKEN, SESSION_COOKIE, SESSION_SECRET, SESSION_TTL_SECONDS,
    SINGLE_SESSION,
)

from . import db

ITER = 200_000
SERVICE_HEADER = "x-service-token"
DEVICE_HEADER = "x-device-id"


class AuthError(Exception):
    """登录环节的拒绝。message 会直接返回给前端，因此不得包含账号是否存在等信息。

    status 区分两种情况：口令类失败一律 401（不区分账号是否存在），
    入口不匹配则 403（身份已成立，只是无权进入该端）。
    """

    def __init__(self, message: str, status: int = 401) -> None:
        super().__init__(message)
        self.status = status


def _now() -> datetime:
    return datetime.now(timezone.utc).astimezone()


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


# ---------------- 口令 ----------------

def hash_password(pwd: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pwd.encode("utf-8"), salt, ITER)
    return f"pbkdf2_sha256${ITER}${salt.hex()}${dk.hex()}"


def verify_password(pwd: str, stored: str) -> bool:
    try:
        algo, it, salt_hex, hash_hex = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", pwd.encode("utf-8"), bytes.fromhex(salt_hex), int(it))
        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


def _burn_time(pwd: str) -> None:
    """账号不存在时也消耗同等算力，抹平时序差异。"""
    hashlib.pbkdf2_hmac("sha256", pwd.encode("utf-8"), b"\x00" * 16, ITER)


# ---------------- 令牌 ----------------

def _sign(body: str) -> str:
    return hmac.new(SESSION_SECRET.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()


def _encode(payload: dict) -> str:
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    body = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    return f"{body}.{_sign(body)}"


def _decode(token: str) -> dict | None:
    try:
        body, sig = token.rsplit(".", 1)
        if not hmac.compare_digest(sig, _sign(body)):
            return None
        raw = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4))
        return json.loads(raw)
    except Exception:
        return None


def issue_token(sid: str) -> str:
    exp = _now() + timedelta(seconds=SESSION_TTL_SECONDS)
    return _encode({"sid": sid, "exp": _iso(exp)})


# ---------------- 登录 / 登出 ----------------

def login(username: str, password: str, portal: str, ip: str = "", ua: str = "",
          device_id: str = "") -> tuple[str, dict]:
    if portal not in PORTAL_ROLES:
        raise AuthError("无效的登录入口")

    # 登录来源限制：先把"从哪里连进来的"筛掉，再谈账号密码
    if ALLOWED_LOGIN_NETS and not _ip_allowed(ip):
        audit.log("inner", "LOGIN_FAIL", actor=username, severity="critical",
                  detail={"reason": "network_denied", "portal": portal, "ip": ip})
        raise AuthError("当前网络位置不允许登录", status=403)

    user = db.user_by_username(username.strip().lower())
    if not user:
        _burn_time(password)
        audit.log("inner", "LOGIN_FAIL", actor=username, severity="high",
                  detail={"reason": "unknown_user", "portal": portal, "ip": ip})
        raise AuthError("账号或口令错误")

    if not user["active"]:
        audit.log("inner", "LOGIN_FAIL", actor=username, severity="high",
                  detail={"reason": "disabled", "portal": portal, "ip": ip})
        raise AuthError("账号已停用，请联系管理员")

    lock = user.get("locked_until")
    if lock and datetime.fromisoformat(lock) > _now():
        left = int((datetime.fromisoformat(lock) - _now()).total_seconds())
        audit.log("inner", "LOGIN_LOCKED", actor=username, severity="critical",
                  detail={"portal": portal, "ip": ip, "remain_s": left})
        raise AuthError(f"账号因连续失败已锁定，请 {max(left, 1)} 秒后重试")

    if not verify_password(password, user["pwd_hash"]):
        n = (user.get("failed_n") or 0) + 1
        locked = _iso(_now() + timedelta(seconds=LOGIN_LOCK_SECONDS)) if n >= LOGIN_MAX_FAIL else None
        db.bump_failure(user["emp_id"], n, locked)
        audit.log("inner", "LOGIN_FAIL", actor=username, severity="high",
                  detail={"reason": "bad_password", "portal": portal, "ip": ip,
                          "failed_n": n, "locked": bool(locked)})
        if locked:
            raise AuthError(f"账号因连续失败 {n} 次已锁定 {LOGIN_LOCK_SECONDS} 秒")
        # 不返回"已失败 n 次"：带计数的提示等于确认了该账号存在，
        # 而未知账号不计数——两者一对比就是可用的账号枚举信道。
        raise AuthError("账号或口令错误")

    # 口令正确之后才校验入口，避免"这个账号属于另一个端"成为账号枚举信道
    if user["role"] not in PORTAL_ROLES[portal]:
        audit.log("inner", "AUTHZ_DENIED", actor=username, severity="high",
                  detail={"reason": "portal_mismatch", "role": user["role"],
                          "portal": portal, "ip": ip})
        raise AuthError("该账号无权登录此入口", status=403)

    # 会话固定攻击防御：每次登录都换新 sid，不复用任何既有标识
    sid = secrets.token_urlsafe(24)

    # 设备绑定：账号一旦绑定设备，后续所有登录（含浏览器）必须来自同一设备。
    # 绑定动作发生在首次携带设备头登录时；未绑定的浏览器登录不受影响。
    bound = user.get("device_id") or ""
    if DEVICE_BINDING and bound:
        if not device_id or not hmac.compare_digest(bound, device_id):
            audit.log("inner", "LOGIN_FAIL", actor=username, severity="critical",
                      detail={"reason": "device_mismatch", "portal": portal, "ip": ip})
            raise AuthError("该账号已绑定其他设备，禁止在当前设备登录", status=403)
    elif device_id and not bound:
        db.set_device_binding(user["emp_id"], device_id)

    exp = _iso(_now() + timedelta(seconds=SESSION_TTL_SECONDS))
    db.create_session(sid, user["emp_id"], user["role"], portal, exp, ip, ua[:200], device_id)
    if SINGLE_SESSION:
        kicked = db.revoke_other_sessions(user["emp_id"], sid)
        if kicked:
            audit.log("inner", "SESSION_KICKED", actor=user["emp_id"], severity="medium",
                      detail={"reason": "single_session", "new_sid": sid[:8], "kicked": kicked})
    db.mark_login_ok(user["emp_id"])

    audit.log("inner", "LOGIN_OK", actor=user["emp_id"], request_id=sid[:8],
              detail={"portal": portal, "role": user["role"], "ip": ip})
    prof = db.employee(user["emp_id"]) or {}
    emp = {"emp_id": user["emp_id"], "name": prof.get("name", user["username"]),
           "role": user["role"], "username": user["username"], "portal": portal, "sid": sid,
           "expires_at": exp,
           "must_change_pwd": bool(user.get("must_change_pwd"))}
    return issue_token(sid), emp


def logout(sid: str, emp_id: str) -> None:
    db.revoke_session(sid)
    audit.log("inner", "LOGOUT", actor=emp_id, detail={"sid": sid[:8]})


# ---------------- 会话解析 ----------------

def session_of(token: str | None, device_id: str = "") -> dict | None:
    if not token:
        return None
    payload = _decode(token)
    if not payload:
        return None
    # 会话有效期以 DB expires_at 为权威（JWT 只携带 sid，不做 exp 硬校验），
    # 配合下方滑动续期：活跃用户不再被固定时长强制掉线（演示/日常使用反馈）。
    row = db.session(payload.get("sid", ""))
    if not row or row["revoked"]:
        return None
    exp_dt = datetime.fromisoformat(row["expires_at"])
    if exp_dt <= _now():
        return None
    # 会话若由某设备建立，后续请求必须来自同一设备——换设备即视为令牌失窃
    bound = row.get("device_id") or ""
    if bound and not (device_id and hmac.compare_digest(bound, device_id)):
        audit.log("inner", "SESSION_DEVICE_MISMATCH", actor=row["emp_id"], severity="high",
                  detail={"sid": row["sid"][:8], "bound": bound[:8]})
        return None
    # 滑动续期：剩余有效期不足 60% 时自动顺延至满额，活跃用户不掉线；
    # 不活跃的会话到期后自然失效（被动过期，不引入清理线程）。
    remaining = (exp_dt - _now()).total_seconds()
    if remaining < SESSION_TTL_SECONDS * 0.6:
        db.extend_session(row["sid"], _iso(_now() + timedelta(seconds=SESSION_TTL_SECONDS)))
    emp = db.employee(row["emp_id"]) or {}
    return {"emp_id": row["emp_id"], "role": row["role"], "portal": row["portal"],
            "sid": row["sid"], "name": emp.get("name", ""), "expires_at": row["expires_at"]}


def _extract(request: Request) -> str | None:
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        return token
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return None


def _ip_allowed(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(n) for n in ALLOWED_LOGIN_NETS)


def current_user(request: Request) -> dict:
    user = session_of(_extract(request), request.headers.get(DEVICE_HEADER, ""))
    if not user:
        raise HTTPException(401, "未登录或会话已失效")
    return user


def require(*roles: str):
    """按角色收敛。未授权一律 403 并落审计——不返回"你需要什么角色"这类提示。"""

    def dep(request: Request) -> dict:
        user = current_user(request)
        if roles and user["role"] not in roles:
            audit.log("inner", "AUTHZ_DENIED", actor=user["emp_id"], severity="high",
                      detail={"role": user["role"], "need": sorted(roles),
                              "path": request.url.path})
            raise HTTPException(403, "当前角色无权执行此操作")
        return user

    return dep


def is_service(request: Request) -> bool:
    """DMZ → 内网 Facade 的服务身份。只此一条通路认它。"""
    tok = request.headers.get(SERVICE_HEADER, "")
    return bool(tok) and hmac.compare_digest(tok, SERVICE_TOKEN)


def set_cookie(resp, token: str) -> None:
    # HttpOnly：JS 读不到，XSS 也偷不走。SameSite=Lax：跨站表单提交不带会话。
    resp.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL_SECONDS,
                    httponly=True, samesite="lax", path="/")


def clear_cookie(resp) -> None:
    resp.delete_cookie(SESSION_COOKIE, path="/")
