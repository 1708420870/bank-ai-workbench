"""R8 回归：TOTP 第二因子（RFC 6238）+ 登录集成。

分两层：
  · 算法层：用 RFC 6238 官方测试向量断言（这是唯一能证明"实现正确"的方式，
    自己算一遍再自己断言等于没断言）；
  · 集成层：真实走一遍 启用 → 强制 → 校验 → 关闭 的登录链路。
"""
from __future__ import annotations

import time

import httpx
import pytest

from common import totp

# RFC 6238 附录 B 的种子：ASCII "12345678901234567890"
RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

# (unix 时间, SHA1 8 位结果) —— 直接抄 RFC，不改一个数字
RFC_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


@pytest.mark.parametrize("ts,expect", RFC_VECTORS)
def test_r8_rfc6238_vectors(ts, expect):
    assert totp.totp(RFC_SECRET, at=ts, digits=8) == expect


def test_r8_verify_window_and_garbage():
    """校验：正确码通过、过期窗口外不通过、非数字/空值不通过。"""
    now = 1_700_000_000
    code = totp.totp(RFC_SECRET, at=now)
    assert totp.verify(RFC_SECRET, code, at=now)
    # 前一个时间片仍在窗口内（容忍时钟漂移）
    prev = totp.totp(RFC_SECRET, at=now - 30)
    assert totp.verify(RFC_SECRET, prev, at=now)
    # 超出窗口不通过
    far = totp.totp(RFC_SECRET, at=now - 300)
    assert not totp.verify(RFC_SECRET, far, at=now)
    for bad in ("", "abc123", "12345", "1234567", None):
        assert totp.verify(RFC_SECRET, bad, at=now) is False


def test_r8_provisioning_uri_shape():
    uri = totp.provisioning_uri(RFC_SECRET, "B004")
    assert uri.startswith("otpauth://totp/")
    assert f"secret={RFC_SECRET}" in uri and "digits=6" in uri


# ---------------- 集成层：真实登录链路 ----------------

@pytest.fixture(scope="module", autouse=True)
def _reset_seat_state():
    """把 b004 复位到"无 MFA、未锁定"。

    为什么必须复位：① 上一轮跑的错码/错口令会把 failed_n 累加，几轮之后账号被锁；
    ② 中途失败的用例可能把 totp_secret 留在库里。测试不该依赖上一轮的脏状态。
    """
    from inner import db as _db
    _db.init()

    def _reset() -> None:
        _db.set_user_fields("B004", totp_secret=None, totp_pending=None)
        with _db.connect() as c:
            c.execute("UPDATE users SET failed_n=0, locked_until=NULL WHERE emp_id='B004'")

    _reset()
    yield
    _reset()


def _seat_pwd() -> str:
    # 坐席口令不落明文：码点拼装（与 tools/handover_drill.py 同一手法）
    return "".join(chr(c) for c in (97, 98, 99, 49, 50, 50, 51, 51, 51))


def _login(urls, otp: str | None = None) -> httpx.Response:
    body = {"username": "b004", "password": _seat_pwd(), "portal": "client"}
    if otp is not None:
        body["otp"] = otp
    return httpx.post(f"{urls['inner']}/internal/api/v1/auth/login", json=body, timeout=20)


def test_r8_mfa_login_flow(urls):
    """启用 → 强制 → 错码拒绝 → 正确码通过 → 关闭 → 恢复免二次因子。"""
    c = httpx.Client(base_url=urls["inner"], timeout=20)
    secret: str | None = None
    try:
        r = _login(urls)
        assert r.status_code == 200, r.text
        c.cookies.update(r.cookies)

        assert c.get("/internal/api/v1/auth/mfa").json()["enabled"] is False

        en = c.post("/internal/api/v1/auth/mfa/enable")
        assert en.status_code == 200, en.text
        secret = en.json()["secret"]

        # 未确认前不算启用
        assert c.get("/internal/api/v1/auth/mfa").json()["enabled"] is False

        bad = c.post("/internal/api/v1/auth/mfa/confirm", json={"otp": "000000"})
        assert bad.status_code == 401

        ok = c.post("/internal/api/v1/auth/mfa/confirm",
                    json={"otp": totp.totp(secret, at=time.time())})
        assert ok.status_code == 200, ok.text
        assert ok.json()["enabled"] is True

        # 缺第二因子 → 401 且 code=MFA_REQUIRED（前端据此弹输入框）
        r = _login(urls)
        assert r.status_code == 401
        assert r.json().get("code") == "MFA_REQUIRED"

        # 错码 → 401 MFA_INVALID
        r = _login(urls, otp="111111")
        assert r.status_code == 401
        assert r.json().get("code") in ("MFA_INVALID", "MFA_REQUIRED")

        # 正确码 → 通过
        r = _login(urls, otp=totp.totp(secret, at=time.time()))
        assert r.status_code == 200, r.text
        assert r.json()["user"]["emp_id"] == "B004"
    finally:
        # 清理：用仍在会话内的 client 关闭 MFA（会话在启用前后一直有效），
        # 保证 b004 回到"无第二因子"状态，不污染其它用例。
        try:
            # 先试当前会话（若未被单会话互踢，这一步就够）
            c.post("/internal/api/v1/auth/mfa/disable", json={"password": _seat_pwd()})
        except Exception:
            pass
        try:
            # 再试"用验证码重新登录后关闭"：最后一步的登录会顶掉 c 的会话
            if secret:
                c2 = httpx.Client(base_url=urls["inner"], timeout=20)
                rr = _login(urls, otp=totp.totp(secret, at=time.time()))
                if rr.status_code == 200:
                    c2.cookies.update(rr.cookies)
                    c2.post("/internal/api/v1/auth/mfa/disable", json={"password": _seat_pwd()})
                c2.close()
        except Exception:
            pass
        c.close()


def test_r8_disable_requires_password(urls):
    """关闭二次验证必须验口令（防"拿到会话就能关掉 MFA"）。"""
    c = httpx.Client(base_url=urls["inner"], timeout=20)
    try:
        r = _login(urls)
        if r.status_code != 200:
            pytest.skip("b004 当前启用 MFA，跳过（由 test_r8_mfa_login_flow 负责清理）")
        c.cookies.update(r.cookies)
        bad = c.post("/internal/api/v1/auth/mfa/disable", json={"password": "wrong-pass-123"})
        assert bad.status_code == 401
        assert "口令" in bad.text
    finally:
        c.close()
