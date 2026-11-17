"""TOTP（RFC 6238）实现：演示级 MFA。

为什么自己实现而不引三方库：
  1. 依赖越少，评审越容易过——这段代码 40 行可逐行核对；
  2. 有官方测试向量可直接断言（见 tests/test_mfa.py），比"信任某个包"更可验证。

定位（不得含糊）：
  · 本文件实现的是**标准 TOTP**，兼容 Google Authenticator / 微软 Authenticator；
  · 它不是行内 SSO。生产应接行内统一身份（OIDC/SAML）+ 行内 MFA，
    本实现作为"PoC 期间可演示的第二因子"，见 docs/22。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

DIGITS = 6
STEP = 30          # 秒
WINDOW = 1         # 允许前后各 1 个时间片（容忍时钟漂移，最多 90 秒）


def new_secret(nbytes: int = 20) -> str:
    """生成 base32 密钥（20 字节 = 160 bit，与主流认证器一致）。"""
    return base64.b32encode(secrets.token_bytes(nbytes)).decode("ascii").rstrip("=")


def _key(secret_b32: str) -> bytes:
    s = secret_b32.strip().replace(" ", "").upper()
    pad = "=" * ((8 - len(s) % 8) % 8)
    return base64.b32decode(s + pad)


def hotp(secret_b32: str, counter: int, digits: int = DIGITS) -> str:
    """HOTP（RFC 4226）：HMAC-SHA1 → 动态截断 → 取模。"""
    mac = hmac.new(_key(secret_b32), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(code).zfill(digits)


def totp(secret_b32: str, at: float | None = None, step: int = STEP,
         digits: int = DIGITS) -> str:
    at = time.time() if at is None else at
    return hotp(secret_b32, int(at // step), digits)


def verify(secret_b32: str, code: str, at: float | None = None,
           step: int = STEP, digits: int = DIGITS, window: int = WINDOW) -> bool:
    """校验 TOTP。字符串比较用 hmac.compare_digest，避免时序侧信道。"""
    if not code:
        return False
    code = str(code).strip().replace(" ", "")
    if not code.isdigit() or len(code) != digits:
        return False
    at = time.time() if at is None else at
    base = int(at // step)
    for drift in range(-window, window + 1):
        if hmac.compare_digest(hotp(secret_b32, base + drift, digits), code):
            return True
    return False


def provisioning_uri(secret_b32: str, account: str, issuer: str = "银行客服AI工作台") -> str:
    """otpauth:// URI：可直接生成二维码供认证器扫描。"""
    label = quote(f"{issuer}:{account}")
    return (f"otpauth://totp/{label}?secret={secret_b32}"
            f"&issuer={quote(issuer)}&algorithm=SHA1&digits={DIGITS}&period={STEP}")
