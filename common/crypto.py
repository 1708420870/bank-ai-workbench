"""跨域签名与令牌映射加密。

两件事：
1. sign/verify —— 保证跨域载荷的完整性与来源可信，防篡改、防伪造。
2. seal/unseal —— 令牌映射表落盘前加密。PoC 用 HMAC 计数器模式构造密钥流；
   生产必须替换为 KMS/HSM 托管的 AEAD（如 AES-GCM）。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from typing import Any


def _canonical(payload: Any) -> bytes:
    """规范化序列化：键排序 + 紧凑分隔符，保证两侧计算结果一致。"""
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign(payload: dict, secret: str) -> str:
    body = {k: v for k, v in payload.items() if k != "signature"}
    return hmac.new(secret.encode(), _canonical(body), hashlib.sha256).hexdigest()


def verify(payload: dict, secret: str) -> bool:
    sig = payload.get("signature")
    if not isinstance(sig, str) or not sig:
        return False
    return hmac.compare_digest(sig, sign(payload, secret))


def _keystream(secret: str, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        block = hmac.new(
            secret.encode(), nonce + counter.to_bytes(8, "big"), hashlib.sha256
        ).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def seal(plaintext: str, secret: str) -> str:
    """确定性对称加密（同一明文同一密文），便于令牌查重与索引。"""
    raw = plaintext.encode("utf-8")
    nonce = hashlib.sha256(secret.encode()).digest()[:8]
    ks = _keystream(secret, nonce, len(raw))
    ct = bytes(a ^ b for a, b in zip(raw, ks))
    return base64.urlsafe_b64encode(nonce + ct).decode()


def unseal(token: str, secret: str) -> str:
    blob = base64.urlsafe_b64decode(token.encode())
    nonce, ct = blob[:8], blob[8:]
    ks = _keystream(secret, nonce, len(ct))
    return bytes(a ^ b for a, b in zip(ct, ks)).decode("utf-8")


def fingerprint(value: str) -> str:
    """不可逆指纹，用于审计关联而不留明文。"""
    salt = os.getenv("AUDIT_SALT", "poc-audit-salt-2026")
    return hashlib.sha256((salt + value).encode()).hexdigest()[:16]
