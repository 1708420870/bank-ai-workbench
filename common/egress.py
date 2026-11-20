"""出域护栏：把"外网不得直连内网"从纪律变成可执行的代码约束。

每个区在发起任何 HTTP 调用前必须经过 guard()。目标端口不在本区白名单内，
直接抛 BlockedEgress 并落审计告警——而不是靠代码评审发现。

这是 ADR-01 / ADR-10 的落地形式，也是 T12、T20 的断言点。
"""
from __future__ import annotations

import uuid
from urllib.parse import urlparse

from .config import ALLOWED_PORTS


class BlockedEgress(RuntimeError):
    """出域被策略拒绝。调用方必须按 fail-closed 处理，不得重试绕过。"""

    def __init__(self, zone: str, url: str, allowed: set[int]):
        self.zone = zone
        self.url = url
        self.allowed = allowed
        super().__init__(
            f"[EGRESS DENIED] zone={zone} target={url} "
            f"allowed_ports={sorted(allowed)} —— 策略拒绝，按 fail-closed 终止"
        )


def _port_of(url: str) -> int:
    p = urlparse(url)
    if p.port:
        return p.port
    return 443 if p.scheme == "https" else 80


def guard(zone: str, url: str) -> None:
    """校验本区是否允许访问该目标。不通过即抛异常，无返回值约定。"""
    allowed = ALLOWED_PORTS.get(zone, set())
    port = _port_of(url)
    if port not in allowed:
        # 延迟导入避免循环依赖
        try:
            from .audit import log

            from .audit import current_trace

            log(
                zone,
                event="EGRESS_BLOCKED",
                # 护栏可能在无 HTTP 上下文的位置被调用（启动自检、后台任务），
                # 此时给事件本身一个独立 trace，保证"每条审计都有 trace"这条不变量成立。
                trace_id=current_trace() or f"GUARD-{uuid.uuid4().hex[:8]}",
                severity="critical",
                detail={"target": url, "allowed_ports": sorted(allowed)},
            )
        except Exception:
            pass
        raise BlockedEgress(zone, url, allowed)


def is_allowed(zone: str, url: str) -> bool:
    return _port_of(url) in ALLOWED_PORTS.get(zone, set())


# ---------------------------------------------------------------------------
# 外发物内容检查（v1.5.2，对应 T03：token 映射表不得经网关外发）
# ---------------------------------------------------------------------------
import re as _re

_TOKENMAP_RES = (
    # 结构化映射表：sealed_value / token_map / mapping_table 字段
    _re.compile(r'"(sealed_value|token_map|mapping_table)"\s*:', _re.I),
    # 令牌与密文并排出现：NAME_001 <16+ 位 base64/十六进制> 或 NAME_001,CARD_001,...
    _re.compile(r"\b(?:NAME|CARD|PHONE|ID|AMT|MERCHANT)_\d{3,}\b\s*[,:\t]\s*[A-Za-z0-9+/=]{16,}"),
    # 映射表文件头（CSV 导出常见）
    _re.compile(r"^\s*(request_id\s*,\s*token\s*,\s*field_type\s*,\s*sealed_value)", _re.I | _re.M),
)


class TokenMapInEgress(BlockedEgress):
    """外发物里含令牌映射表：属于数据边界的关键缺陷，一律拒绝并留审计。"""


def scan_tokenmap(text: str) -> str | None:
    """检测外发物是否包含令牌映射表内容。命中返回证据片段（脱敏），否则 None。"""
    if not text:
        return None
    for pat in _TOKENMAP_RES:
        m = pat.search(text)
        if m:
            frag = m.group(0)[:40].replace("\n", " ")
            return f"tokenmap-signature:{frag}"
    return None

