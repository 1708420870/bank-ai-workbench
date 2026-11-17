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
