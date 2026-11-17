"""分区审计：每个区写自己的库，跨区不共享。

铁律：审计只记元数据，不记明文。写入前统一过 scrub()，即使调用方疏忽
传了原始值，也不会落盘——这是 ADR-08，也是 T18 的断言对象。
"""
from __future__ import annotations

import json
import re
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

from .config import db_path

# 兜底脱敏：卡号、手机号、证件号、货币金额
_SCRUB_PATTERNS = [
    (re.compile(r"\b\d{16,19}\b"), "<CARD_REDACTED>"),
    (re.compile(r"\b1[3-9]\d{9}\b"), "<PHONE_REDACTED>"),
    (re.compile(r"\b\d{17}[\dXx]\b"), "<ID_REDACTED>"),
    (re.compile(r"[¥￥]\s?\d[\d,]*(\.\d{2})?"), "<AMOUNT_REDACTED>"),
]

_DDL = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    zone TEXT NOT NULL,
    event TEXT NOT NULL,
    request_id TEXT,
    trace_id TEXT,
    actor TEXT,
    severity TEXT DEFAULT 'info',
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_req ON events(request_id);
"""


def _conn(zone: str) -> sqlite3.Connection:
    c = sqlite3.connect(db_path(zone), timeout=10)
    c.row_factory = sqlite3.Row
    c.executescript(_DDL)
    return c


@contextmanager
def _conn_ctx(zone: str) -> Iterator[sqlite3.Connection]:
    """短连接上下文：退出时提交并关闭连接（sqlite3 的 with 语义不含 close）。"""
    c = _conn(zone)
    try:
        with c:
            yield c
    finally:
        c.close()


def scrub(value: Any) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, sort_keys=True)
    for pat, repl in _SCRUB_PATTERNS:
        text = pat.sub(repl, text)
    return text


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def log(
    zone: str,
    event: str,
    *,
    request_id: str | None = None,
    trace_id: str | None = None,
    actor: str | None = None,
    detail: Any = None,
    severity: str = "info",
) -> str:
    eid = uuid.uuid4().hex[:12]
    payload = scrub(detail) if detail is not None else None
    with _conn_ctx(zone) as c:
        c.execute(
            "INSERT INTO events (ts, zone, event, request_id, trace_id, actor, severity, detail)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (now_iso(), zone, event, request_id, trace_id or request_id, actor, severity, payload),
        )
    return eid


def query(zone: str, request_id: str | None = None, limit: int = 200) -> list[dict]:
    sql = "SELECT * FROM events"
    args: list[Any] = []
    if request_id:
        sql += " WHERE request_id = ?"
        args.append(request_id)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    with _conn_ctx(zone) as c:
        return [dict(r) for r in c.execute(sql, args)]


def count_by_severity(zone: str) -> dict[str, int]:
    with _conn_ctx(zone) as c:
        rows = c.execute("SELECT severity, COUNT(*) n FROM events GROUP BY severity").fetchall()
    return {r["severity"]: r["n"] for r in rows}
