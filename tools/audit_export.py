"""审计导出工具（C9 / D4 的证据生成器）。

两个用途：
  1. 按 request_id 导出全链路（人员+请求+规则版本+模型版本+工具调用+人工确认），
     用于"单条工单可追溯"的现场演示与验收抽样；
  2. 全量导出成 CSV + JSON，并按 PII 形态扫描一遍，证明"审计里没有客户原文"。

用法：
  python tools/audit_export.py                              # 全量导出到 evidence/audit/
  python tools/audit_export.py --request-id REQ-2026...      # 单链路导出（打印 + 落盘）
  python tools/audit_export.py --scan-pii                    # 只做 PII 扫描
  python tools/audit_export.py --data-dir data_test          # 指向测试库

退出码：扫描发现疑似 PII → 3（便于 CI 直接判失败）。
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sqlite3
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ZONES = ("inner", "dmz", "outer")

# 与 dmz/outer 侧一致的形态级 PII 规则（数字环视版，中文语境可靠）
PII_PATTERNS = [
    ("CARD", re.compile(r"(?<!\d)\d{16,19}(?!\d)")),
    ("PHONE", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")),
    ("ID_CARD", re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)")),
]
TOKEN_RE = re.compile(r"\b(?:NAME|CARD|PHONE|ID|AMT|DATE|MERCHANT|ACCT|TXN)_\d{3,}\b")

SIX = [
    ("人员 actor", lambda e: bool(e.get("actor"))),
    ("请求 request_id", lambda e: bool(e.get("request_id"))),
    ("规则版本", lambda e: "rule" in json.dumps(e.get("detail") or {}, ensure_ascii=False).lower()),
    ("模型版本", lambda e: "model" in json.dumps(e.get("detail") or {}, ensure_ascii=False).lower()),
    ("工具/调用", lambda e: e.get("event", "").upper() in {
        "EGRESS_ACCEPTED", "MCP_CALL", "MCP_FORWARDED", "TOKENIZED", "AGENT_PLAN"}),
    ("人工确认", lambda e: e.get("event") in {"HUMAN_CONFIRMED", "ADJUDICATED", "ON_BEHALF"}),
]


def _conn(data_dir: Path, zone: str) -> sqlite3.Connection | None:
    p = data_dir / f"{zone}.db"
    if not p.exists():
        return None
    c = sqlite3.connect(p)
    c.row_factory = sqlite3.Row
    return c


def fetch(data_dir: Path, zone: str, request_id: str | None, limit: int = 5000) -> list[dict]:
    c = _conn(data_dir, zone)
    if not c:
        return []
    sql = "SELECT * FROM events"
    args: list = []
    if request_id:
        sql += " WHERE request_id=? OR trace_id=?"
        args += [request_id, request_id]
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    try:
        rows = [dict(r) for r in c.execute(sql, args)]
    except sqlite3.OperationalError:
        rows = []
    finally:
        c.close()
    for r in rows:
        r["zone"] = zone
        if isinstance(r.get("detail"), str):
            try:
                r["detail"] = json.loads(r["detail"])
            except Exception:
                pass
    return rows


def scan(rows: list[dict]) -> list[dict]:
    hits = []
    for r in rows:
        blob = json.dumps({k: r.get(k) for k in ("detail", "actor", "request_id", "event")},
                          ensure_ascii=False)
        blob = TOKEN_RE.sub(" ", blob)   # 令牌不算泄露
        for label, pat in PII_PATTERNS:
            m = pat.search(blob)
            if m:
                v = m.group(0)
                hits.append({"zone": r.get("zone"), "event": r.get("event"),
                             "pattern": label, "masked": f"{v[:4]}****{v[-4:]}"})
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data-dir", default=str(ROOT / "data"))
    ap.add_argument("--out", default=str(ROOT / "evidence" / "audit"))
    ap.add_argument("--request-id", default=None)
    ap.add_argument("--scan-pii", action="store_true")
    ap.add_argument("--limit", type=int, default=5000)
    args = ap.parse_args()

    data_dir = Path(args.data_dir)
    rows: list[dict] = []
    for z in ZONES:
        rows += fetch(data_dir, z, args.request_id, args.limit)

    if not rows:
        print(f"未找到审计事件（data_dir={data_dir}）")
        return 1

    hits = scan(rows)
    print(f"事件 {len(rows)} 条；PII 疑似命中 {len(hits)} 条")
    if hits:
        for h in hits[:10]:
            print("  !", h)

    if args.request_id:
        print(f"\n== 单链路六要素核对 request_id={args.request_id} ==")
        for name, fn in SIX:
            ok = any(fn(e) for e in rows)
            print(f"  {'✓' if ok else '✗'} {name}")

    if args.scan_pii:
        return 3 if hits else 0

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    tag = args.request_id or "all"

    jf = out / f"audit-export-{tag}-{stamp}.json"
    jf.write_text(json.dumps({
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "data_dir": str(data_dir), "request_id": args.request_id,
        "total": len(rows), "pii_hits": len(hits),
        "by_event": _count(rows, "event"),
        "events": rows,
    }, ensure_ascii=False, indent=2), encoding="utf-8")

    cf = out / f"audit-export-{tag}-{stamp}.csv"
    with cf.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["ts", "zone", "event", "request_id", "trace_id", "actor", "severity", "detail"])
        for r in rows:
            w.writerow([r.get("ts"), r.get("zone"), r.get("event"), r.get("request_id"),
                        r.get("trace_id"), r.get("actor"), r.get("severity"),
                        json.dumps(r.get("detail"), ensure_ascii=False)])
    print(f"已导出：\n  {jf}\n  {cf}")
    return 3 if hits else 0


def _count(rows: list[dict], key: str) -> dict:
    d: dict[str, int] = {}
    for r in rows:
        d[str(r.get(key))] = d.get(str(r.get(key)), 0) + 1
    return dict(sorted(d.items(), key=lambda kv: -kv[1]))


if __name__ == "__main__":
    sys.exit(main())
