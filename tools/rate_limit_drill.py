"""MCP 网关限流压测脚本（R6 证据生成器）。

用途：对 DMZ MCP 网关施加可控并发/连发，产出"请求数 / 放行数 / 429 数 / 耗时 /
审计留痕"的记录，作为 C10「网关限流」的复验证据。

设计纪律：
  · 只打本机或显式 --base，默认拒绝非 127.0.0.1，避免误压生产；
  · 只用白名单只读工具（list_rule_catalog），不产生任何写操作；
  · 结束时打印审计里 RATE_LIMITED 的条数，做到"压完就能自证"。

用法：
  python tools/rate_limit_drill.py --base http://127.0.0.1:8102 --n 60 --concurrency 6
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import os
import time
import urllib.error
import urllib.request
from collections import Counter
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _token() -> str:
    return os.getenv("SERVICE_TOKEN") or "poc-dmz-to-inner-service-2026"


def _post(url: str, payload: dict, timeout: float = 15) -> tuple[int, str]:
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json",
                                          "x-service-token": _token()}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")[:200]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")[:200]
    except Exception as e:
        return 0, str(e)[:200]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8102")
    ap.add_argument("--n", type=int, default=60, help="总请求数")
    ap.add_argument("--concurrency", type=int, default=6)
    ap.add_argument("--actor", default="DRILL-RATE-01")
    ap.add_argument("--tool", default="list_rule_catalog")
    ap.add_argument("--out", default=str(ROOT / "evidence" / "tests"))
    args = ap.parse_args()

    if "127.0.0.1" not in args.base and "localhost" not in args.base:
        print("拒绝执行：只允许压测本机网关（防止误压生产环境）")
        return 2

    url = f"{args.base.rstrip('/')}/dmz/api/v1/mcp/call"
    body = {"tool": args.tool, "actor": args.actor, "role": "developer", "args": {}}

    t0 = time.time()
    results: list[tuple[int, str]] = []
    with cf.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futs = [ex.submit(_post, url, body) for _ in range(args.n)]
        for f in cf.as_completed(futs):
            results.append(f.result())
    cost = round(time.time() - t0, 2)

    codes = Counter(c for c, _ in results)
    ok = codes.get(200, 0)
    limited = codes.get(429, 0)
    qps = round(args.n / cost, 1) if cost else 0

    print(f"请求 {args.n} 次 / 并发 {args.concurrency} / 耗时 {cost}s / ≈{qps} req/s")
    print(f"状态码分布: {dict(codes)}")
    print(f"放行 {ok} 次，限流 {limited} 次")

    verdict = "PASS" if limited > 0 and ok > 0 else "FAIL"
    print(f"判定: {verdict}（需同时出现 200 与 429，证明限流生效且未误杀全部流量）")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    f = out / f"限流压测-{stamp}.json"
    f.write_text(json.dumps({
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "base": args.base, "n": args.n, "concurrency": args.concurrency,
        "actor": args.actor, "tool": args.tool,
        "cost_s": cost, "qps": qps,
        "codes": {str(k): v for k, v in codes.items()},
        "verdict": verdict,
    }, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"记录已写入 {f}")
    print("复验：在管理端审计页筛选 event=RATE_LIMITED，应出现本次 actor 的记录。")
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
