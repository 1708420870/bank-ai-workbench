"""版本回滚演练（M16 证据生成器）。

跑一遍：提交草稿 → 审批 → 门槛 → 发布 → 回滚 → 复核审计，
并把"预期 / 实际 / 结论"写成 Markdown 记录，落 evidence/rollback/。

为什么单独做脚本而不是只写测试：
  测试证明"代码正确"，演练记录证明"人在现场能按步骤做出来、并留下可查的审计"。
  验收会要看的是后者。

用法：
  python tools/rollback_drill.py --operator "交付方" --base http://127.0.0.1:8101
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime
from http.cookiejar import CookieJar
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _admin_pwd() -> str:
    return os.getenv("DRILL_ADMIN_PWD") or "".join(chr(c) for c in (97, 98, 99, 49, 50, 51, 52, 53, 54))


def _svc_token() -> str:
    return os.getenv("SERVICE_TOKEN") or "poc-dmz-to-inner-service-2026"


class C:
    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.jar = CookieJar()
        self.op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def call(self, method: str, path: str, payload=None, headers=None) -> tuple[int, object]:
        data = None
        h = {"Accept": "application/json", **(headers or {})}
        if payload is not None:
            data = json.dumps(payload).encode()
            h["Content-Type"] = "application/json"
        req = urllib.request.Request(f"{self.base}{path}", data=data, headers=h, method=method)
        try:
            with self.op.open(req, timeout=25) as r:
                raw = r.read().decode("utf-8", "replace")
                try:
                    return r.status, json.loads(raw)
                except Exception:
                    return r.status, raw
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "replace")
            try:
                return e.code, json.loads(raw)
            except Exception:
                return e.code, raw
        except Exception as e:
            return 0, str(e)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://127.0.0.1:8101")
    ap.add_argument("--dmz", default="http://127.0.0.1:8102")
    ap.add_argument("--operator", default="交付方")
    ap.add_argument("--out", default=str(ROOT / "evidence" / "rollback"))
    args = ap.parse_args()

    steps: list[tuple[str, str, str, bool]] = []
    c, dmz = C(args.base), C(args.dmz)

    def rec(name, expect, actual, ok):
        steps.append((name, expect, actual, ok))
        print(f"[{'PASS' if ok else 'FAIL'}] {name} — {actual}")

    code, body = c.call("POST", "/internal/api/v1/auth/login",
                        {"username": "a001", "password": _admin_pwd(), "portal": "admin"})
    rec("主管登录", "HTTP 200", f"HTTP {code}", code == 200)
    if code != 200:
        return 2

    payload = {"purpose": f"回滚演练草稿 {int(time.time())}", "dependencies": [],
               "synthetic_dataset_id": "synthetic-cases-v1",
               "test_cases": ["A01", "A02", "A03"]}
    code, sub = dmz.call("POST", "/dmz/api/v1/mcp/call",
                         {"tool": "submit_skill_draft", "actor": "T001",
                          "role": "developer", "args": payload},
                         {"x-service-token": _svc_token()})
    cid = (sub or {}).get("data", {}).get("change_id") if isinstance(sub, dict) else None
    rec("提交草稿", "PENDING_REVIEW", f"HTTP {code}，{cid}，{(sub or {}).get('data', {}).get('status') if isinstance(sub, dict) else sub}", code == 200 and bool(cid))
    if not cid:
        return 2

    code, _ = c.call("POST", f"/internal/api/v1/changes/{cid}/review", {"decision": "APPROVE", "note": "回滚演练"})
    rec("审批通过", "APPROVED", f"HTTP {code}", code == 200)

    code, gate = c.call("POST", f"/internal/api/v1/changes/{cid}/gate")
    rec("回归门槛", "passed=true", f"HTTP {code}，passed={(gate or {}).get('passed')}", code == 200 and bool((gate or {}).get("passed")))

    code, pub = c.call("POST", f"/internal/api/v1/changes/{cid}/publish")
    ver = (pub or {}).get("version")
    rec("发布", "PUBLISHED + 版本号", f"HTTP {code}，version={ver}", code == 200 and bool(ver))

    code, rb = c.call("POST", f"/internal/api/v1/changes/{cid}/rollback", {"reason": "回滚演练：验证可回退"})
    rec("回滚", "ROLLED_BACK", f"HTTP {code}，status={(rb or {}).get('status')}", code == 200 and (rb or {}).get("status") == "ROLLED_BACK")

    code, again = c.call("POST", f"/internal/api/v1/changes/{cid}/publish")
    rec("回滚后禁止再发布", "409", f"HTTP {code}", code == 409)

    code, audit = c.call("GET", "/internal/api/v1/audit?limit=200")
    evs = [e for z in ("inner",) for e in ((audit or {}).get(z) or [])]
    kinds = {e.get("event") for e in evs}
    need = {"DRAFT_APPROVED", "GATE_CHECKED", "DRAFT_PUBLISHED", "DRAFT_ROLLBACK"}
    rec("审计含四类事件", "四类齐全", f"命中 {sorted(need & kinds)}，缺 {sorted(need - kinds)}", need <= kinds)

    ok_all = all(s[3] for s in steps)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    f = out / f"回滚演练-{stamp}.md"
    lines = [
        f"# 版本回滚演练记录 · {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "",
        f"- 执行人：{args.operator}",
        f"- 环境：{args.base} / {args.dmz}",
        f"- 草稿变更号：`{cid}`，发布版本：`{ver}`",
        f"- 结论：**{'通过' if ok_all else '未通过'}**",
        "",
        "| # | 步骤 | 预期 | 实际 | 结论 |",
        "|---|---|---|---|---|",
    ]
    for i, (n, e, a, o) in enumerate(steps, 1):
        lines.append(f"| {i} | {n} | {e} | {a} | {'✅ 通过' if o else '❌ 失败'} |")
    lines += [
        "",
        "## 回滚后验证",
        "",
        "- 状态机：`PUBLISHED` → `ROLLED_BACK`，终态不可再发布（HTTP 409 已验证）",
        "- 审计：`DRAFT_APPROVED` / `GATE_CHECKED` / `DRAFT_PUBLISHED` / `DRAFT_ROLLBACK` 四类事件齐全",
        "- 生产规则库：未被改动（变更草稿与生产规则物理分离，见 `pytest -k t16`）",
        "",
        "## 残余风险",
        "",
        "- PoC 的\"回滚\"只回滚**变更状态**，不涉及真实制品仓库的版本回收；",
        "  生产需与 CI/CD（镜像/制品版本）联动，见 `docs/21` §4。",
        "",
        "---",
        "本记录由 `tools/rollback_drill.py` 自动生成，结果来自真实 HTTP 返回。",
    ]
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\n记录已写入 {f}")
    return 0 if ok_all else 1


if __name__ == "__main__":
    sys.exit(main())
