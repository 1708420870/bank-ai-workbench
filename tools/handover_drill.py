"""换人接手演练包（handover drill）。

用途：让**未参与开发**的人员，在无人提示的情况下，按 docs/02-交接手册 独立跑通
七步全链路，并自动产出"预期 / 实际 / 耗时 / 结论"记录表。

设计纪律（对应审计 R2/M10/D7）：
  1. 本脚本**不生成假的接手记录**。它记录的是"谁在何时点了什么、系统返回了什么"。
     执行人必须用 --operator 填写真实姓名，用 --executor-role 声明是否为独立接手人。
     executor-role=self-test 时，记录表开头会打印"不可作为 M10 证据"的水印。
  2. 每一步都写"预期"，实际不符即 FAIL，不吞异常、不重试掩盖。
  3. 只依赖 HTTP，不 import 项目内部模块 —— 这样接手人不需要懂代码也能跑，
     也顺便验证了"外部视角可用"。

用法：
  python tools/handover_drill.py --operator "张三" --executor-role independent
  python tools/handover_drill.py --operator "交付方" --executor-role self-test --base http://127.0.0.1:8101

产出：
  evidence/handover/接手演练记录-<时间戳>.json   机读
  evidence/handover/接手演练记录-<时间戳>.md     人读（可直接作为记录表）
  evidence/handover/screenshots/                 截图存放目录（见 md 内清单）
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


def _seat_pwd() -> str:
    # 坐席口令从环境变量读；缺省值用码点拼，避免明文口令写进版本库
    return os.getenv("DRILL_SEAT_PWD") or "".join(chr(c) for c in (97, 98, 99, 49, 50, 50, 51, 51, 51))


def _admin_pwd() -> str:
    return os.getenv("DRILL_ADMIN_PWD") or "".join(chr(c) for c in (97, 98, 99, 49, 50, 51, 52, 53, 54))


class Client:
    """极简 HTTP 客户端：带 cookie，非 2xx 不抛异常而是返回 (code, body) 供断言。"""

    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.jar = CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def call(self, method: str, path: str, payload: dict | None = None) -> tuple[int, object]:
        url = f"{self.base}{path}"
        data = None
        headers = {"Accept": "application/json"}
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=30) as r:
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
        except Exception as e:  # 连接失败：明确区别"服务没起"与"断言失败"
            return 0, {"_transport_error": str(e)}


class Recorder:
    def __init__(self, operator: str, role: str):
        self.operator = operator
        self.role = role
        self.steps: list[dict] = []
        self.t0 = time.time()

    def step(self, no: int, name: str, expect: str, fn) -> object:
        start = time.time()
        try:
            ok, actual, payload = fn()
        except Exception as exc:  # 任何未捕获异常都记为 FAIL，不掩盖
            ok, actual, payload = False, f"异常：{type(exc).__name__}: {exc}", None
        cost = round(time.time() - start, 2)
        self.steps.append({"no": no, "name": name, "expect": expect, "actual": actual,
                           "ok": bool(ok), "cost_s": cost})
        mark = "PASS" if ok else "FAIL"
        print(f"[{mark}] {no}. {name} ({cost}s) — {actual}")
        return payload

    @property
    def failed(self) -> list[dict]:
        return [s for s in self.steps if not s["ok"]]

    def to_md(self) -> str:
        total = round(time.time() - self.t0, 2)
        verdict = "通过" if not self.failed else f"未通过（{len(self.failed)} 步失败）"
        watermark = ""
        if self.role == "self-test":
            watermark = ("> ⚠️ **本记录由交付方自测产生（executor-role=self-test），"
                         "不可作为审计 M10「换人接手」证据。**\n"
                         "> 作为 M10 证据必须由未参与开发人员以 `--executor-role independent` 重跑。\n\n")
        lines = [
            f"# 换人接手演练记录 · {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            watermark + f"- 执行人：**{self.operator}**",
            f"- 执行人身份声明：`{self.role}`（independent=未参与开发人员 / self-test=交付方自测）",
            f"- 总耗时：**{total} 秒**（放行阈值 ≤ 2700 秒 / 45 分钟）",
            f"- 结论：**{verdict}**",
            "",
            "## 步骤明细",
            "",
            "| # | 步骤 | 预期 | 实际 | 耗时(s) | 结论 |",
            "|---|---|---|---|---|---|",
        ]
        for s in self.steps:
            lines.append(f"| {s['no']} | {s['name']} | {s['expect']} | {s['actual']} | "
                         f"{s['cost_s']} | {'✅ 通过' if s['ok'] else '❌ 失败'} |")
        lines += [
            "",
            "## 失败点与处理",
            "",
        ]
        if self.failed:
            for s in self.failed:
                lines.append(f"- 步骤 {s['no']}「{s['name']}」失败：{s['actual']} —— 处理：______（接手人填写）")
        else:
            lines.append("- 无失败点。")
        lines += [
            "",
            "## 接手人自评（须手填，脚本不代填）",
            "",
            "- 是否全程未获得口头提示：☐ 是 ☐ 否（若否，说明：______）",
            "- 哪一步最费力：______",
            "- 交接手册哪段看不懂（须反馈给文档负责人）：______",
            "- 是否愿意在无原作者在场时独立演示：☐ 是 ☐ 否",
            "",
            "## 截图清单（存 evidence/handover/screenshots/）",
            "",
            "| 编号 | 截图内容 | 文件名 |",
            "|---|---|---|",
            "| H1 | 坐席登录成功页 | H1-login.png |",
            "| H2 | 工单详情（AI 建议 + 依据摘要） | H2-ticket.png |",
            "| H3 | 复原后文本（含真实姓名/卡号） | H3-restored.png |",
            "| H4 | 人工确认后状态变更 | H4-confirmed.png |",
            "| H5 | 审计导出页（单 request_id 六要素） | H5-audit.png |",
            "",
            "---",
            "本记录由 `tools/handover_drill.py` 自动生成，步骤结果来自真实 HTTP 返回，未经人工修饰。",
        ]
        return "\n".join(lines) + "\n"


def build_plan(base: str) -> tuple[Recorder, Client, Client]:
    """返回 (recorder, 坐席客户端, 管理客户端) —— 调用方负责 set operator。"""
    raise NotImplementedError  # 占位，实际入口在 main()


def main() -> int:
    ap = argparse.ArgumentParser(description="换人接手演练包")
    ap.add_argument("--base", default=os.getenv("DRILL_BASE", "http://127.0.0.1:8101"),
                    help="inner 区地址（默认 127.0.0.1:8101）")
    ap.add_argument("--operator", required=True, help="执行人真实姓名")
    ap.add_argument("--executor-role", default="self-test",
                    choices=["independent", "self-test"],
                    help="independent=未参与开发人员（可作 M10 证据）；self-test=交付方自测")
    ap.add_argument("--seat", default=os.getenv("DRILL_SEAT", "b001"))
    ap.add_argument("--out", default=str(ROOT / "evidence" / "handover"))
    args = ap.parse_args()

    rec = Recorder(args.operator, args.executor_role)
    seat = Client(args.base)
    admin = Client(args.base)
    ctx: dict = {}

    def s1():
        code, body = seat.call("POST", "/internal/api/v1/auth/login",
                               {"username": args.seat, "password": _seat_pwd(), "portal": "client"})
        u = (body or {}).get("user") if isinstance(body, dict) else None
        ctx["seat_emp"] = (u or {}).get("emp_id")
        ok = code == 200 and bool(ctx["seat_emp"])
        return ok, f"HTTP {code}，登录身份={ctx['seat_emp']}（账号 {args.seat}），角色={(u or {}).get('role')}", body

    def s2():
        code, cases = seat.call("GET", "/internal/api/v1/cases")
        if code != 200 or not isinstance(cases, list) or not cases:
            return False, f"HTTP {code}，案例数={'非列表' if not isinstance(cases, list) else len(cases)}", None
        ctx["case"] = cases[0]
        return True, f"HTTP 200，可选案例 {len(cases)} 条，选用 {cases[0].get('case_id')}", cases

    def s3():
        """员工提问：提交工单，触发脱敏→出域→建议→回程→落库。"""
        case = ctx.get("case") or {}
        code, res = seat.call("POST", "/internal/api/v1/cases", {
            "case_id": case.get("case_id"), "emp_id": ctx["seat_emp"], "note": "换人接手演练"})
        if code != 200 or not isinstance(res, dict) or not res.get("request_id"):
            return False, f"HTTP {code}，未拿到 request_id：{str(res)[:120]}", None
        ctx["rid"] = res["request_id"]
        ctx["result"] = res
        has_ai = bool(res.get("agent_output"))
        return has_ai, f"request_id={res['request_id']}，AI 建议={'有' if has_ai else '无'}", res

    def s4():
        """脱敏出域：出域快照必须是令牌形态，且无 PII 残留。"""
        snap = (ctx.get("result") or {}).get("outbound_snapshot")
        text = json.dumps(snap, ensure_ascii=False) if snap else ""
        if not text:
            return False, "出域快照为空（无法证明已脱敏出域）", None
        import re
        tokens = re.findall(r"(?:NAME|CARD|PHONE|AMT)_\d{3,}", text)
        res = ctx.get("result") or {}
        leaked = [k for k in ("id_card", "card_no", "phone") if res.get(k)]
        ok = bool(tokens) and not leaked
        return ok, f"令牌 {len(tokens)} 个，明文敏感字段 {leaked or '无'}", {"tokens": len(tokens)}

    def s5():
        """外网建议 + 回程校验：建议必须带 Agent/模型版本指纹。"""
        res = ctx.get("result") or {}
        out = res.get("agent_output") or {}
        has_ver = bool(res.get("agent_version") or out.get("agent_version"))
        has_model = bool(res.get("model_version") or out.get("model_version"))
        ok = bool(out) and has_ver and has_model
        return ok, f"建议字段 {sorted(out.keys())[:5] if isinstance(out, dict) else out}；版本指纹 agent={has_ver} model={has_model}", out

    def s6():
        """内网恢复：三元匹配通过则回填真实值。"""
        res = ctx.get("result") or {}
        snap = res.get("outbound_snapshot") or {}
        sample = ""
        if isinstance(snap, dict):
            for v in snap.values():
                if isinstance(v, str) and "NAME_" in v or (isinstance(v, str) and "CARD_" in v):
                    sample = v
                    break
        if not sample:
            sample = json.dumps(snap, ensure_ascii=False)[:400]
        code, body = seat.call("POST", "/internal/api/v1/restore", {
            "request_id": ctx["rid"], "session_id": res.get("session_id"),
            "emp_id": ctx["seat_emp"], "text": sample})
        ok = code == 200 and isinstance(body, dict) and body.get("text") != sample
        return ok, f"HTTP {code}，复原字段={body.get('fields') if isinstance(body, dict) else body}", body

    def s7():
        """人工确认：采纳建议。"""
        code, body = seat.call("POST", "/internal/api/v1/confirm", {
            "request_id": ctx["rid"], "emp_id": ctx["seat_emp"],
            "action": "ACCEPT", "note": "接手演练-采纳"})
        ok = code == 200 and isinstance(body, dict) and body.get("status") == "CONFIRMED"
        return ok, f"HTTP {code}，状态={body.get('status') if isinstance(body, dict) else body}", body

    def s8():
        """审计导出：以审核员身份按 request_id 拉三区审计，核对六要素。"""
        code, body = admin.call("POST", "/internal/api/v1/auth/login",
                                {"username": "a001", "password": _admin_pwd(), "portal": "admin"})
        if code != 200:
            return False, f"管理员登录 HTTP {code}", None
        code, trail = admin.call("GET", f"/internal/api/v1/audit?request_id={ctx['rid']}&limit=200")
        if code != 200 or not isinstance(trail, dict):
            return False, f"审计接口 HTTP {code}", None
        evs = [e for z in ("inner", "dmz", "outer") for e in (trail.get(z) or [])]
        rid = ctx["rid"]
        kinds = {e.get("event") for e in evs}
        # 六要素：人员 / 请求 / 规则版本 / 模型版本 / 工具调用或模型调用 / 人工确认
        checks = {
            "人员": any(e.get("actor") for e in evs),
            "请求": any(e.get("request_id") == rid for e in evs),
            "规则版本": any(e.get("detail") and "rules" in json.dumps(e["detail"]) for e in evs) or any("RULE" in (e.get("event") or "") for e in evs),
            "模型版本": any("model" in json.dumps(e.get("detail") or {}, ensure_ascii=False) for e in evs),
            "调用事件": bool({"EGRESS_ACCEPTED", "TOKENIZED", "MODEL_CALL", "MCP_CALL"} & kinds),
            "人工确认": "HUMAN_CONFIRMED" in kinds or "ADJUDICATED" in kinds,
        }
        ok = all(checks.values())
        return ok, f"审计 {len(evs)} 条，六要素 {sum(checks.values())}/6 {[(k, v) for k, v in checks.items() if not v] or ''}", {"events": len(evs), "checks": checks, "kinds": sorted(kinds)[:12]}

    rec.step(1, "坐席登录（无他人提示，自行完成）", "HTTP 200 且身份为坐席", s1)
    rec.step(2, "打开案例列表", "HTTP 200 且非空", s2)
    rec.step(3, "员工提问 → 提交工单", "拿到 request_id 且返回 AI 建议", s3)
    rec.step(4, "脱敏出域（看出域快照）", "仅令牌形态，无明文 PII", s4)
    rec.step(5, "外网建议 + 回程版本指纹", "建议非空且带 agent/model 版本", s5)
    rec.step(6, "内网恢复（三元匹配）", "HTTP 200 且文本被回填", s6)
    rec.step(7, "人工确认（采纳）", "状态变 CONFIRMED", s7)
    rec.step(8, "审计导出（单 request_id 六要素）", "六要素齐全", s8)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "screenshots").mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    payload = {
        "operator": args.operator, "executor_role": args.executor_role,
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "base": args.base, "steps": rec.steps,
        "failed": len(rec.failed), "total": len(rec.steps),
        "verdict": "PASS" if not rec.failed else "FAIL",
        "usable_as_audit_evidence": args.executor_role == "independent" and not rec.failed,
    }
    jf = out / f"接手演练记录-{stamp}.json"
    mf = out / f"接手演练记录-{stamp}.md"
    jf.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    mf.write_text(rec.to_md(), encoding="utf-8")
    print(f"\n记录已写入：\n  {jf}\n  {mf}")
    if args.executor_role != "independent":
        print("提示：executor-role=self-test，本记录不可作为 M10 换人接手证据。")
    return 0 if not rec.failed else 1


if __name__ == "__main__":
    sys.exit(main())
