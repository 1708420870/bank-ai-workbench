"""R6 回归：DMZ 网关限流 + 入站长度 + 回程恶意内容扫描。

审计 R6 原文：*"MCP 网关无限流 → C10 不达标 → 滑动窗口限流 429 + RATE_LIMITED 审计"*。
本文件把三件事钉住：
  1. 超限必须 429，且审计里留下 RATE_LIMITED（可导出、可复验）；
  2. 超长入站必须 413/400，不进业务逻辑；
  3. 外网返回带提示注入/脚本 → 回程直接拒（第⑨道），内网收不到。
"""
from __future__ import annotations

import json

import httpx
import pytest

from common.config import RATE_LIMIT_MAX_CALLS
from tests.env import COOKIE, SERVICE_HEADERS


def _mcp(urls, tool: str, role: str = "developer", args: dict | None = None,
         actor: str = "RATE-TEST-01") -> httpx.Response:
    return httpx.post(f"{urls['dmz']}/dmz/api/v1/mcp/call",
                      json={"tool": tool, "actor": actor, "role": role,
                            "args": args or {}},
                      timeout=25, headers=SERVICE_HEADERS)


def test_r6_mcp_rate_limited_returns_429(urls):
    """同一 actor+tool 连续调用超过窗口上限 → 第 N+1 次 429。"""
    actor = "RATE-TEST-429"
    codes = []
    for _ in range(RATE_LIMIT_MAX_CALLS + 1):
        r = _mcp(urls, "list_rule_catalog", "developer", {}, actor=actor)
        codes.append(r.status_code)
    assert codes[-1] == 429, f"期望最后一次 429，实际序列尾部 {codes[-3:]}"
    assert any(c == 200 for c in codes), "限流前应有正常放行的调用"
    assert "频率超限" in r.text


def test_r6_rate_limited_audited(urls):
    """限流必须留审计：RATE_LIMITED 可被审核员导出（否则无法证明限流生效）。"""
    r = httpx.get(f"{urls['inner']}/internal/api/v1/audit?limit=200", timeout=15, cookies=COOKIE)
    assert r.status_code == 200
    trail = r.json()
    dmz_events = [e["event"] for e in trail.get("dmz", [])]
    assert "RATE_LIMITED" in dmz_events, f"审计中未见 RATE_LIMITED，实际事件：{set(dmz_events)}"
    hit = [e for e in trail["dmz"] if e["event"] == "RATE_LIMITED"]
    detail = json.loads(hit[0]["detail"]) if isinstance(hit[0]["detail"], str) else hit[0]["detail"]
    assert detail.get("limit") and detail.get("window_s"), detail


def test_r6_actor_wide_limit_independent_of_tool(urls):
    """换工具不能绕过 actor 总额度（防"每个工具各刷一遍"）。"""
    from common.config import RATE_LIMIT_MAX_PER_ACTOR
    actor = "RATE-TEST-ACTOR"
    tools = ["list_rule_catalog", "get_rule_metadata", "list_synthetic_cases",
             "get_aggregate_metrics", "get_masked_sample_case"]
    codes = []
    for i in range(RATE_LIMIT_MAX_PER_ACTOR + 2):
        codes.append(_mcp(urls, tools[i % len(tools)], "developer", {}, actor=actor).status_code)
    assert 429 in codes, f"actor 总额度未生效，状态码序列 {set(codes)}"


def test_r6_dispatch_request_too_large(urls):
    """入站载荷超长 → 413，且不进字段白名单/签名等后续逻辑。"""
    from common.config import MAX_REQUEST_CHARS
    from common.crypto import sign
    from common.config import SECRET_INNER_DMZ
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc).astimezone()
    task = {
        "request_id": "REQ-R6-BIG",
        "schema_version": "1.0",
        "trace_id": "REQ-R6-BIG",
        "intent_hint": "TRANSACTION_QUERY",
        "sanitized_context": "A" * (MAX_REQUEST_CHARS + 100),
        "approved_rule_context": [],
        "allowed_output": ["intent_summary"],
        "issued_at": now.isoformat(timespec="seconds"),
        "expires_at": (now + timedelta(seconds=300)).isoformat(timespec="seconds"),
    }
    task["signature"] = sign(task, SECRET_INNER_DMZ)
    r = httpx.post(f"{urls['dmz']}/dmz/api/v1/dispatch", json=task, timeout=20)
    assert r.status_code == 413, f"期望 413，实际 {r.status_code}: {r.text[:200]}"
    assert "REQUEST_TOO_LARGE" in r.text


def test_r6_mcp_args_too_large(urls):
    """MCP 参数超长 → 413，并写 MCP_DENIED(args_too_large)。"""
    from common.config import MAX_REQUEST_CHARS
    r = _mcp(urls, "submit_skill_draft", "developer",
             {"purpose": "x" * (MAX_REQUEST_CHARS + 100)}, actor="RATE-TEST-BIG")
    assert r.status_code == 413, f"期望 413，实际 {r.status_code}: {r.text[:200]}"


def test_r6_response_prompt_injection_blocked(urls):
    """回程第⑨道：外网返回携带提示注入 → 网关拦截，内网不会收到该载荷。

    构造方式：把 outer 切到 inject 模式（合法签名 + 合法结构 + 恶意正文），
    断言 DMZ 拦截并留审计，内网最终状态为 TIMEOUT/REJECTED（转人工）而非 ADJUDICATED。
    """
    r = httpx.post(f"{urls['outer']}/outer/api/v1/_fault", json={"mode": "inject"}, timeout=10)
    assert r.status_code == 200, f"故障注入失败：{r.status_code} {r.text[:120]}"
    try:
        cases = httpx.get(f"{urls['inner']}/internal/api/v1/cases", timeout=15, cookies=COOKIE).json()
        case = next(c for c in cases if c.get("intent") in
                    ("TRANSACTION_QUERY", "DISPUTE_PROCESS", "PENDING_CONFIRM"))
        res = httpx.post(f"{urls['inner']}/internal/api/v1/cases",
                         json={"case_id": case["case_id"], "emp_id": "B002",
                               "note": "R6 注入测试"},
                         timeout=40, cookies=COOKIE).json()
        assert res["status"] in ("REJECTED", "TIMEOUT", "BLOCKED"), \
            f"注入响应不应被采纳，实际状态 {res['status']}"
        assert not res.get("agent_output"), "被拒的响应不得进入工作台"
        # 审计侧证：DMZ 明确记录了拦截原因
        trail = httpx.get(f"{urls['inner']}/internal/api/v1/audit?limit=200", timeout=15, cookies=COOKIE).json()
        codes = []
        for e in trail.get("dmz", []):
            if e["event"] != "EGRESS_DENIED":
                continue
            d = json.loads(e["detail"]) if isinstance(e["detail"], str) else (e["detail"] or {})
            codes.append(d.get("code"))
        assert any(c in ("RESPONSE_MALICIOUS_CONTENT", "RESPONSE_PII_RESIDUE") for c in codes), \
            f"审计未见回程拦截证据，实际拒绝码：{set(codes)}"
    finally:
        httpx.post(f"{urls['outer']}/outer/api/v1/_fault", json={"mode": "ok"}, timeout=10)


@pytest.fixture(scope="module", autouse=True)
def _fresh_admin_session(urls):
    """模块前后各刷新一次管理员会话：既保证本模块拿到有效会话，
    也保证后续模块拿到的不是被本模块顶掉的旧 sid（单会话互踢所致）。"""
    from tests.env import refresh_admin_cookie
    refresh_admin_cookie(urls["inner"])
    yield
    refresh_admin_cookie(urls["inner"])
