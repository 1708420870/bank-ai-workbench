"""R7 回归：变更草稿审批发布流水线（C10 / A4 / 一票否决 #3 的补充证据）。

覆盖状态机全部合法迁移与四种非法迁移：
  PENDING_REVIEW → APPROVED → PUBLISHED → ROLLED_BACK（合法）
  · 自审批 → 403
  · 未审批直接发布 → 409
  · 门槛未过发布 → 409
  · 审批后篡改草稿再发布 → 409
"""
from __future__ import annotations

import uuid

import httpx
import pytest

from tests.env import COOKIE, SERVICE_HEADERS


def _submit(urls, payload: dict, actor: str = "T001", tool: str = "submit_skill_draft") -> dict:
    payload = {**payload, "purpose": f"{payload.get('purpose','草稿')} · {uuid.uuid4().hex[:8]}"}
    r = httpx.post(f"{urls['dmz']}/dmz/api/v1/mcp/call",
                   json={"tool": tool, "actor": actor, "role": "developer", "args": payload},
                   timeout=25, headers=SERVICE_HEADERS)
    assert r.status_code == 200, f"提交草稿失败 {r.status_code}: {r.text[:200]}"
    return r.json()["data"]


def _api(urls, method: str, path: str, **kw) -> httpx.Response:
    return httpx.request(method, f"{urls['inner']}{path}", cookies=COOKIE, timeout=25, **kw)


GOOD_PAYLOAD = {
    "purpose": f"新增争议受理 Skill 草稿 {uuid.uuid4().hex[:6]}",
    "dependencies": [],
    "synthetic_dataset_id": "synthetic-cases-v1",
    "test_cases": ["case A01 争议受理", "case A02 查询指引", "case A03 转人工"],
}


def test_r7_full_lifecycle(urls):
    """合法全链路：提交 → 审批 → 门槛 → 发布 → 回滚，每步都要留审计。"""
    d = _submit(urls, GOOD_PAYLOAD)
    cid = d["change_id"]
    assert d["status"] == "PENDING_REVIEW"

    r = _api(urls, "POST", f"/internal/api/v1/changes/{cid}/review",
             json={"decision": "APPROVE", "note": "R7 审批"})
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "APPROVED"

    g = _api(urls, "POST", f"/internal/api/v1/changes/{cid}/gate")
    assert g.status_code == 200, g.text
    assert g.json()["passed"] is True, g.json()
    assert len(g.json()["checks"]) == 5

    p = _api(urls, "POST", f"/internal/api/v1/changes/{cid}/publish")
    assert p.status_code == 200, p.text
    body = p.json()
    assert body["status"] == "PUBLISHED" and body["version"].startswith("skill-v")

    rb = _api(urls, "POST", f"/internal/api/v1/changes/{cid}/rollback",
              json={"reason": "R7 回滚演练：验证可回退"})
    assert rb.status_code == 200, rb.text
    assert rb.json()["status"] == "ROLLED_BACK"

    # 审计侧证：四类事件齐全
    trail = _api(urls, "GET", "/internal/api/v1/audit?limit=300").json()
    events = {e["event"] for e in trail.get("inner", [])}
    for ev in ("DRAFT_APPROVED", "GATE_CHECKED", "DRAFT_PUBLISHED", "DRAFT_ROLLBACK"):
        assert ev in events, f"审计缺少 {ev}，实际含 {sorted(events)}"


def test_r7_publish_without_approval_denied(urls):
    """未审批直接发布 → 409（草稿不能跳过审批）。"""
    d = _submit(urls, GOOD_PAYLOAD)
    r = _api(urls, "POST", f"/internal/api/v1/changes/{d['change_id']}/publish")
    assert r.status_code == 409, f"期望 409，实际 {r.status_code}"
    assert "审批" in r.text


def test_r7_publish_without_gate_denied(urls):
    """审批通过但未过门槛 → 409（APPROVED 只是"同意"，不是"可上线"）。"""
    d = _submit(urls, GOOD_PAYLOAD)
    cid = d["change_id"]
    _api(urls, "POST", f"/internal/api/v1/changes/{cid}/review", json={"decision": "APPROVE"})
    r = _api(urls, "POST", f"/internal/api/v1/changes/{cid}/publish")
    assert r.status_code == 409
    assert "门槛" in r.text


def test_r7_gate_blocks_banned_dependency(urls):
    """门槛：依赖黑名单（pickle）→ 不通过，且发布被拒。"""
    payload = dict(GOOD_PAYLOAD)
    payload["dependencies"] = ["pickle"]
    d = _submit(urls, payload)
    cid = d["change_id"]
    _api(urls, "POST", f"/internal/api/v1/changes/{cid}/review", json={"decision": "APPROVE"})
    g = _api(urls, "POST", f"/internal/api/v1/changes/{cid}/gate").json()
    assert g["passed"] is False
    failed = [c["id"] for c in g["checks"] if not c["ok"]]
    assert "DEPENDENCY_SCAN" in failed
    r = _api(urls, "POST", f"/internal/api/v1/changes/{cid}/publish")
    assert r.status_code == 409


def test_r7_gate_blocks_production_write_claim(urls):
    """门槛：草稿声明 write_production → 判不通过（防"把生产写包装成 Skill"）。"""
    payload = dict(GOOD_PAYLOAD)
    payload["write_production"] = True
    d = _submit(urls, payload)
    cid = d["change_id"]
    _api(urls, "POST", f"/internal/api/v1/changes/{cid}/review", json={"decision": "APPROVE"})
    g = _api(urls, "POST", f"/internal/api/v1/changes/{cid}/gate").json()
    assert g["passed"] is False
    assert "NO_PROD_WRITE" in [c["id"] for c in g["checks"] if not c["ok"]]


def test_r7_self_approval_denied(urls):
    """自审批 → 403，且审计留 AUTHZ_DENIED(self_approval)。"""
    from inner import db
    cid = f"CHG-SELF-{uuid.uuid4().hex[:6].upper()}"
    db.add_change(cid, "rule", "A001", "自审批测试", {"purpose": "x"}, "2026-11-17T00:00:00")
    r = _api(urls, "POST", f"/internal/api/v1/changes/{cid}/review",
             json={"decision": "APPROVE"})
    assert r.status_code == 403
    assert "自己" in r.text


def test_r7_tampered_after_approval_denied(urls):
    """审批后篡改草稿 → 发布时指纹不一致 → 409（防"批一套发一套"）。"""
    from inner import db
    import json as _json
    d = _submit(urls, GOOD_PAYLOAD)
    cid = d["change_id"]
    _api(urls, "POST", f"/internal/api/v1/changes/{cid}/review", json={"decision": "APPROVE"})
    assert _api(urls, "POST", f"/internal/api/v1/changes/{cid}/gate").json()["passed"] is True
    # 绕过 API 直接改库：模拟"库被改"或"审批后补内容"
    db.set_change(cid, payload=_json.dumps({"purpose": "偷换的用途", "test_cases": ["a", "b", "c"]},
                                           ensure_ascii=False))
    r = _api(urls, "POST", f"/internal/api/v1/changes/{cid}/publish")
    assert r.status_code == 409
    assert "不一致" in r.text


def test_r7_rollback_requires_published(urls):
    """非 PUBLISHED 状态不可回滚。"""
    d = _submit(urls, GOOD_PAYLOAD)
    r = _api(urls, "POST", f"/internal/api/v1/changes/{d['change_id']}/rollback",
             json={"reason": "不该成功"})
    assert r.status_code == 409


def test_r7_draft_never_touches_production_rule(urls):
    """草稿无论走到哪一步，生产规则版本保持不变（T16 的强化版）。"""
    before = {r["rule_id"]: r["version"] for r in _api(urls, "GET", "/internal/api/v1/rules").json()}
    d = _submit(urls, GOOD_PAYLOAD, tool="submit_rule_change_request")
    cid = d["change_id"]
    _api(urls, "POST", f"/internal/api/v1/changes/{cid}/review", json={"decision": "APPROVE"})
    _api(urls, "POST", f"/internal/api/v1/changes/{cid}/gate")
    _api(urls, "POST", f"/internal/api/v1/changes/{cid}/publish")
    after = {r["rule_id"]: r["version"] for r in _api(urls, "GET", "/internal/api/v1/rules").json()}
    assert before == after, "草稿发布不得直接改动生产规则版本"


@pytest.fixture(scope="module", autouse=True)
def _fresh_admin_session(urls):
    """模块前后各刷新一次管理员会话：既保证本模块拿到有效会话，
    也保证后续模块拿到的不是被本模块顶掉的旧 sid（单会话互踢所致）。"""
    from tests.env import refresh_admin_cookie
    refresh_admin_cookie(urls["inner"])
    yield
    refresh_admin_cookie(urls["inner"])
