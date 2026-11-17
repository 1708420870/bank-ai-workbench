"""R9 回归：模型端点登记与逐端点审批闸门。

断言两件事：
  1. 出域端点若无审批人，`select()` 必须降级到内网端点（不依赖人的记性）；
  2. 气隙模式（EGRESS_ENABLED=false）下，任何意图都只能选到内网端点；
  3. 运行态登记表接口的字段与文档口径一致（region/auth/max_data_level/approved_by）。
"""
from __future__ import annotations

import pytest

from inner import agent as agent_mod
from inner.agent import ENDPOINTS, ModelConnector


def test_r9_egress_endpoint_requires_approval(monkeypatch):
    """把外网端点的审批人清空 → 必须降级到内网端点。"""
    ep = ENDPOINTS["ep-partner-b"]
    unapproved = agent_mod.Endpoint(
        ep.endpoint_id, ep.supplier, ep.version, ep.egress, ep.tier,
        region=ep.region, auth=ep.auth, max_data_level=ep.max_data_level,
        approved_by="", effective_from=ep.effective_from)
    monkeypatch.setitem(agent_mod.ENDPOINTS, "ep-partner-b", unapproved)
    got = ModelConnector().select("DISPUTE_PROCESS")
    assert got.endpoint_id == "ep-internal-a", "未审批的外网端点不得被选中"


def test_r9_airgap_mode_forces_internal(monkeypatch):
    """气隙模式：所有意图强制内网端点。"""
    monkeypatch.setattr(agent_mod, "EGRESS_ENABLED", False)
    for intent in ("DISPUTE_PROCESS", "TRANSACTION_QUERY", "SUSPECTED_UNAUTHORIZED",
                   "PENDING_CONFIRM", "FEEDBACK_REPLY", "UNKNOWN_INTENT_X"):
        assert ModelConnector().select(intent).endpoint_id == "ep-internal-a"


def test_r9_egress_endpoint_only_l1(monkeypatch):
    """外网端点数据等级必须为 L1（外网不允许接收 L2）。"""
    for ep in ENDPOINTS.values():
        if ep.egress:
            assert ep.max_data_level == "L1", f"{ep.endpoint_id} 位于外网却是 {ep.max_data_level}"


def test_r9_registry_api_fields(urls):
    """运行态登记表接口：字段齐备且与代码一致。"""
    import httpx
    from tests.env import COOKIE

    r = httpx.get(f"{urls['inner']}/internal/api/v1/model-endpoints", cookies=COOKIE, timeout=15)
    assert r.status_code == 200, r.text
    rows = {x["endpoint_id"]: x for x in r.json()}
    assert set(rows) == set(ENDPOINTS)
    for eid, ep in ENDPOINTS.items():
        row = rows[eid]
        assert row["region"] == ep.region
        assert row["auth"] == ep.auth
        assert row["max_data_level"] == ep.max_data_level
        assert row["callable"] == ((not ep.egress) or bool(ep.approved_by))


@pytest.fixture(scope="module", autouse=True)
def _fresh_admin_session(urls):
    """模块前后各刷新一次管理员会话：既保证本模块拿到有效会话，
    也保证后续模块拿到的不是被本模块顶掉的旧 sid（单会话互踢所致）。"""
    from tests.env import refresh_admin_cookie
    refresh_admin_cookie(urls["inner"])
    yield
    refresh_admin_cookie(urls["inner"])
