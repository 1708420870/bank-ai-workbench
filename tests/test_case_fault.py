"""案例级故障演练的验收测试（v1.5.1）

对应 12 例里的 C 组：
  C03（fault=timeout）  → 工单 TIMEOUT，decision=HUMAN_HANDOFF，无复原结果
  C04（fault=bad_json） → 工单 REJECTED，decision=HUMAN_HANDOFF

背景：`cases` 表本来就有 fault 字段，但 handle_case 从未读取，
所以这两例 0.4 秒照常返回 RESTORED。这个测试锁住修复后的行为。
"""
from __future__ import annotations

import httpx
import pytest

from tests.env import TEST_ACCOUNT


def _own_cookie(urls: dict) -> dict:
    """自带会话，不依赖共享 COOKIE —— 避免与其它用例（SINGLE_SESSION）互相顶号。"""
    r = httpx.post(f"{urls['inner']}/internal/api/v1/auth/login",
                   json=TEST_ACCOUNT, timeout=20)
    assert r.status_code == 200, r.text
    return dict(r.cookies)


def _run_case(urls: dict, case_id: str) -> dict:
    r = httpx.post(f"{urls['inner']}/internal/api/v1/cases",
                   json={"case_id": case_id, "emp_id": "B001"},
                   timeout=40, cookies=_own_cookie(urls))
    assert r.status_code == 200, r.text
    return r.json()


@pytest.mark.parametrize(
    "case_id,expect_status,expect_reason",
    [
        ("C03", "TIMEOUT", "UPSTREAM_UNAVAILABLE"),
        ("C04", "REJECTED", "SCHEMA_INVALID"),
    ],
)
def test_case_fault_short_circuits(urls, case_id, expect_status, expect_reason):
    d = _run_case(urls, case_id)
    assert d["status"] == expect_status, f"{case_id} 期望 {expect_status}，实际 {d['status']}"
    assert d["decision"] == "HUMAN_HANDOFF"
    assert expect_reason in (d.get("reason_codes") or []), d.get("reason_codes")
    # fail-closed：故障案例不得产出复原文本
    assert not d.get("restored_text")


def test_case_without_fault_still_normal(urls):
    """对照组：A01 没有 fault，必须仍然是可展示建议（不能因为改判据被误伤）"""
    d = _run_case(urls, "A01")
    assert d["status"] == "RESTORED"
    assert d["decision"] == "SHOW_SUGGESTION"
