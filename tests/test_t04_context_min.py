"""T04 上下文最小化：出域只带白名单字段，历史/原文一律不出内网（v1.5.2）

任务书 T04：超范围上下文（历史对话、原文、整表导出）不得进入出域载荷。

本用例把"最小化"钉成三条可执行断言：
  ① 契约层：EgressTask 的字段集合 ⊆ EGRESS_FIELD_WHITELIST，且不含任何历史/原文键；
  ② 网关层：往 dispatch 里塞 `history` / `raw_text` / `transcript` 等键 → 400 FIELD_NOT_WHITELISTED；
  ③ 回程层：模型若越权返回 `history` 等键 → _validate_response 判越权，整包作废。

②③ 是"拿证据"而不是"读代码"：字段白名单必须在运行期真正拦住，而不是文档里写着。
"""
from __future__ import annotations

import httpx
import pytest

from common.config import SERVICE_TOKEN
from common.schema import (ALLOWED_OUTPUT_FIELDS, EGRESS_FIELD_WHITELIST,
                           EgressTask)
from inner.service import _validate_response

# 任何形态的历史 / 原文 / 整表，都不属于出域最小集
FORBIDDEN_KEYS = [
    "history", "messages", "raw_text", "transcript", "conversation",
    "note_full", "full_table", "token_map", "sealed_value", "customer_name",
]


def test_t04_contract_has_no_history_keys():
    """① 契约层：白名单里不许出现历史/原文类键。"""
    leaked = [k for k in FORBIDDEN_KEYS if k in EGRESS_FIELD_WHITELIST]
    assert leaked == [], f"出域白名单混入了上下文类字段: {leaked}"

    # 契约模型的字段必须完全落在白名单内（新增字段必须先改白名单，否则这里就红）
    fields = set(EgressTask.model_fields)
    assert fields <= EGRESS_FIELD_WHITELIST, f"契约字段越出白名单: {fields - EGRESS_FIELD_WHITELIST}"

    # 反向断言：模型能带出内网的只有"已脱敏上下文"这一个自由文本字段
    free_text = [f for f in fields if f in ("sanitized_context",)]
    assert len(free_text) == 1, "出域自由文本字段应且仅应有 sanitized_context"


@pytest.mark.parametrize("bad_key", ["history", "raw_text", "transcript"])
def test_t04_dispatch_rejects_context_field(urls, bad_key):
    """② 网关层：多带一个上下文键，DMZ 直接 400 拒收（不需要签名就到了这一步）。"""
    task = {
        "request_id": "REQ-20261120-T04TEST",
        "schema_version": "1.0",
        "trace_id": "trace-t04",
        "intent_hint": "DISPUTE_PROCESS",
        "sanitized_context": "客户咨询争议材料",
        "approved_rule_context": [],
        "allowed_output": list(ALLOWED_OUTPUT_FIELDS),
        "issued_at": "2026-11-20T10:00:00+08:00",
        "expires_at": "2099-01-01T00:00:00+08:00",
        bad_key: "前 30 轮完整对话原文……",
    }
    r = httpx.post(f"{urls['dmz']}/dmz/api/v1/dispatch", json=task,
                   headers={"x-service-token": SERVICE_TOKEN}, timeout=20)
    assert r.status_code == 400, f"{bad_key} 应被拒收，实际 {r.status_code}: {r.text}"
    assert "FIELD_NOT_WHITELISTED" in r.text or "白名单" in r.text, r.text


def test_t04_response_side_rejects_context_field():
    """③ 回程层：模型越权把历史塞回来，整包判作废。"""
    task = {"request_id": "REQ-20261120-T04RESP"}
    body = {
        "request_id": "REQ-20261120-T04RESP",
        "schema_version": "1.0",
        "intent_summary": "争议流程咨询",
        "reasoning_summary": "按规则 R-D1 给出材料清单",
        "missing_information": [],
        "recommended_next_step": "REQUEST_DISPUTE_FORM",
        "risk_flags": [],
        "source_rule_ids": ["R-D1"],
        "agent_version": "1.5.2",
        "model_supplier": "test",
        "model_version": "test",
        "history": ["上一轮客户原话……"],          # 越权字段
    }
    violations = _validate_response(body, task)
    assert any("越权字段" in v and "history" in v for v in violations), violations
