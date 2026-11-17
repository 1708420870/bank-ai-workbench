"""R5 回归：回程校验六项（标准口径）单元级用例。

审计 R5 指出原实现"自述五重校验、实际 7 项但缺长度与敏感内容两项"。
本文件把"缺的两项"钉成可复跑的断言，防止后续改动再退化。

为什么用单元级而不是纯端到端：
- 端到端很难稳定构造"外网返回超长/含 PII"的恶意响应（需要篡改 outer 行为）；
- 回程校验是纯函数，逐项断言才能定位到具体哪一项失效；
- 同时保留一个端到端用例（tests/test_acceptance.py）证明它真的被调用。
"""
from __future__ import annotations

import json
import uuid

import pytest

from common.config import SECRET_INNER_DMZ, SCHEMA_VERSION
from common.crypto import sign
from common.schema import ALLOWED_OUTPUT_FIELDS
from inner import db, service


@pytest.fixture(scope="module", autouse=True)
def _init_db():
    db.init()
    yield


def _body(request_id: str, **override) -> dict:
    """构造一个"各项都合法"的响应，再按需覆盖字段。"""
    body = {
        "request_id": request_id,
        "schema_version": SCHEMA_VERSION,
        "intent_summary": "客户咨询交易争议处理流程",
        "reasoning_summary": "依据规则摘要判断属于争议受理范围，需客户补充交易时间",
        "missing_information": ["交易时间"],
        "recommended_next_step": "指导客户提交争议申请表",
        "risk_flags": [],
        "source_rule_ids": ["R-001"],
        "agent_version": "bull-hermes-1.4.2",
        "model_supplier": "internal-llm",
        "model_version": "Qwen3.5-9B-AWQ",
    }
    body.update(override)
    body.pop("signature", None)
    body["signature"] = sign(body, SECRET_INNER_DMZ)
    return body


def _task(request_id: str) -> dict:
    return {"request_id": request_id, "allowed_output": list(ALLOWED_OUTPUT_FIELDS)}


def test_r5_baseline_valid_response_passes():
    """基线：合法响应零违例——防止"一加校验就全拒"的过度收紧。"""
    rid = "REQ-R5-BASE"
    assert service._validate_response(_body(rid), _task(rid)) == []


def test_r5_overlong_rejected(monkeypatch):
    """长度校验：整体长度超上限必须拒绝（标准第②项）。

    通过压低阈值构造，避免真的拼接 8KB 字符串导致用例变慢、日志变脏。
    """
    monkeypatch.setattr(service, "MAX_RESPONSE_CHARS", 200)
    rid = "REQ-R5-LONG"
    v = service._validate_response(_body(rid), _task(rid))
    assert any("响应超长" in x for x in v), v


def test_r5_single_field_overlong_rejected(monkeypatch):
    """长度校验（单字段）：一个字段塞超长文本也必须拒绝，不能被整体阈值掩盖。"""
    monkeypatch.setattr(service, "MAX_FIELD_CHARS", 20)
    rid = "REQ-R5-FIELD"
    v = service._validate_response(_body(rid), _task(rid))
    assert any("超长" in x and "reasoning_summary" in x for x in v), v


def test_r5_sensitive_residue_rejected():
    """敏感内容复检：外网把手机号原文塞回来 → 整包作废（标准第④项）。"""
    rid = "REQ-R5-PII"
    v = service._validate_response(
        _body(rid, reasoning_summary="已按客户手机号 13800138000 核对"), _task(rid))
    assert any("回程敏感内容" in x for x in v), v


def test_r5_card_and_id_residue_rejected():
    """敏感内容复检：卡号 / 证件号原文同样必须拦。"""
    rid = "REQ-R5-CARD"
    v = service._validate_response(
        _body(rid, reasoning_summary="核对卡号 6222021234567890123 与证件 110101199001011234"), _task(rid))
    hit = [x for x in v if "回程敏感内容" in x]
    assert hit, v
    assert "卡号残留" in hit[0] and "证件号残留" in hit[0], hit


def test_r5_token_echo_not_flagged():
    """令牌回显不算泄露：模型复述 NAME_001 是允许的（否则会误杀正常建议）。"""
    rid = "REQ-R5-TOKEN"
    v = service._validate_response(
        _body(rid, reasoning_summary="客户 NAME_001 的卡 CARD_001 存在争议"), _task(rid))
    assert v == [], v


def test_r5_request_id_mismatch_rejected():
    """request_id 串包校验（标准第⑤项）。"""
    v = service._validate_response(_body("REQ-OTHER"), _task("REQ-MINE"))
    assert any("request_id 不一致" in x for x in v), v


def test_r5_version_mismatch_rejected():
    """版本校验（标准第⑥项）：schema_version 不符必须拒绝。"""
    rid = "REQ-R5-VER"
    v = service._validate_response(_body(rid, schema_version="0.9"), _task(rid))
    assert any("schema_version 不一致" in x for x in v), v


def test_r5_missing_model_version_rejected():
    """版本校验：缺模型版本指纹必须拒绝（否则无法追溯用了哪个模型）。"""
    rid = "REQ-R5-NOVER"
    b = _body(rid)
    b["model_version"] = ""
    b.pop("signature", None)
    b["signature"] = sign(b, SECRET_INNER_DMZ)
    v = service._validate_response(b, _task(rid))
    assert any("版本指纹" in x for x in v), v


def test_r5_signature_tamper_rejected():
    """签名校验（第⑦项）：改内容不重签 → 拒。"""
    rid = "REQ-R5-SIG"
    b = _body(rid)
    b["reasoning_summary"] = "被篡改的建议"
    v = service._validate_response(b, _task(rid))
    assert any("签名无效" in x for x in v), v


def test_r5_extra_field_rejected():
    """字段白名单（第③项）：多一个字段就拒。"""
    rid = "REQ-R5-EXTRA"
    b = _body(rid)
    b["raw_customer_note"] = "原文"
    b.pop("signature", None)
    b["signature"] = sign(b, SECRET_INNER_DMZ)
    v = service._validate_response(b, _task(rid))
    assert any("越权字段" in x for x in v), v
