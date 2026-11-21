"""客户通道答复分流的单元测试（v1.5.1）

覆盖三件事：
  1. 低风险"提争议" → 给交易争议入口的具体话术（不再是通用自助话术）
  2. 信息不足"看不懂" → 追问缺失信息
  3. 话术里不得出现内部术语（动作码/意图摘要/JSON 等）

只测纯函数，不起服务。高风险关键词分流在 inner/app.py 的 fb_ingest 里，
由 test_acceptance 的客户反馈用例覆盖。
"""
from __future__ import annotations

from inner.app import _fb_compose_reply, _fb_intent_hint


def test_intent_hint_dispute():
    assert _fb_intent_hint("想对一笔 268 元消费提争议，需要准备什么材料？") == "REQUEST_DISPUTE_FORM"


def test_intent_hint_unclear():
    assert _fb_intent_hint("账单里有一笔 39.9 元扣款我看不懂") == "COLLECT_MORE_INFO"


def test_intent_hint_none_for_generic():
    assert _fb_intent_hint("想问信用卡年费在哪看") is None


def test_dispute_reply_mentions_dispute_entry():
    reply, meta = _fb_compose_reply("ACCOUNT", "想对一笔 268 元消费提争议，需要准备什么材料？")
    assert meta.get("next_step") == "REQUEST_DISPUTE_FORM"
    assert "交易争议" in reply
    assert reply.strip(), "答复不得为空"


def test_unclear_reply_asks_for_detail():
    reply, meta = _fb_compose_reply("ACCOUNT", "账单里有一笔 39.9 元扣款我看不懂")
    assert meta.get("next_step") == "COLLECT_MORE_INFO"
    assert "补充" in reply


def test_reply_has_no_internal_terms():
    for body in ("想对一笔 268 元消费提争议，需要准备什么材料？", "账单里有一笔 39.9 元扣款我看不懂"):
        reply, _ = _fb_compose_reply("ACCOUNT", body)
        for bad in ("动作码", "意图摘要", "risk_flags", "next_step", "JSON", "HUMAN_REVIEW"):
            assert bad not in reply, f"答复出现内部术语：{bad}"
