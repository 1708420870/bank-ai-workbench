"""多轮意图兜底的单元测试（v1.5.2）

场景：客户先问「想对一笔消费提争议，要什么材料」，AI 答完，客户只回「嗯」。
关键词命中不了，之前会掉回通用话术；现在应沿用上一轮的意图。
"""
from __future__ import annotations

from inner.app import _fb_compose_reply, _fb_intent_hint

HISTORY = [
    {"sender": "customer", "body": "想对一笔 268 元消费提争议，需要准备什么材料？"},
    {"sender": "ai", "body": "您好，如涉及交易争议，可以在手机银行 App「交易争议」入口提交。"},
]


def test_short_reply_inherits_dispute_intent():
    assert _fb_intent_hint("嗯", HISTORY) == "REQUEST_DISPUTE_FORM"
    assert _fb_intent_hint("对", HISTORY) == "REQUEST_DISPUTE_FORM"
    assert _fb_intent_hint("继续", HISTORY) == "REQUEST_DISPUTE_FORM"


def test_short_reply_without_history_is_none():
    assert _fb_intent_hint("嗯", None) is None
    assert _fb_intent_hint("嗯", []) is None


def test_long_message_not_inherited():
    """超过 3 个字且不含确认语，不应继承（避免把所有话都当确认）"""
    assert _fb_intent_hint("那这个要多久才能处理完", HISTORY) is None


def test_compose_reply_uses_history_for_short_reply():
    reply, meta = _fb_compose_reply("ACCOUNT", "嗯", history=HISTORY)
    assert meta.get("next_step") == "REQUEST_DISPUTE_FORM"
    assert "交易争议" in reply
    assert reply.strip(), "答复不得为空"
