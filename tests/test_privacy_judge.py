"""隐私三级判据的单元测试（v1.5.1）

对应 12 例验收里的 C 组：
  C01 带完整证件号          → BLOCKED / PRIVACY_ID_NUMBER
  C02 要求回拨且给完整手机号 → HUMAN_HANDOFF / CALLBACK_REQUIRES_AUTH
  A 组正文里的合成卡号/手机号 → 不得命中（否则 A 组全误杀）

这几条是纯函数级验证，不需要起服务。
"""
from __future__ import annotations

from inner.privacy import PrivacyService


def _svc() -> PrivacyService:
    return PrivacyService([])  # 不注入已知姓名，判据只看标识形态


def test_judge_id_number_blocked():
    """C01：正文出现 18 位证件号 → BLOCKED"""
    svc = _svc()
    text = "客户 张示例 办理查询，客服在备注中粘贴了完整身份信息 110101199001011231 与卡号 6222000000000001。"
    f = svc.judge(text)
    assert f is not None
    assert f["status"] == "BLOCKED"
    assert f["code"] == "PRIVACY_ID_NUMBER"
    assert f["severity"] == "critical"


def test_judge_card_in_note_blocked():
    """补充说明里出现完整卡号 → BLOCKED（人把原文贴进了业务文本）"""
    svc = _svc()
    f = svc.judge("客户咨询账单明细", note="卡号 6222000000000009 帮我查一下")
    assert f is not None
    assert f["status"] == "BLOCKED"
    assert f["code"] == "PRIVACY_RAW_CARD_IN_NOTE"


def test_judge_callback_requires_human():
    """C02：要求回拨/回访且给了完整手机号 → 转人工（外呼需二次授权）"""
    svc = _svc()
    text = "客户 李合成 来电，回拨号码 13800138002，要求回访，并提及姓名与卡号 6222000000000002。"
    f = svc.judge(text)
    assert f is not None
    assert f["status"] == "HUMAN_HANDOFF"
    assert f["code"] == "CALLBACK_REQUIRES_AUTH"


def test_judge_a_group_text_not_hit():
    """A 组正文含合成卡号/手机号，但没有人粘贴动作 → 不得命中"""
    svc = _svc()
    a01 = ("客户 张示例 来电，询问如何对卡号 6222000000000001 的一笔消费发起争议，"
           "需要准备哪些材料。联系电话 13800138001。")
    assert svc.judge(a01) is None
    a03 = "客户 王样测 询问卡号 6222000000000003 上一笔金额 15600.00 元的交易当前状态。"
    assert svc.judge(a03) is None


def test_judge_plain_text_no_hit():
    svc = _svc()
    assert svc.judge("想问一下信用卡年费怎么查") is None
    assert svc.judge("") is None
    assert svc.judge(None) is None
