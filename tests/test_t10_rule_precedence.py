"""T10 内网规则优先：判定转人工后，动作码收敛为 HUMAN_REVIEW（v1.5.3）

任务书 T10：外部建议与内网规则冲突时，以内网为准。

原缺陷：B04 已经 HUMAN_HANDOFF（MANDATORY_HUMAN + INVALID_RULE_REFERENCE），
但建议动作仍是 COLLECT_MORE_INFO——坐席看到会去"收集更多信息"，而正确动作是交人工研判。
修法：规则引擎在判定转人工且命中强制类理由时给出 action_override=HUMAN_REVIEW，
service 落库前覆盖模型给的动作码，并记 ACTION_OVERRIDDEN 审计（可追溯"是谁改的"）。
"""
from __future__ import annotations

from inner.rules import evaluate

KNOWN = {"R-PENDING-01", "R-PENDING-02", "R-DISPUTE-01", "R-TXN-01"}
MANDATORY_RULE = [{"rule_id": "R-PENDING-02", "mandatory_human": 1, "summary": "挂账/待确认必须人工"}]


def _out(action: str, cited: list[str], **kw) -> dict:
    base = {
        "intent_summary": "PENDING_CONFIRM",
        "reasoning_summary": "客户称已转账但对方未收到",
        "recommended_next_step": action,
        "source_rule_ids": cited,
        "risk_flags": [],
    }
    base.update(kw)
    return base


def test_t10_mandatory_human_forces_human_review():
    """强制人工 + 模型给 COLLECT_MORE_INFO → 收敛为 HUMAN_REVIEW，并留覆盖理由。"""
    v = evaluate(intent="PENDING_CONFIRM",
                 agent_output=_out("COLLECT_MORE_INFO", ["R-PENDING-02"]),
                 local_rules=MANDATORY_RULE, known_rule_ids=KNOWN)
    assert v["decision"] == "HUMAN_HANDOFF"
    assert "MANDATORY_HUMAN" in v["reason_codes"]
    assert v["action_override"] == "HUMAN_REVIEW", v
    assert "ACTION_OVERRIDDEN_BY_RULE" in v["reason_codes"], v


def test_t10_invalid_rule_reference_forces_human_review():
    """模型引用了不存在的规则（幻觉）→ 转人工且动作码收敛。"""
    v = evaluate(intent="PENDING_CONFIRM",
                 agent_output=_out("COLLECT_MORE_INFO", ["R-NOT-EXIST-99"]),
                 local_rules=[], known_rule_ids=KNOWN)
    assert v["decision"] == "HUMAN_HANDOFF"
    assert "INVALID_RULE_REFERENCE" in v["reason_codes"]
    assert v["action_override"] == "HUMAN_REVIEW", v


def test_t10_normal_case_keeps_model_action():
    """正常放行场景不动模型给的动作码——覆盖只在转人工时生效。"""
    v = evaluate(intent="DISPUTE_PROCESS",
                 agent_output=_out("REQUEST_DISPUTE_FORM", ["R-DISPUTE-01"]),
                 local_rules=[], known_rule_ids=KNOWN)
    assert v["decision"] == "SHOW_SUGGESTION"
    assert v["action_override"] is None, v


def test_t10_already_human_review_not_duplicated():
    """模型本来就给 HUMAN_REVIEW → 不重复覆盖、不加多余理由。"""
    v = evaluate(intent="PENDING_CONFIRM",
                 agent_output=_out("HUMAN_REVIEW", ["R-PENDING-02"]),
                 local_rules=MANDATORY_RULE, known_rule_ids=KNOWN)
    assert v["decision"] == "HUMAN_HANDOFF"
    assert v["action_override"] is None
    assert "ACTION_OVERRIDDEN_BY_RULE" not in v["reason_codes"]
