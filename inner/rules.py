"""内网规则引擎：最终裁决权的唯一持有者。

设计要点：规则引擎不是"校验模型结论"，而是"在模型之后独立作出结论"。
两者差别很大——前者是模型说了算再补个检查，后者是模型只提供候选。

ADR-04 / T10 的落地。
"""
from __future__ import annotations

from common.schema import ACTION_CODES

# 规则 → 允许的动作集。动作不在集合内即判定为与规则冲突。
RULE_ACTION_POLICY: dict[str, set[str]] = {
    "R-DISPUTE-01": {"REQUEST_DISPUTE_FORM", "COLLECT_MORE_INFO", "HUMAN_REVIEW"},
    "R-DISPUTE-02": {"COLLECT_MORE_INFO", "REQUEST_DISPUTE_FORM", "HUMAN_REVIEW"},
    "R-TXN-01": {"GUIDE_APP_QUERY", "COLLECT_MORE_INFO", "HUMAN_REVIEW"},
    "R-TXN-02": {"GUIDE_APP_QUERY", "COLLECT_MORE_INFO", "HUMAN_REVIEW"},
    "R-UNAUTH-01": {"HUMAN_REVIEW"},
    "R-UNAUTH-02": {"HUMAN_REVIEW", "COLLECT_MORE_INFO"},
    "R-PENDING-01": {"HUMAN_REVIEW"},
    "R-PENDING-02": {"HUMAN_REVIEW", "COLLECT_MORE_INFO"},
}

# 模型不得声称已执行业务动作
PROHIBITED_CLAIMS = ["已为您办理", "已冻结", "已退款", "已赔付", "已撤销", "承诺赔付", "保证赔付"]

# 各意图对应的批准回复模板（低风险场景使用）
_TEMPLATES = {
    "DISPUTE_PROCESS": "请引导客户打开手机银行 App →「我的」→「交易争议」→ 选择对应交易提交申请。"
                       "需准备：交易时间、金额、商户名称、争议原因说明。客服不代为提交，也不承诺处理时限。",
    "TRANSACTION_QUERY": "请引导客户在 App →「账户」→「交易明细」中自助查看该笔记录。"
                         "如需口头核对，仅提供卡号后四位。交易状态以核心系统为准。",
    "SUSPECTED_UNAUTHORIZED": "请先建议客户临时冻结卡片，随后转入风控人工核查工单。"
                              "不得回复处理结论，不得承诺赔付。",
    "PENDING_CONFIRM": "客户陈述不足以判定意图，请转人工坐席继续沟通，并补充：具体交易时间、金额、诉求类型。",
}


def build_egress_context(rules: list[dict]) -> list[dict]:
    """只把「规则编号 + 批准摘要」送出内网，完整规则正文留在内网。"""
    return [{"rule_id": r["rule_id"], "summary": r["summary"]} for r in rules]


def mandatory_human(rules: list[dict]) -> bool:
    return any(int(r.get("mandatory_human", 0)) == 1 for r in rules)


def template_for(intent: str) -> str:
    return _TEMPLATES.get(intent, _TEMPLATES["PENDING_CONFIRM"])


def evaluate(
    *,
    intent: str,
    agent_output: dict,
    local_rules: list[dict],
    known_rule_ids: set[str],
) -> dict:
    """在模型输出之后独立裁决。返回 decision + reason_codes + conflicts。

    任何一个 reason code 都是 HUMAN_HANDOFF 的理由；只有全部通过才 SHOW_SUGGESTION。
    """
    reasons: list[str] = []
    conflicts: list[str] = []

    action = agent_output.get("recommended_next_step", "")
    cited = agent_output.get("source_rule_ids", []) or []
    risk_flags = agent_output.get("risk_flags", []) or []
    blob = " ".join(
        str(agent_output.get(k, "")) for k in ("intent_summary", "reasoning_summary", "recommended_next_step")
    )

    # ① 意图级强制人工
    if mandatory_human(local_rules):
        reasons.append("MANDATORY_HUMAN")

    # ② 模型自报需人工
    if "HUMAN_REVIEW_REQUIRED" in risk_flags:
        reasons.append("AGENT_REQUESTED_HUMAN")

    # ③ 引用了不存在的规则 —— 属幻觉，一律不可采纳
    unknown = [r for r in cited if r not in known_rule_ids]
    if unknown:
        reasons.append("INVALID_RULE_REFERENCE")
        conflicts.append(f"引用未登记规则: {','.join(unknown)}")

    # ④ 动作码越界
    if action not in ACTION_CODES:
        reasons.append("INVALID_ACTION_CODE")

    # ⑤ 动作与所引规则语义冲突 —— 内网规则为准
    if cited and action in ACTION_CODES:
        allowed: set[str] = set()
        for rid in cited:
            allowed |= RULE_ACTION_POLICY.get(rid, set())
        if allowed and action not in allowed:
            reasons.append("RULE_ACTION_CONFLICT")
            conflicts.append(f"建议动作 {action} 与规则 {','.join(cited)} 允许集不符")

    # ⑥ 声称已执行业务动作
    hit = [p for p in PROHIBITED_CLAIMS if p in blob]
    if hit:
        reasons.append("PROHIBITED_CLAIM")
        conflicts.append(f"越权表述: {','.join(hit)}")

    # ⑦ 意图未识别
    if not agent_output.get("intent_summary") or not action:
        reasons.append("MISSING_REQUIRED_OUTPUT")

    decision = "HUMAN_HANDOFF" if reasons else "SHOW_SUGGESTION"

    # ⑧【补丁 v1.5.3 · T10】内网规则优先：一旦判定转人工，模型给的"下一步"不再对外
    # 理由：转人工场景下若仍写着 COLLECT_MORE_INFO，坐席会去收集信息，
    #       而正确动作是交人工研判——"外部建议与内网规则冲突，以内网为准"的落地。
    action_override = None
    _force = {"MANDATORY_HUMAN", "RULE_ACTION_CONFLICT", "INVALID_RULE_REFERENCE",
              "PROHIBITED_CLAIM", "INVALID_ACTION_CODE"}
    if decision == "HUMAN_HANDOFF" and (_force & set(reasons)) and action != "HUMAN_REVIEW":
        action_override = "HUMAN_REVIEW"
        reasons = list(reasons) + ["ACTION_OVERRIDDEN_BY_RULE"]

    return {
        "decision": decision,
        "reason_codes": sorted(set(reasons)),
        "conflicts": conflicts,
        "rule_ids": [r["rule_id"] for r in local_rules],
        "template": template_for(intent) if decision == "SHOW_SUGGESTION" else None,
        "action_override": action_override,
    }
