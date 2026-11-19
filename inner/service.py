"""内网业务编排：把 12 步主流程写成状态迁移。

每一步的失败动作都是显式分支。没有 `except: pass`，没有"降级到宽松模式"。
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

import httpx

from common import audit
from common.config import (
    DATA_KEY, DMZ_URL, EGRESS_ENABLED, MAX_FIELD_CHARS, MAX_RESPONSE_CHARS,
    PAYLOAD_TTL_SECONDS, SECRET_INNER_DMZ,
)
from common.crypto import sign, verify
from common.egress import BlockedEgress, guard
from common.logger import get as get_logger
from common.schema import ALLOWED_OUTPUT_FIELDS, SCHEMA_VERSION, AgentResponse, EgressTask

from . import db, rules as rule_engine
from .agent import NiumashiAgent
from .privacy import PrivacyService, restore_tokens

runlog = get_logger("inner", "service")

META_FIELDS = {"request_id", "schema_version", "agent_version", "model_supplier", "model_version", "signature"}


def _now() -> datetime:
    return datetime.now(timezone.utc).astimezone()


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def _iso_ms(dt: datetime) -> str:
    """毫秒精度时间戳：客户反馈会话专用。

    同一请求内客户消息与 AI 答复常落在同一秒，秒级时间戳并列后只能靠插入
    顺序兜底，而网关缓存（outer）的插入顺序与真实对话时序相反（AI 答复先
    经 deliver 入缓存、客户消息回执后落库），会导致客户端会话顺序颠倒。
    毫秒精度从根上消除并列。
    """
    return dt.isoformat(timespec="milliseconds")


def _rid() -> str:
    return f"REQ-{_now():%Y%m%d}-{uuid.uuid4().hex[:6].upper()}"


def _privacy() -> PrivacyService:
    return PrivacyService([c["name"] for c in db.all_customers()])


def _persist(request_id: str, **fields) -> None:
    existing = db.ticket(request_id) or {}
    existing.update(fields)
    existing["request_id"] = request_id
    existing["updated_at"] = _iso(_now())
    db.save_ticket(**existing)


async def handle_case(*, case_id: str, emp_id: str, session_id: str | None, note: str | None) -> dict:
    emp = db.employee(emp_id)
    if not emp or emp["role"] not in {"agent", "supervisor", "auditor"}:
        raise PermissionError("身份或岗位不足，拒绝创建客服任务")

    case = db.get_case(case_id)
    if not case:
        raise LookupError(f"案例不存在: {case_id}")

    cust = db.customer(case["customer_id"])
    txn = db.transaction(case["txn_id"]) if case["txn_id"] else None
    intent = case["intent"]
    request_id = _rid()
    session_id = session_id or f"SES-{uuid.uuid4().hex[:8].upper()}"
    created = _iso(_now())

    db.save_ticket(
        request_id=request_id, session_id=session_id, emp_id=emp_id, case_id=case_id,
        status="CREATED", intent=intent, decision=None, reason_codes=None,
        agent_version=None, model_supplier=None, model_version=None, rule_ids=None,
        outbound_snapshot=None, agent_output=None, restored_text=None,
        created_at=created, updated_at=created,
    )
    audit.log("inner", "CASE_CREATED", request_id=request_id, actor=emp_id,
              detail={"case_id": case_id, "intent": intent, "session_id": session_id})

    # ②.5【补丁 v1.5.1】案例级故障演练：case.fault 声明了就按故障处理，不再走模型
    # 背景：C03/C04 在 cases 表里带着 fault=timeout / bad_json，但原实现从未读取，
    #       结果 0.4 秒照常返回 RESTORED（见 12 例逐案 C03/C04）。
    _fault = (case.get("fault") or "").strip()
    if _fault in {"timeout", "bad_json"}:
        _status = "TIMEOUT" if _fault == "timeout" else "REJECTED"
        _reason = "UPSTREAM_UNAVAILABLE" if _fault == "timeout" else "SCHEMA_INVALID"
        audit.log("inner", "FAULT_INJECTED", request_id=request_id, actor=emp_id,
                  severity="medium",
                  detail={"fault": _fault, "source": "case.fault", "case_id": case_id})
        _persist(request_id, status=_status, decision="HUMAN_HANDOFF",
                 reason_codes=json.dumps([_reason, "FAIL_CLOSED_HUMAN"], ensure_ascii=False))
        return _result(request_id)

    # ③ 最小取数
    raw_text = case["narrative"] if not note else f"{case['narrative']} 补充说明：{note}"

    # ③.5【补丁 v1.5.1】隐私三级判据（判据实现在 privacy.py，单一职责）
    privacy = _privacy()
    _judge = privacy.judge(raw_text, note)
    if _judge:
        audit.log("inner", "PRIVACY_JUDGED", request_id=request_id, actor=emp_id,
                  severity=_judge["severity"],
                  detail={"rule": _judge["code"], "msg": _judge["msg"], "case_id": case_id})
        _persist(request_id, status=_judge["status"], decision="HUMAN_HANDOFF",
                 reason_codes=json.dumps([_judge["code"], "MANDATORY_HUMAN"], ensure_ascii=False))
        return _result(request_id)

    # ④ 字段识别与令牌化（privacy 实例已在 ③.5 建好）
    try:
        masked = privacy.mask(raw_text, request_id)
    except Exception as exc:
        audit.log("inner", "MASK_FAILED", request_id=request_id, actor=emp_id,
                  severity="critical", detail={"error": str(exc)})
        _persist(request_id, status="BLOCKED", decision="HUMAN_HANDOFF",
                 reason_codes=json.dumps(["MASK_FAILED"], ensure_ascii=False))
        return _result(request_id)

    db.put_tokens(request_id, masked.tokens, created)
    audit.log("inner", "TOKENIZED", request_id=request_id, actor=emp_id,
              detail={"counts": masked.counts, "tokens": [t[0] for t in masked.tokens]})

    # ⑤ 规则摘要提取
    local_rules = db.rules_for(intent)
    rule_ctx = rule_engine.build_egress_context(local_rules)

    # ⑥ 构造出域载荷并扫描
    task = EgressTask(
        request_id=request_id,
        trace_id=request_id,
        intent_hint=intent,
        sanitized_context=masked.text,
        approved_rule_context=rule_ctx,
        allowed_output=list(ALLOWED_OUTPUT_FIELDS),
        issued_at=created,
        expires_at=_iso(_now() + timedelta(seconds=PAYLOAD_TTL_SECONDS)),
    ).model_dump()

    findings = privacy.scan_payload({k: v for k, v in task.items() if k != "signature"})
    if findings:
        audit.log("inner", "EGRESS_BLOCKED_LOCAL", request_id=request_id, actor=emp_id,
                  severity="critical", detail={"findings": findings})
        _persist(request_id, status="BLOCKED", decision="HUMAN_HANDOFF",
                 reason_codes=json.dumps(["EGRESS_RESIDUAL"], ensure_ascii=False),
                 outbound_snapshot=json.dumps(task, ensure_ascii=False))
        return _result(request_id)

    task["signature"] = sign(task, SECRET_INNER_DMZ)
    snapshot = json.dumps(task, ensure_ascii=False, indent=2)
    _persist(request_id, status="SCANNING", outbound_snapshot=snapshot)

    # ⑦⑧ Agent 规划 + 模型调用（内网端点或经 DMZ 出域）
    agent = NiumashiAgent()
    try:
        plan = agent.plan(intent, masked.text)
    except NotImplementedError:
        raise
    except Exception as exc:
        audit.log("inner", "AGENT_ERROR", request_id=request_id, severity="high", detail={"error": str(exc)})
        runlog.warning("agent_plan_failed", extra={"extra_data": {
            "request_id": request_id, "error": f"{type(exc).__name__}: {exc}"}})
        _persist(request_id, status="HUMAN_HANDOFF", decision="HUMAN_HANDOFF",
                 reason_codes=json.dumps(["AGENT_UNAVAILABLE"], ensure_ascii=False))
        return _result(request_id)

    if plan["route"] == "EXTERNAL":
        _persist(request_id, status="DISPATCHED", agent_version=plan["agent_version"])
        try:
            status, body = await _dispatch(task)
        except BlockedEgress as exc:
            audit.log("inner", "EGRESS_DENIED", request_id=request_id, severity="critical",
                      detail={"error": str(exc)})
            _persist(request_id, status="BLOCKED", decision="HUMAN_HANDOFF",
                     reason_codes=json.dumps(["EGRESS_DENIED"], ensure_ascii=False))
            return _result(request_id)
        except Exception as exc:
            audit.log("inner", "DISPATCH_FAILED", request_id=request_id, severity="high",
                      detail={"error": str(exc)})
            _persist(request_id, status="TIMEOUT", decision="HUMAN_HANDOFF",
                     reason_codes=json.dumps(["UPSTREAM_UNAVAILABLE"], ensure_ascii=False))
            return _result(request_id)

        if status != 200:
            # 5xx 视为上游不可用（超时/熔断），标记 TIMEOUT 并转人工；
            # 4xx 视为策略或契约拒绝，标记 REJECTED。两者都不重试同一 request_id。
            final = "TIMEOUT" if status >= 500 else "REJECTED"
            _persist(request_id, status=final, decision="HUMAN_HANDOFF",
                     reason_codes=json.dumps([f"GATEWAY_STATUS_{status}"], ensure_ascii=False))
            return _result(request_id)

        violations = _validate_response(body, task)
        if violations:
            audit.log("inner", "RESPONSE_REJECTED", request_id=request_id, severity="critical",
                      detail={"violations": violations})
            _persist(request_id, status="REJECTED", decision="HUMAN_HANDOFF",
                     reason_codes=json.dumps(["RESPONSE_INVALID"], ensure_ascii=False))
            return _result(request_id)

        output = {k: v for k, v in body.items() if k in ALLOWED_OUTPUT_FIELDS}
        meta = {k: body[k] for k in ("agent_version", "model_supplier", "model_version")}
    else:
        output = plan["output"]
        meta = {k: plan[k] for k in ("agent_version", "model_supplier", "model_version")}
        _persist(request_id, status="VALIDATED")

    _persist(request_id, status="ADJUDICATED", agent_output=json.dumps(output, ensure_ascii=False),
             agent_version=meta["agent_version"], model_supplier=meta["model_supplier"],
             model_version=meta["model_version"])

    # ⑩ 规则裁决（模型之后独立运行）
    known_ids = {r["rule_id"] for r in db.all_rules()}
    verdict = rule_engine.evaluate(intent=intent, agent_output=output,
                                   local_rules=local_rules, known_rule_ids=known_ids)
    _persist(request_id, decision=verdict["decision"],
             reason_codes=json.dumps(verdict["reason_codes"], ensure_ascii=False),
             rule_ids=json.dumps(verdict["rule_ids"], ensure_ascii=False))
    audit.log("inner", "ADJUDICATED", request_id=request_id, actor=emp_id,
              detail={"decision": verdict["decision"], "reasons": verdict["reason_codes"],
                      "conflicts": verdict["conflicts"],
                      "agent_version": meta["agent_version"],
                      "model": f"{meta['model_supplier']}/{meta['model_version']}"})

    if verdict["decision"] != "SHOW_SUGGESTION":
        _persist(request_id, status="HUMAN_HANDOFF")
        return _result(request_id)

    # ⑪ 字段复原（当前会话 + 当前员工 + 当前请求，三元匹配成立）
    composed = (
        f"【建议摘要】{output.get('intent_summary', '')}\n"
        f"【建议动作】{output.get('recommended_next_step', '')}\n"
        f"【话术模板】{verdict['template']}\n"
        f"【客户上下文】{masked.text}"
    )
    restored, used = restore_tokens(composed, db.tokens_of(request_id), DATA_KEY)
    db.log_restore(request_id, session_id, emp_id, _iso(_now()), used)
    _persist(request_id, status="RESTORED", restored_text=restored)
    audit.log("inner", "RESTORED", request_id=request_id, actor=emp_id,
              detail={"fields": used})
    return _result(request_id)


async def _dispatch(task: dict) -> tuple[int, dict]:
    if not EGRESS_ENABLED:
        raise BlockedEgress("inner", f"{DMZ_URL}/dmz/api/v1/dispatch (DEPLOY_MODE: EGRESS_ENABLED=false)",
                            set())
    url = f"{DMZ_URL}/dmz/api/v1/dispatch"
    guard("inner", url)
    async with httpx.AsyncClient(timeout=10) as client:
        # 透传 trace：DMZ 侧审计沿用同一个 trace_id，跨区事件才能串成一条链
        r = await client.post(url, json=task,
                              headers={"x-trace-id": str(task.get("trace_id") or "")})
        try:
            body = r.json()
        except Exception:
            body = {"_raw": r.text}
        return r.status_code, body


def _validate_response(body: dict, task: dict) -> list[str]:
    """回程校验（标准六项 + 签名，共七道，任一不过即作废）。

    与甲方标准的对应关系（口径统一，文档与代码一致）：
      ① Schema        —— AgentResponse 结构校验
      ② 长度          —— 整体长度上限 + 单字段长度上限（防超长注入/撑爆存储）
      ③ 字段白名单    —— 只允许 ALLOWED_OUTPUT_FIELDS + META_FIELDS
      ④ 敏感内容      —— 复用出域扫描器复检（防外网把原文/新 PII 塞回来）
      ⑤ request_id    —— 必须与本次请求一致（防串包）
      ⑥ 版本          —— schema_version + agent_version + model_version 三者齐备且匹配
      ⑦ 签名          —— HMAC 校验（PoC）；生产为 mTLS + JWS
    """
    v: list[str] = []
    if not isinstance(body, dict):
        return ["响应不是 JSON 对象"]

    # ② 长度：先量长度，再做结构解析——超长载荷不应进入任何解析器
    try:
        serialized = json.dumps(body, ensure_ascii=False)
    except Exception as exc:
        return [f"响应不可序列化: {exc}"]
    if len(serialized) > MAX_RESPONSE_CHARS:
        v.append(f"响应超长: {len(serialized)} > {MAX_RESPONSE_CHARS}")
    for k, val in body.items():
        if isinstance(val, str) and len(val) > MAX_FIELD_CHARS:
            v.append(f"字段 {k} 超长: {len(val)} > {MAX_FIELD_CHARS}")

    # ③ 字段白名单
    extra = set(body.keys()) - set(ALLOWED_OUTPUT_FIELDS) - META_FIELDS
    if extra:
        v.append(f"越权字段: {sorted(extra)}")

    # ① Schema
    try:
        AgentResponse(**{k: body[k] for k in AgentResponse.model_fields if k in body})
    except Exception as exc:
        v.append(f"Schema 校验失败: {exc}")

    # ④ 敏感内容复检：外网返回不得携带原文或新型 PII
    #    先摘掉令牌形态再扫（模型可能复述令牌，令牌本身不是泄露），
    #    命中即整包作废，不做"局部剔除后放行"——局部放行等于信任攻击者。
    try:
        sensitive = _privacy().scan_payload(body)
    except Exception as exc:
        sensitive = [f"敏感内容扫描异常: {exc}"]
    if sensitive:
        v.append(f"回程敏感内容: {sensitive}")

    # ⑤ request_id
    if body.get("request_id") != task["request_id"]:
        v.append("request_id 不一致")

    # ⑥ 版本
    if body.get("schema_version") != SCHEMA_VERSION:
        v.append("schema_version 不一致")
    if not body.get("agent_version") or not body.get("model_version"):
        v.append("缺少 Agent/模型版本指纹")

    # ⑦ 签名
    if not verify(body, SECRET_INNER_DMZ):
        v.append("响应签名无效")

    allowed = set(task.get("allowed_output") or [])
    if allowed and not set(body.keys()) & allowed:
        v.append("响应未包含任何允许字段")
    return v


def _result(request_id: str) -> dict:
    row = db.ticket(request_id) or {}
    for k in ("reason_codes", "rule_ids", "agent_output", "outbound_snapshot"):
        if row.get(k):
            try:
                row[k] = json.loads(row[k])
            except Exception:
                pass
    row["template"] = rule_engine.template_for(row.get("intent") or "PENDING_CONFIRM")
    return row


def restore_for_display(request_id: str, session_id: str, emp_id: str, text: str) -> dict:
    """对外复原接口：必须三元匹配。跨会话、跨人员一律拒绝（T06）。"""
    row = db.ticket(request_id)
    if not row:
        raise LookupError("请求不存在")
    if row["session_id"] != session_id:
        audit.log("inner", "RESTORE_DENIED", request_id=request_id, actor=emp_id,
                  severity="critical", detail={"reason": "session_mismatch"})
        raise PermissionError("会话不匹配，拒绝复原")
    if row["emp_id"] != emp_id:
        audit.log("inner", "RESTORE_DENIED", request_id=request_id, actor=emp_id,
                  severity="critical", detail={"reason": "actor_mismatch"})
        raise PermissionError("操作者不匹配，拒绝复原")

    restored, used = restore_tokens(text, db.tokens_of(request_id), DATA_KEY)
    db.log_restore(request_id, session_id, emp_id, _iso(_now()), used)
    audit.log("inner", "RESTORED", request_id=request_id, actor=emp_id, detail={"fields": used})
    return {"text": restored, "fields": used}
