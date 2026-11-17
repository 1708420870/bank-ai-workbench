"""跨域载荷契约。字段即白名单：不在这份模型里的键，网关一律拒收。

契约是分区间唯一的耦合点，也是"新增字段必须先改契约"这句话的物理实现。
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.0"

# 出域载荷允许出现的键——网关据此做第一道白名单
EGRESS_FIELD_WHITELIST = {
    "request_id",
    "schema_version",
    "trace_id",
    "intent_hint",
    "sanitized_context",
    "approved_rule_context",
    "allowed_output",
    "issued_at",
    "expires_at",
    "signature",
}

# 模型可以返回的字段——不在其中即视为越权输出
ALLOWED_OUTPUT_FIELDS = [
    "intent_summary",
    "reasoning_summary",
    "missing_information",
    "recommended_next_step",
    "risk_flags",
    "source_rule_ids",
]

INTENTS = [
    "DISPUTE_PROCESS",
    "TRANSACTION_QUERY",
    "SUSPECTED_UNAUTHORIZED",
    "PENDING_CONFIRM",
]

# 建议动作码：模型只能从这些码里选，不接受自由文本动作
ACTION_CODES = {
    "REQUEST_DISPUTE_FORM",
    "GUIDE_APP_QUERY",
    "HUMAN_REVIEW",
    "COLLECT_MORE_INFO",
}


class RuleRef(BaseModel):
    rule_id: str
    summary: str


class EgressTask(BaseModel):
    request_id: str
    schema_version: str = SCHEMA_VERSION
    trace_id: str
    intent_hint: str
    sanitized_context: str
    approved_rule_context: list[RuleRef] = Field(default_factory=list)
    allowed_output: list[str] = Field(default_factory=lambda: list(ALLOWED_OUTPUT_FIELDS))
    issued_at: str
    expires_at: str
    signature: str | None = None


class AgentResponse(BaseModel):
    request_id: str
    schema_version: str = SCHEMA_VERSION
    intent_summary: str
    reasoning_summary: str
    missing_information: list[str] = Field(default_factory=list)
    recommended_next_step: str
    risk_flags: list[str] = Field(default_factory=list)
    source_rule_ids: list[str] = Field(default_factory=list)
    agent_version: str
    model_supplier: str
    model_version: str
    signature: str | None = None


class CreateCaseRequest(BaseModel):
    case_id: str
    emp_id: str
    session_id: str | None = None
    note: str | None = None
    intent_override: str | None = None


class RestoreRequest(BaseModel):
    request_id: str
    session_id: str
    emp_id: str
    text: str


class ConfirmRequest(BaseModel):
    request_id: str
    emp_id: str
    action: Literal["ACCEPT", "MODIFY", "HUMAN_HANDOFF", "REJECT"]
    note: str | None = None


class FaultRequest(BaseModel):
    mode: Literal["ok", "timeout", "bad_json", "unknown_intent"]


class McpCall(BaseModel):
    tool: str
    actor: str
    role: str
    args: dict = Field(default_factory=dict)


class ChangeRequest(BaseModel):
    kind: Literal["skill", "workflow", "rule"]
    owner: str
    purpose: str
    payload: dict = Field(default_factory=dict)


# ---------------- 身份与会话 ----------------

class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)
    portal: Literal["client", "admin"] = "client"


class McpProxyRequest(BaseModel):
    tool: str
    args: dict = Field(default_factory=dict)


class UserStateRequest(BaseModel):
    active: bool


class CreateUserRequest(BaseModel):
    emp_id: str = Field(min_length=2, max_length=16, pattern=r"^[A-Za-z0-9_-]+$")
    name: str = Field(min_length=1, max_length=32)
    username: str = Field(min_length=3, max_length=32, pattern=r"^[a-z0-9_]+$")
    password: str = Field(min_length=8, max_length=128)
    role: Literal["agent", "supervisor", "auditor", "developer"]


class PasswordResetRequest(BaseModel):
    password: str = Field(min_length=8, max_length=128)


# ---------------- OA：个人中心 / 通知 / 请假 ----------------

class ChangePasswordRequest(BaseModel):
    old_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)


class NoticeRequest(BaseModel):
    title: str = Field(min_length=1, max_length=80)
    body: str = Field(min_length=1, max_length=2000)
    level: Literal["normal", "important", "urgent"] = "normal"


class LeaveSubmitRequest(BaseModel):
    start_date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    end_date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    reason: str = Field(min_length=2, max_length=500)


class LeaveReviewRequest(BaseModel):
    action: Literal["APPROVED", "REJECTED"]
    comment: str = Field(default="", max_length=300)


class MustChangePwdRequest(BaseModel):
    enabled: bool


class DmSendRequest(BaseModel):
    to_emp_id: str = Field(min_length=2, max_length=16)
    body: str = Field(min_length=1, max_length=500)


# ---------------- 第二期：客户反馈小程序（M2 契约） ----------------

# 客户反馈业务类型（客户端只能从中选择，不接受自由文本类别）
FEEDBACK_CATEGORIES = {"ACCOUNT", "LOAN", "CREDIT_CARD", "OTHER"}


class FeedbackIngestRequest(BaseModel):
    """客户反馈入站（网关 → DMZ → inner）。kind: ticket=新提单, message=追加消息, eval=评价。"""
    fb_id: str = Field(min_length=6, max_length=40)
    openid_hash: str = Field(min_length=16, max_length=64)
    category: str
    body_masked: str = Field(min_length=1, max_length=2000)
    kind: Literal["ticket", "message", "eval"] = "ticket"
    created_at: str | None = None


class FeedbackDeliverRequest(BaseModel):
    """答复出站（inner → DMZ 裁决 → 网关缓存）。status_after: 裁决通过后的工单状态。"""
    fb_id: str = Field(min_length=6, max_length=40)
    rid: str = Field(min_length=6, max_length=48)
    sender: str = Field(min_length=2, max_length=16)
    body: str = Field(min_length=1, max_length=2000)
    status_after: str
    created_at: str | None = None


class FeedbackSeatReplyRequest(BaseModel):
    """坐席人工回复（inner 内部，回复文本出站前同样过 DMZ 裁决）。"""
    body: str = Field(min_length=1, max_length=500)
