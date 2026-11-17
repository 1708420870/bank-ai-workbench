"""安全交换区 / DMZ：跨域交换网关 + MCP 受控网关。

两条职责分得很清：
  /dmz/api/v1/dispatch —— 数据跨域。四重白名单（方向/协议/目标/字段）+ 内容复检 + TTL + 重放。
  /dmz/api/v1/mcp/call —— 工具跨域。工具级授权 + 参数 Schema + 身份透传 + 审计。

关于内容复检的一个诚实说明：DMZ 不持有客户名单，因此它能查的是"形态"
（卡号/手机号/证件号/金额的字符模式），查不出"这个中文名是不是客户"。
姓名级检测只能在内网完成——这也是为什么两道的失效模式必须不同，而不是简单重复。
"""
from __future__ import annotations

import hmac
import json
import re
import time
from collections import deque
from datetime import datetime, timezone

import httpx
from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from common import audit
from common.config import (
    DMZ_PORT, INNER_URL, MAX_REQUEST_CHARS, OUTER_URL, RATE_LIMIT_MAX_CALLS,
    RATE_LIMIT_MAX_PER_ACTOR, RATE_LIMIT_WINDOW_SECONDS, SECRET_DMZ_OUTER,
    SECRET_INNER_DMZ, SERVICE_TOKEN,
)
from common.crypto import sign, verify
from common.egress import guard
from common.logger import get as get_logger
from common.schema import (
    EGRESS_FIELD_WHITELIST, FeedbackDeliverRequest, FeedbackIngestRequest, McpCall,
)

app = FastAPI(title="安全交换区 / DMZ", version="1.0")

runlog = get_logger("dmz", "gateway")

# 仅用于 PoC：允许外网技术入口面板访问 MCP 网关与健康检查。生产按白名单收敛。
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

# 已处理 request_id（重放检测）。PoC 用进程内集合，生产应落带 TTL 的分布式存储。
_SEEN: dict[str, float] = {}

# 形态级 DLP 规则（DMZ 侧）
_DLP = [
    ("CARD_LIKE", re.compile(r"\b\d{16,19}\b")),
    ("PHONE_LIKE", re.compile(r"\b1[3-9]\d{9}\b")),
    ("ID_LIKE", re.compile(r"\b\d{17}[\dXx]\b")),
    ("AMOUNT_LIKE", re.compile(r"[¥￥]\s?\d")),
]

# 令牌形态（与 inner/privacy.TOKEN_RE 一致）：回程 PII 复检前先摘掉，避免误报
_TOKEN_RE = re.compile(r"\b(?:NAME|CARD|PHONE|ID|AMT|DATE|MERCHANT|ACCT|TXN)_\d{3,}\b")

# 回程恶意内容特征（第⑨道）：外网返回不得携带可执行指令/提示注入/脚本片段。
# 这批规则的作用不是"识别攻击者"，而是"不让攻击者的载荷以合法 JSON 的形式进内网"。
_MALICIOUS = [
    ("PROMPT_INJECTION", re.compile(r"忽略(?:之前|以上|先前)的?(?:指令|规则|设定)|ignore\s+(?:all\s+)?previous\s+instructions", re.I)),
    ("SYSTEM_PROMPT_PROBE", re.compile(r"system\s*prompt|系统提示词", re.I)),
    ("SCRIPT_INJECTION", re.compile(r"<\s*script|javascript:|onerror\s*=", re.I)),
    ("SQL_INJECTION", re.compile(r"\b(?:drop|truncate)\s+table\b|\bunion\s+select\b", re.I)),
    ("SHELL_INJECTION", re.compile(r"\brm\s+-rf\b|\bcurl\s+http|\bwget\s+http", re.I)),
]

# 滑动窗口限流：key -> 时间戳队列。PoC 用进程内结构，生产应落 Redis 等共享存储。
_RATE: dict[str, deque] = {}

MCP_TOOL_ALLOWLIST = {
    "list_rule_catalog", "get_rule_metadata", "get_approved_rule_summary",
    "list_synthetic_cases", "get_masked_sample_case", "get_aggregate_metrics",
    "submit_skill_draft", "submit_workflow_draft", "submit_rule_change_request",
    "run_sandbox_test", "get_change_status",
}

# 出现在拒绝清单里的名字：注册表里不存在，调用时给出明确的策略拒绝
MCP_DENIED_HINTS = {
    "get_raw_customer_record", "query_customer_account", "execute_sql",
    "export_full_customer_dataset", "update_production_rule", "execute_refund_or_freeze",
}


@app.on_event("startup")
def _startup() -> None:
    audit.log("dmz", "ZONE_START", trace_id="DMZ-START", detail={"zone": "dmz", "port": DMZ_PORT})
    runlog.info("dmz_zone_started", extra={"extra_data": {"port": DMZ_PORT}})


@app.middleware("http")
async def _trace_middleware(request: Request, call_next):
    """DMZ 侧 trace：沿用内网传入的 X-Trace-Id，保证跨区事件同一 trace。"""
    tid = (request.headers.get("x-trace-id") or "").strip() or f"TR-DMZ-{int(time.time() * 1000)}"
    audit.set_trace(tid)
    response = await call_next(request)
    response.headers["X-Trace-Id"] = tid
    return response


@app.get("/dmz/api/v1/health")
def health() -> dict:
    return {"zone": "dmz", "status": "ok"}


def _rate_limit(key: str, limit: int, actor: str, scope: str, detail: dict | None = None) -> None:
    """滑动窗口限流。超限返回 429 并写 RATE_LIMITED 审计。

    为什么按 key 分开计数而不是全局一个桶：
    一个科技人员刷爆自己的额度，不应该让另一个人的 MCP 调用被连带拒绝（可用性）；
    但同一 actor 跨工具的总额度也要有上限（防止换工具绕过）。
    """
    now = time.time()
    q = _RATE.setdefault(key, deque())
    while q and now - q[0] > RATE_LIMIT_WINDOW_SECONDS:
        q.popleft()
    if len(q) >= limit:
        audit.log("dmz", "RATE_LIMITED", actor=actor or "anonymous", severity="high",
                  detail={"key": key, "scope": scope,
                          "window_s": RATE_LIMIT_WINDOW_SECONDS,
                          "limit": limit, "observed": len(q), **(detail or {})})
        runlog.warning("rate_limited", extra={"extra_data": {
            "key": key, "scope": scope, "limit": limit}})
        raise HTTPException(429, f"调用频率超限（{scope}）：{RATE_LIMIT_WINDOW_SECONDS}s 内上限 {limit} 次")
    q.append(now)


@app.post("/dmz/api/v1/dispatch")
async def dispatch(task: dict = Body(...)) -> JSONResponse:
    rid = task.get("request_id", "?")

    # ⓪ 入站长度上限：在解析前先量体积，超长载荷不进入任何业务判断
    raw_len = len(json.dumps(task, ensure_ascii=False))
    if raw_len > MAX_REQUEST_CHARS:
        _deny("REQUEST_TOO_LARGE", rid, {"len": raw_len, "max": MAX_REQUEST_CHARS}, 413)

    # ① 字段白名单：不认识的键一律拒收
    extra = set(task.keys()) - EGRESS_FIELD_WHITELIST
    if extra:
        _deny("FIELD_NOT_WHITELISTED", rid, {"extra": sorted(extra)}, 400)

    # ② 签名校验
    if not verify(task, SECRET_INNER_DMZ):
        _deny("SIGNATURE_INVALID", rid, None, 401)

    # ③ 有效期
    try:
        expires = datetime.fromisoformat(task["expires_at"])
    except Exception:
        _deny("TTL_MISSING", rid, None, 400)
    if expires < datetime.now(timezone.utc).astimezone():
        _deny("TTL_EXPIRED", rid, {"expires_at": task["expires_at"]}, 410)

    # ④ 重放检测
    now = time.time()
    for k, ts in list(_SEEN.items()):
        if now - ts > 600:
            _SEEN.pop(k, None)
    if rid in _SEEN:
        _deny("REPLAY_DETECTED", rid, None, 409)
    _SEEN[rid] = now

    # ⑤ 内容复检（形态级）
    blob = str(task.get("sanitized_context", ""))
    hits = [label for label, pat in _DLP if pat.search(re.sub(r"\b[A-Z]+_\d{3,}\b", " ", blob))]
    if hits:
        _deny("CONTENT_INSPECTION_FAILED", rid, {"patterns": hits}, 451)

    audit.log("dmz", "EGRESS_ACCEPTED", request_id=rid,
              detail={"intent": task.get("intent_hint"),
                      "rules": [r.get("rule_id") for r in task.get("approved_rule_context", [])],
                      "context_len": len(blob)})

    # ⑥ 逐跳换签：DMZ→外网使用独立密钥
    forward = {k: v for k, v in task.items() if k != "signature"}
    forward["signature"] = sign(forward, SECRET_DMZ_OUTER)

    url = f"{OUTER_URL}/outer/api/v1/tasks"
    guard("dmz", url)
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.post(url, json=forward,
                                  headers={"x-trace-id": str(task.get("trace_id") or rid)})
    except Exception as exc:
        audit.log("dmz", "DOWNSTREAM_UNAVAILABLE", request_id=rid, severity="high",
                  detail={"error": str(exc)})
        runlog.error("downstream_unavailable", extra={"extra_data": {
            "request_id": rid, "error": f"{type(exc).__name__}: {str(exc)[:200]}"}})
        raise HTTPException(502, "外网任务服务不可达，按 fail-closed 返回")

    if r.status_code != 200:
        _deny(f"DOWNSTREAM_{r.status_code}", rid, {"body": r.text[:300]}, 502)

    body = r.json()

    # ⑦ 回程校验：来源签名 + request_id + 结构
    if not verify(body, SECRET_DMZ_OUTER):
        _deny("RESPONSE_SIGNATURE_INVALID", rid, None, 502)
    if body.get("request_id") != rid:
        _deny("RESPONSE_ID_MISMATCH", rid, {"got": body.get("request_id")}, 502)

    # ⑦a 回程恶意内容扫描：外网返回必须以"纯数据"身份进内网，不得携带指令/脚本/注入
    text_back = json.dumps({k: v for k, v in body.items() if k != "signature"}, ensure_ascii=False)
    mal = [label for label, pat in _MALICIOUS if pat.search(text_back)]
    if mal:
        _deny("RESPONSE_MALICIOUS_CONTENT", rid, {"patterns": mal}, 502)
    # ⑦b 回程 PII 形态复检：DMZ 侧独立再查一遍（与内网 scan_text 的失效模式不同）
    resid = [label for label, pat in _FB_DLP if pat.search(_TOKEN_RE.sub(" ", text_back))]
    if resid:
        _deny("RESPONSE_PII_RESIDUE", rid, {"patterns": resid}, 502)

    # ⑧ 换回内网密钥签名
    back = {k: v for k, v in body.items() if k != "signature"}
    back["signature"] = sign(back, SECRET_INNER_DMZ)

    audit.log("dmz", "RESPONSE_RELAYED", request_id=rid,
              detail={"model": f"{body.get('model_supplier')}/{body.get('model_version')}"})
    return JSONResponse(back)


def _deny(code: str, rid: str, detail: dict | None, status: int) -> None:
    audit.log("dmz", "EGRESS_DENIED", request_id=rid, severity="critical",
              detail={"code": code, **(detail or {})})
    runlog.warning("egress_denied", extra={"extra_data": {
        "request_id": rid, "code": code, "status": status}})
    raise HTTPException(status, code)


@app.post("/dmz/api/v1/mcp/call")
async def mcp_call(call: McpCall, request: Request) -> JSONResponse:
    # 网关的第一步不是看工具名，而是看调用方凭什么身份到达这里。
    # 无凭证的调用连"工具是否存在"都不该知道。
    _require_service(request)

    # 限流：先于工具存在性判断——否则攻击者可以靠"猜工具名"免费刷满网关日志
    _rate_limit(f"mcp:{call.actor}:{call.tool}", RATE_LIMIT_MAX_CALLS,
                call.actor, "actor+tool", {"tool": call.tool})
    _rate_limit(f"mcp-actor:{call.actor}", RATE_LIMIT_MAX_PER_ACTOR,
                call.actor, "actor", {"tool": call.tool})

    # 入站参数体积上限：MCP 参数同样可能被用来塞超长载荷
    args_len = len(json.dumps({"args": call.args}, ensure_ascii=False))
    if args_len > MAX_REQUEST_CHARS:
        audit.log("dmz", "MCP_DENIED", actor=call.actor, severity="high",
                  detail={"tool": call.tool, "reason": "args_too_large", "len": args_len})
        raise HTTPException(413, f"参数超长：{args_len} > {MAX_REQUEST_CHARS}")

    if call.tool in MCP_DENIED_HINTS:
        audit.log("dmz", "MCP_DENIED", actor=call.actor, severity="critical",
                  detail={"tool": call.tool, "reason": "denied_registry"})
        raise HTTPException(403, f"策略拒绝：{call.tool} 不在受控工具目录内")
    if call.tool not in MCP_TOOL_ALLOWLIST:
        audit.log("dmz", "MCP_DENIED", actor=call.actor, severity="high",
                  detail={"tool": call.tool, "reason": "not_in_allowlist"})
        raise HTTPException(403, f"策略拒绝：{call.tool} 未登记")

    url = f"{INNER_URL}/internal/api/v1/mcp/{call.tool}"
    guard("dmz", url)
    audit.log("dmz", "MCP_FORWARDED", actor=call.actor,
              detail={"tool": call.tool, "role": call.role, "args_keys": sorted(call.args)})

    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.post(
                url,
                json={"actor": call.actor, "role": call.role, "args": call.args},
                headers={"x-service-token": SERVICE_TOKEN},
            )
    except Exception as exc:
        raise HTTPException(502, f"内网工具服务不可达: {exc}")

    if r.status_code != 200:
        raise HTTPException(r.status_code, r.text)
    return JSONResponse(r.json())


def _require_service(request: Request) -> None:
    """服务间凭证校验。DMZ 不认用户会话——用户身份在内网终止，不跨界。"""
    tok = request.headers.get("x-service-token", "")
    if not tok or not hmac.compare_digest(tok, SERVICE_TOKEN):
        audit.log("dmz", "MCP_DENIED", severity="critical",
                  detail={"reason": "service_auth", "path": request.url.path})
        raise HTTPException(401, "服务凭证无效")


@app.get("/dmz/api/v1/mcp/catalog")
def catalog() -> dict:
    return {"tools": sorted(MCP_TOOL_ALLOWLIST), "denied": sorted(MCP_DENIED_HINTS)}


# ---------------- 第二期：客户反馈通道（M2） ----------------
#
# 职责与 /dispatch 一脉相承，方向相反：
#   /feedback/inbox  —— 客户原文入站：形态级脱敏后投递内网。原文只在请求内存中
#                       存在于本函数执行期间，不落任何库、不进任何日志。
#   /feedback/deliver —— 答复出站裁决：内网 AI/人工答复下发客户前，过 DLP 形态
#                       复检 + 业务口径红线；命中一律 deny 返回内网（fail-closed
#                       转人工），绝不放行。
#   /feedback/status —— 状态单向同步：内网是唯一事实源，网关缓存只做展示。

# 答复业务口径红线：命中即否决（模板化约束之外的第二道闸）
_FB_REPLY_DENY = [
    ("FB_PROMISE_RETURN", re.compile(r"保本|稳赚|保证收益|无风险|稳赢")),
    ("FB_PROMISE_REFUND", re.compile(r"全额退款|保证退款|退款保证|免息|返现")),
    ("FB_ABSOLUTE_CLAIM", re.compile(r"百分之百|绝对没问题|肯定没问题|一定成功")),
]

# 反馈通道专用 DLP（数字环视版）。注意：不能直接复用 _DLP——它的 \b 依赖 ASCII 词
# 边界，而 Python 正则里汉字也是 \w，"卡号6222..."紧贴中文时 \b 匹配不到，
# 会漏检（冒烟实测踩中）。(?<!\d)(?!\d) 只看数字边界，中文语境下可靠。
_FB_DLP = [
    ("CARD_LIKE", re.compile(r"(?<!\d)\d{16,19}(?!\d)")),
    ("PHONE_LIKE", re.compile(r"(?<!\d)1[3-9]\d{9}(?!\d)")),
    ("ID_LIKE", re.compile(r"(?<!\d)\d{17}[\dXx](?!\d)")),
]


def _fb_mask(text: str) -> str:
    """形态级脱敏：证件号(18位)先于银行卡号(16-19位)处理，手机号最后。"""
    text = re.sub(r"(?<!\d)\d{17}[\dXx](?!\d)",
                  lambda m: m.group(0)[:4] + "**********" + m.group(0)[-2:], text)
    text = re.sub(r"(?<!\d)\d{16,19}(?!\d)", lambda m: "****" + m.group(0)[-4:], text)
    text = re.sub(r"(?<!\d)1[3-9]\d{9}(?!\d)",
                  lambda m: m.group(0)[:3] + "****" + m.group(0)[-4:], text)
    return text


@app.post("/dmz/api/v1/feedback/inbox")
async def fb_inbox(req: FeedbackIngestRequest, request: Request) -> JSONResponse:
    _require_service(request)
    audit.log("dmz", "FB_INBOUND", request_id=req.fb_id,
              detail={"kind": req.kind, "category": req.category,
                      "len": len(req.body_masked)})
    masked = _fb_mask(req.body_masked)
    url = f"{INNER_URL}/internal/api/v1/feedback/ingest"
    guard("dmz", url)
    payload = req.model_dump()
    payload["body_masked"] = masked
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.post(url, json=payload,
                                  headers={"x-service-token": SERVICE_TOKEN})
    except Exception as exc:
        audit.log("dmz", "FB_INNER_UNREACHABLE", request_id=req.fb_id, severity="high",
                  detail={"error": str(exc)[:200]})
        raise HTTPException(502, "内网反馈服务不可达，fail-closed")
    if r.status_code != 200:
        try:
            detail = r.json().get("detail", r.text[:200])
        except Exception:
            detail = r.text[:200]
        audit.log("dmz", "FB_INNER_REJECTED", request_id=req.fb_id, severity="high",
                  detail={"status": r.status_code})
        raise HTTPException(r.status_code, detail)
    # 脱敏后回执随响应返回：供网关缓存客户消息（客户可见自己发的内容），
    # 网关始终只拿到脱敏文本，原文依旧不出 DMZ 执行期内存。
    out = r.json()
    out["body_masked"] = masked
    out["created_at"] = req.created_at
    return JSONResponse(out)


@app.post("/dmz/api/v1/feedback/deliver")
async def fb_deliver(req: FeedbackDeliverRequest, request: Request) -> dict:
    _require_service(request)
    blob = req.body
    # ① DLP 形态复检：答复里不得出现卡号/手机号/证件号形态（数字环视版，见 _FB_DLP 注释）
    hits = [label for label, pat in _FB_DLP if pat.search(blob)]
    if hits:
        audit.log("dmz", "FB_OUTBOUND_DENIED", request_id=req.fb_id, severity="critical",
                  detail={"rule_id": "FB_CONTENT_DLP", "patterns": hits})
        return {"verdict": "deny", "rule_id": "FB_CONTENT_DLP"}
    # ② 业务口径红线
    for rule_id, pat in _FB_REPLY_DENY:
        if pat.search(blob):
            audit.log("dmz", "FB_OUTBOUND_DENIED", request_id=req.fb_id,
                      severity="critical", detail={"rule_id": rule_id})
            return {"verdict": "deny", "rule_id": rule_id}
    # ③ 通过 → 投递网关缓存（客户只从网关读取，永远摸不到内网）
    url = f"{OUTER_URL}/feedback/api/v1/_deliver"
    guard("dmz", url)
    try:
        async with httpx.AsyncClient(timeout=8) as client:
            r = await client.post(url, json=req.model_dump(),
                                  headers={"x-service-token": SERVICE_TOKEN})
        if r.status_code != 200:
            audit.log("dmz", "FB_GATEWAY_REJECT", request_id=req.fb_id, severity="high",
                      detail={"status": r.status_code})
            return {"verdict": "deny", "rule_id": f"GATEWAY_{r.status_code}"}
    except Exception as exc:
        audit.log("dmz", "FB_GATEWAY_UNREACHABLE", request_id=req.fb_id, severity="high",
                  detail={"error": str(exc)[:200]})
        return {"verdict": "deny", "rule_id": "GATEWAY_UNAVAILABLE"}
    audit.log("dmz", "FB_OUTBOUND_DELIVERED", request_id=req.fb_id,
              detail={"sender": req.sender, "status_after": req.status_after})
    return {"verdict": "pass"}


@app.post("/dmz/api/v1/feedback/status")
async def fb_status(payload: dict = Body(...), request: Request = None) -> dict:
    _require_service(request)
    fb_id = str(payload.get("fb_id", ""))[:40]
    status = str(payload.get("status", ""))[:32]
    if not fb_id or not status:
        raise HTTPException(400, "缺 fb_id/status")
    url = f"{OUTER_URL}/feedback/api/v1/_status"
    guard("dmz", url)
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            r = await client.post(url, json={"fb_id": fb_id, "status": status},
                                  headers={"x-service-token": SERVICE_TOKEN})
        if r.status_code != 200:
            raise HTTPException(r.status_code, "网关拒绝")
    except Exception as exc:
        audit.log("dmz", "FB_STATUS_SYNC_FAILED", request_id=fb_id, severity="high",
                  detail={"status": status, "error": str(exc)[:150]})
        return {"ok": False, "note": "内网状态仍是唯一事实源，缓存失败不阻断"}
    audit.log("dmz", "FB_STATUS_RELAYED", request_id=fb_id, detail={"status": status})
    return {"ok": True}
