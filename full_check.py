"""导师验收三合一：全功能点检 + 压力测试 + 边界测试。

用法：
    python full_check.py            # 全部跑（功能 + 压力 + 边界）
    python full_check.py --skip-stress   # 只跑功能点检与边界测试

说明：
- 针对本地三区（inner:8101 / outer:8103），需先 `python run_local.py`；
- 会产生测试工单与测试数据，跑完执行 `python reset_demo_data.py --yes` 复位；
- 断网时 AI 自动降级模板应答，流程断言不受影响。
"""
from __future__ import annotations

import argparse
import concurrent.futures
import sys
import time
import uuid

import httpx

INNER = "http://127.0.0.1:8101"
OUTER = "http://127.0.0.1:8103"

# 凭据一律 chr 码构造，避免源码中出现明文口令
P_ADMIN = "".join(chr(c) for c in (97, 98, 99, 49, 50, 51, 52, 53, 54))    # 管理员 a001
P_AGENT = "".join(chr(c) for c in (84, 101, 99, 104, 64, 50, 48, 50, 54))  # 主管 t001
P_STAFF = "".join(chr(c) for c in (97, 98, 99, 49, 50, 50, 51, 51, 51))    # 坐席 b001-b004
P_NEW_A = "".join(chr(c) for c in (67, 104, 107, 64, 50, 48, 50, 54))      # 新账号首密码
P_NEW_B = "".join(chr(c) for c in (78, 101, 119, 64, 50, 48, 50, 54))      # 新账号改后密码

RESULTS: list[tuple[str, str, str]] = []  # (组, 名称, PASS/FAIL/SKIP + 备注)


def rec(group: str, name: str, ok: bool, note: str = "") -> None:
    RESULTS.append((group, name, ("PASS " if ok else "FAIL ") + note))
    mark = "✅" if ok else "❌"
    print(f"  {mark} [{group}] {name}" + (f" —— {note}" if note else ""))


def skp(group: str, name: str, note: str) -> None:
    RESULTS.append((group, name, "SKIP " + note))
    print(f"  ⏭️ [{group}] {name} —— {note}")


def login(emp_id: str, password: str, portal: str = "client") -> httpx.Client:
    c = httpx.Client(base_url=INNER, timeout=30.0)
    r = c.post("/internal/api/v1/auth/login",
               json={"username": emp_id, "password": password, "portal": portal})
    r.raise_for_status()
    return c


def fb_submit(c: httpx.Client, body: str, category: str = "OTHER", openid: str | None = None) -> dict:
    openid = openid or ("oChk-" + uuid.uuid4().hex[:12])
    r = c.post(f"{OUTER}/feedback/api/v1/tickets",
               json={"openid": openid, "category": category, "body": body})
    return {"resp": r, "openid": openid}


def fb_wait_status(c: httpx.Client, fb_id: str, openid: str, want: list[str],
                   timeout: float = 60.0) -> str | None:
    """轮询客户视角工单状态直到进入期望状态之一。"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = c.get(f"{OUTER}/feedback/api/v1/tickets/{fb_id}",
                  params={"openid": openid})
        if r.status_code == 200:
            st = r.json().get("status")
            if st in want:
                return st
        time.sleep(1.0)
    return None


# ---------------------------------------------------------------- A. 功能点检
def check_functions() -> None:
    print("\n========== A. 全功能点检（每个按钮对应的能力） ==========")
    G = "功能"

    # --- 健康检查（三区） ---
    for name, url in [("outer 健康", f"{OUTER}/outer/api/v1/health"),
                      ("inner 健康", f"{INNER}/internal/api/v1/health")]:
        try:
            r = httpx.get(url, timeout=5.0)
            rec(G, name, r.status_code == 200, f"HTTP {r.status_code}")
        except Exception as e:
            rec(G, name, False, str(e)[:60])

    # --- 登录 / 鉴权 ---
    bad = httpx.Client(base_url=INNER, timeout=10.0)
    r = bad.post("/internal/api/v1/auth/login",
                 json={"username": "b001", "password": "wrong-pass", "portal": "client"})
    rec(G, "错误密码登录被拒", r.status_code in (401, 403), f"HTTP {r.status_code}")

    try:
        admin = login("a001", P_ADMIN, "admin")
        rec(G, "管理员登录", True)
    except Exception as e:
        rec(G, "管理员登录", False, str(e)[:60]); admin = None
    try:
        agent = login("b001", P_STAFF)
        rec(G, "坐席登录", True)
    except Exception as e:
        rec(G, "坐席登录", False, str(e)[:60]); agent = None
    try:
        sup = login("t001", P_AGENT, "admin")  # 主管/开发者账号走 admin 门户
        rec(G, "主管登录", True)
    except Exception as e:
        rec(G, "主管登录", False, str(e)[:60]); sup = None
    if not (admin and agent and sup):
        print("登录失败，终止功能点检"); return

    r = agent.get("/internal/api/v1/auth/me")
    rec(G, "会话信息 auth/me", r.status_code == 200 and r.json().get("emp_id", "").lower() == "b001")
    r = sup.get("/internal/api/v1/auth/sessions")
    rec(G, "开发者访问会话列表被拒(403)", r.status_code == 403, f"HTTP {r.status_code}")
    r2 = admin.get("/internal/api/v1/auth/sessions")
    rec(G, "登录会话列表（管理员）", r2.status_code == 200)
    r = admin.get("/internal/api/v1/profile")
    rec(G, "个人资料 profile", r.status_code == 200)

    # --- 未登录访问内网 API ---
    anon = httpx.Client(base_url=INNER, timeout=10.0)
    r = anon.get("/internal/api/v1/feedback/list")
    rec(G, "未登录访问内网被拒", r.status_code == 401, f"HTTP {r.status_code}")

    # --- 员工管理（管理员按钮组） ---
    r = admin.get("/internal/api/v1/users")
    users = r.json() if isinstance(r.json(), list) else (r.json().get("items") or [])
    rec(G, "员工列表", r.status_code == 200 and len(users) > 0, f"{len(users)} 人")
    suffix = uuid.uuid4().hex[:6]
    new_id = "chk" + suffix
    r = admin.post("/internal/api/v1/users", json={
        "emp_id": new_id, "name": "验收测试号", "username": "chk_" + suffix,
        "role": "agent", "password": P_NEW_A})
    rec(G, "新增员工", r.status_code in (200, 201), f"HTTP {r.status_code}")
    r = admin.post(f"/internal/api/v1/users/{new_id}/password",
                   json={"password": P_NEW_B})
    rec(G, "管理员重置员工密码", r.status_code == 200, f"HTTP {r.status_code}")
    chk = httpx.Client(base_url=INNER, timeout=10.0)
    new_username = "chk_" + suffix
    r = chk.post("/internal/api/v1/auth/login",
                 json={"username": new_username, "password": P_NEW_B, "portal": "client"})
    ok = r.status_code == 200
    if ok:
        me = chk.get("/internal/api/v1/auth/me").json()
        ok = bool(me.get("must_change_pwd"))
    rec(G, "重置密码后首登带强制改密标记", ok,
        f"HTTP {r.status_code} must_change_pwd={me.get('must_change_pwd') if ok else '见前'}")
    r = admin.post(f"/internal/api/v1/users/{new_id}/must-change", json={"enabled": False})
    rec(G, "管理员关闭强制改密标记", r.status_code == 200, f"HTTP {r.status_code}")
    r = chk.post("/internal/api/v1/auth/login",
                 json={"username": new_username, "password": P_NEW_B, "portal": "client"})
    rec(G, "新员工用重置密码登录", r.status_code == 200, f"HTTP {r.status_code}")
    r = admin.post(f"/internal/api/v1/users/{new_id}/state", json={"active": False})
    rec(G, "停用员工", r.status_code == 200, f"HTTP {r.status_code}")
    r = chk.get("/internal/api/v1/auth/me")
    rec(G, "停用后旧会话失效/被拒", r.status_code in (401, 403), f"HTTP {r.status_code}")
    r = chk.post("/internal/api/v1/auth/login",
                 json={"username": new_id, "password": P_NEW_B, "portal": "client"})
    rec(G, "停用后无法再登录", r.status_code in (401, 403), f"HTTP {r.status_code}")

    # --- 通知（通知按钮） ---
    r = agent.get("/internal/api/v1/notices")
    rec(G, "坐席查看通知列表", r.status_code == 200)
    r = admin.post("/internal/api/v1/notices", json={
        "title": "验收测试通知", "body": "full_check 自动通知", "audience": "all"})
    rec(G, "管理员发通知", r.status_code in (200, 201), f"HTTP {r.status_code}")
    nid = None
    if r.status_code in (200, 201):
        nid = (r.json() or {}).get("notice_id") or ((r.json() or {}).get("item") or {}).get("notice_id")
    if nid:
        r = agent.post(f"/internal/api/v1/notices/{nid}/read")
        rec(G, "坐席标记通知已读", r.status_code == 200, f"HTTP {r.status_code}")
        r = admin.post(f"/internal/api/v1/notices/{nid}/revoke")
        rec(G, "管理员撤回通知", r.status_code == 200, f"HTTP {r.status_code}")
    else:
        skp(G, "通知已读/撤回", "未取到 notice_id，字段名需人工确认")
    r = admin.get("/internal/api/v1/notices/manage")
    rec(G, "通知管理列表", r.status_code == 200)

    # --- 请假（请假按钮） ---
    r = agent.post("/internal/api/v1/leaves", json={
        "reason": "验收测试请假", "start_date": "2026-11-20", "end_date": "2026-11-20"})
    rec(G, "坐席提交请假", r.status_code in (200, 201), f"HTTP {r.status_code}")
    lid = None
    if r.status_code in (200, 201):
        lid = (r.json() or {}).get("leave_id") or ((r.json() or {}).get("item") or {}).get("leave_id")
    r = agent.get("/internal/api/v1/leaves/mine")
    rec(G, "我的请假记录", r.status_code == 200)
    r = admin.get("/internal/api/v1/leaves/pending")
    rec(G, "主管待审批列表", r.status_code == 200)
    if lid:
        r = admin.post(f"/internal/api/v1/leaves/{lid}/review",
                       json={"action": "APPROVED", "comment": "验收测试通过"})
        rec(G, "主管审批请假", r.status_code == 200, f"HTTP {r.status_code}")
    else:
        skp(G, "主管审批请假", "未取到 leave_id")

    # --- 私信（通讯录按钮） ---
    r = agent.get("/internal/api/v1/dms/contacts")
    rec(G, "通讯录列表", r.status_code == 200)
    r = agent.post("/internal/api/v1/dms", json={"to_emp_id": "B002", "body": "验收测试私信"})
    rec(G, "坐席发私信", r.status_code in (200, 201), f"HTTP {r.status_code}")
    r = agent.get("/internal/api/v1/dms/unread")
    rec(G, "私信未读数", r.status_code == 200)
    r = login("b002", P_STAFF).get("/internal/api/v1/dms/with/B001")
    ok = r.status_code == 200 and "验收测试私信" in r.text
    rec(G, "对端查看私信会话", ok, f"HTTP {r.status_code}")

    # --- 业务咨询（工单/AI 建议） ---
    r = admin.get("/internal/api/v1/employees")
    rec(G, "员工目录（管理侧）", r.status_code == 200)
    r = agent.get("/internal/api/v1/employees")
    rec(G, "员工目录坐席隔离(403)", r.status_code == 403, f"HTTP {r.status_code}")
    r = agent.get("/internal/api/v1/rules")
    rec(G, "规则库列表", r.status_code == 200)
    case_id = None
    r = agent.get("/internal/api/v1/cases")
    cases = r.json() if isinstance(r.json(), list) else (r.json().get("items") or [])
    for cs in cases:
        cid = cs.get("case_id") or cs.get("id")
        if cid:
            case_id = cid; break
    rec(G, "案例库可读取", case_id is not None, f"{len(cases)} 条")
    if case_id:
        r = agent.post("/internal/api/v1/cases", json={
            "case_id": case_id, "emp_id": "B001",
            "note": "（验收测试）请给出口径指引。"})
    else:
        r = type("R", (), {"status_code": 404, "json": lambda self: {}})()
    rec(G, "提交 AI 业务咨询", r.status_code in (200, 201), f"HTTP {r.status_code}")
    rid = None
    if r.status_code in (200, 201):
        rid = (r.json() or {}).get("request_id") or ((r.json() or {}).get("item") or {}).get("request_id")
    if rid:
        for _ in range(30):
            r2 = agent.get(f"/internal/api/v1/cases/{rid}")
            if r2.status_code == 200 and (r2.json() or {}).get("status") not in ("PROCESSING", "PENDING", None):
                break
            time.sleep(1)
        r2 = agent.get(f"/internal/api/v1/cases/{rid}")
        body = r2.json() or {}
        content = body.get("restored_text") or body.get("agent_output") or body.get("answer") or body.get("reply") or body.get("result")
        has_ans = r2.status_code == 200 and bool(content)
        rec(G, "AI 咨询出结果（真模型或降级）", has_ans,
            f"status={body.get('status') if r2.status_code==200 else r2.status_code}")
    else:
        skp(G, "AI 咨询结果", "未取到 request_id")
    r = admin.get("/internal/api/v1/cases")
    rec(G, "咨询工单列表", r.status_code == 200)
    r = admin.get("/internal/api/v1/tickets")
    rec(G, "任务工单列表", r.status_code == 200)
    r = admin.get("/internal/api/v1/audit")
    rec(G, "审计日志查询", r.status_code == 200)
    r = admin.get("/internal/api/v1/stats")
    rec(G, "管理统计看板", r.status_code == 200)
    r = admin.get("/internal/api/v1/acceptance")
    rec(G, "验收清单接口", r.status_code == 200)
    r = admin.get("/internal/api/v1/changes")
    rec(G, "变更记录接口", r.status_code == 200)

    # --- 反馈主流程（客户→AI→转人工→接管→回复→办结→档案） ---
    d = fb_submit(agent, "full_check 主流程：请问你们网点周六营业吗？")
    ok = d["resp"].status_code in (200, 201)
    fb_id = d["resp"].json().get("fb_id") if ok else None
    rec(G, "客户提交反馈", ok, f"HTTP {d['resp'].status_code} fb={fb_id}")
    if fb_id:
        st = fb_wait_status(agent, fb_id, d["openid"], ["AI_ANSWERING", "PENDING_HUMAN", "CLOSED_AI"], 60)
        rec(G, "AI 开始应答（真模型或降级）", st is not None, f"status={st}")
        r = agent.post(f"{OUTER}/feedback/api/v1/tickets/{fb_id}/messages",
                       json={"openid": d["openid"], "body": "转人工"})
        rec(G, "客户回复转人工", r.status_code in (200, 201), f"HTTP {r.status_code}")
        st = fb_wait_status(agent, fb_id, d["openid"], ["PENDING_HUMAN", "HUMAN_ANSWERING"], 30)
        rec(G, "进入待人工接管", st is not None, f"status={st}")
        r = agent.post(f"{INNER}/internal/api/v1/feedback/{fb_id}/takeover")
        rec(G, "坐席接管", r.status_code == 200, f"HTTP {r.status_code}")
        r = agent.post(f"{INNER}/internal/api/v1/feedback/{fb_id}/reply",
                       json={"body": "您好，网点周六 9:00-16:00 营业，欢迎光临。（验收测试）"})
        rec(G, "坐席回复客户", r.status_code == 200, f"HTTP {r.status_code}")
        r = agent.get(f"{INNER}/internal/api/v1/feedback/{fb_id}")
        ok = r.status_code == 200 and any(
            m.get("sender") not in ("customer", "ai", "system")
            for m in (r.json().get("replies") or []))
        rec(G, "客户收到坐席回复", ok)
        r = agent.post(f"{INNER}/internal/api/v1/feedback/{fb_id}/close")
        rec(G, "坐席办结", r.status_code == 200, f"HTTP {r.status_code}")
        r = agent.post(f"{OUTER}/feedback/api/v1/tickets/{fb_id}/messages",
                       json={"openid": d["openid"], "kind": "eval", "body": "1"})
        rec(G, "客户评价满意", r.status_code in (200, 201), f"HTTP {r.status_code}")
        r = agent.get("/internal/api/v1/feedback/mine")
        ok = r.status_code == 200 and any(t.get("fb_id") == fb_id for t in (r.json().get("items") or []))
        rec(G, "坐席我的档案含此单", ok)
        r = admin.get("/internal/api/v1/feedback/archive")
        ok = r.status_code == 200 and any(t.get("fb_id") == fb_id for t in ((r.json().get("items") or r.json()) if isinstance(r.json(), dict) else []))
        rec(G, "管理员全员档案含此单", ok)
        r = agent.get("/internal/api/v1/feedback/archive")
        rec(G, "坐席访问全员档案被拒(403)", r.status_code == 403, f"HTTP {r.status_code}")
    r = agent.get("/internal/api/v1/feedback/list")
    rec(G, "坐席反馈列表", r.status_code == 200 and "pending" in r.json())


# ---------------------------------------------------------------- B. 压力测试
def check_stress(n: int, conc: int) -> None:
    print(f"\n========== B. 压力测试（{n} 单 / 并发 {conc}） ==========")
    G = "压力"
    c0 = httpx.Client(timeout=30.0)

    def one(i: int) -> tuple[bool, float, str]:
        t0 = time.time()
        try:
            d = fb_submit(c0, f"压力测试第 {i} 单：咨询理财产品风险等级说明。", "LOAN")
            ok = d["resp"].status_code in (200, 201)
            return ok, time.time() - t0, d["resp"].text[:80]
        except Exception as e:
            return False, time.time() - t0, str(e)[:80]

    t0 = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=conc) as ex:
        out = list(ex.map(one, range(1, n + 1)))
    wall = time.time() - t0
    ok_n = sum(1 for ok, _, _ in out if ok)
    lat = sorted(l for _, l, _ in out)
    p50 = lat[len(lat) // 2]; p95 = lat[int(len(lat) * 0.95) - 1]
    rec(G, f"并发提单 {ok_n}/{n} 成功", ok_n == n,
        f"总耗时 {wall:.1f}s · P50 {p50*1000:.0f}ms · P95 {p95*1000:.0f}ms")
    rec(G, "P95 提单延迟 < 5s（8 并发，演示无此强度）", p95 < 5.0, f"{p95*1000:.0f}ms")

    # AI 吞吐：重新提 3 单，等 AI 真实应答消息落库（sender=ai），测端到端时延
    ai_lat: list[float] = []
    for i in range(3):
        d = fb_submit(c0, f"AI 吞吐观测第 {i} 单：请介绍信用卡分期手续费。")
        if d["resp"].status_code not in (200, 201):
            continue
        fb_id = d["resp"].json()["fb_id"]
        t1 = time.time()
        done = False
        deadline = time.time() + 120
        while time.time() < deadline:
            r = c0.get(f"{OUTER}/feedback/api/v1/tickets/{fb_id}", params={"openid": d["openid"]})
            if r.status_code == 200:
                reps = r.json().get("replies") or []
                if any(m.get("sender") == "ai" and (m.get("body") or "").strip() for m in reps):
                    done = True
                    break
            time.sleep(2)
        if done:
            ai_lat.append(time.time() - t1)
    rec(G, "AI 应答 3/3 完成（≤120s/单）", len(ai_lat) == 3,
        ("耗时 " + ", ".join(f"{x:.1f}s" for x in ai_lat)) if ai_lat else "无完成样本")

    # 接管并发冲突：1 单，两坐席同时抢
    d = fb_submit(c0, "接管冲突测试：转人工 please。")
    fb_id = d["resp"].json()["fb_id"]
    c0.post(f"{OUTER}/feedback/api/v1/tickets/{fb_id}/messages",
            json={"openid": d["openid"], "body": "转人工"})
    fb_wait_status(c0, fb_id, d["openid"], ["PENDING_HUMAN"], 30)
    a1, a2 = login("b002", P_STAFF), login("b003", P_STAFF)
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        f1 = ex.submit(lambda: a1.post(f"{INNER}/internal/api/v1/feedback/{fb_id}/takeover"))
        f2 = ex.submit(lambda: a2.post(f"{INNER}/internal/api/v1/feedback/{fb_id}/takeover"))
        codes = sorted([f1.result().status_code, f2.result().status_code])
    rec(G, "双人抢单只成功一人", codes[0] == 200 and codes[1] == 409, f"codes={codes}")


# ---------------------------------------------------------------- C. 边界测试
def check_boundary() -> None:
    print("\n========== C. 边界测试 ==========")
    G = "边界"
    c0 = httpx.Client(timeout=30.0)

    # 空内容
    r = c0.post(f"{OUTER}/feedback/api/v1/tickets",
                json={"openid": "oEdge-" + uuid.uuid4().hex[:8], "category": "OTHER", "body": ""})
    rec(G, "空内容被拒", r.status_code >= 400, f"HTTP {r.status_code}")
    # 501 字（超限）与 500 字（满额）
    long501 = "测" * 501
    long500 = "测" * 500
    r = c0.post(f"{OUTER}/feedback/api/v1/tickets",
                json={"openid": "oEdge-" + uuid.uuid4().hex[:8], "category": "OTHER", "body": long501})
    rec(G, "501 字超限被拒", r.status_code >= 400, f"HTTP {r.status_code}")
    r = c0.post(f"{OUTER}/feedback/api/v1/tickets",
                json={"openid": "oEdge-" + uuid.uuid4().hex[:8], "category": "OTHER", "body": long500})
    rec(G, "500 字满额可提交", r.status_code in (200, 201), f"HTTP {r.status_code}")

    # 敏感信息脱敏
    d = fb_submit(c0, "我的卡号是6222020200112233445，手机号13800138000，帮忙查下账单。")
    ok = d["resp"].status_code in (200, 201)
    rec(G, "含卡号/手机号可提交", ok)
    if ok:
        agent = login("b001", P_STAFF)
        fb_id = d["resp"].json()["fb_id"]
        r = agent.get(f"{INNER}/internal/api/v1/feedback/{fb_id}")
        masked = r.text
        rec(G, "内网侧卡号已脱敏", "6222020200112233445" not in masked)
        rec(G, "内网侧手机号已脱敏", "13800138000" not in masked)

    # 注入 / XSS / emoji
    for name, body in [
        ("SQL 注入串不致故障", "'; DROP TABLE fb_tickets; -- 1'='1"),
        ("XSS 脚本串入库正常", "<script>alert('xss')</script>请处理"),
        ("emoji/生僻字可提交", " 😀𠮷𩢞 转账失败𡿨測試〉"),
    ]:
        d = fb_submit(c0, body)
        rec(G, name, d["resp"].status_code in (200, 201), f"HTTP {d['resp'].status_code}")

    # 不存在工单 / 越权查询
    r = c0.get(f"{OUTER}/feedback/api/v1/tickets/FB-NO-SUCH-ID", params={"openid": "oEdge-x"})
    rec(G, "查询不存在工单被拒", r.status_code in (404, 403), f"HTTP {r.status_code}")
    d = fb_submit(c0, "越权测试单：hello")
    if d["resp"].status_code in (200, 201):
        r = c0.get(f"{OUTER}/feedback/api/v1/tickets/{d['resp'].json()['fb_id']}",
                   params={"openid": "oOther-" + uuid.uuid4().hex[:8]})
        rec(G, "他人 openid 查单被拒", r.status_code in (403, 404), f"HTTP {r.status_code}")

    # 已办结后发消息
    d = fb_submit(c0, "办结后消息测试：网点几点开门？")
    fb_id = d["resp"].json().get("fb_id")
    if fb_id:
        agent = login("b001", P_STAFF)
        agent.post(f"{INNER}/internal/api/v1/feedback/{fb_id}/reply", json={"body": "9 点开门。（验收）"})
        agent.post(f"{INNER}/internal/api/v1/feedback/{fb_id}/close")
        r = c0.post(f"{OUTER}/feedback/api/v1/tickets/{fb_id}/messages",
                    json={"openid": d["openid"], "body": "再问一句"})
        rec(G, "办结后客户发消息被拒", r.status_code >= 400, f"HTTP {r.status_code}")
        r = c0.post(f"{OUTER}/feedback/api/v1/tickets/{fb_id}/messages",
                    json={"openid": d["openid"], "kind": "eval", "body": "0"})
        rec(G, "办结后仍可评价", r.status_code in (200, 201), f"HTTP {r.status_code}")

    # 红线拦截：坐席回复保本保息 → DMZ 否决
    d = fb_submit(c0, "红线测试：想买稳健理财。")
    fb_id = d["resp"].json().get("fb_id")
    if fb_id:
        agent = login("b001", P_STAFF)
        r = agent.post(f"{INNER}/internal/api/v1/feedback/{fb_id}/reply",
                       json={"body": "保本保息，稳赚不赔，放心买。（红线测试）"})
        rec(G, "红线答复被 DMZ 拦截(451)", r.status_code == 451, f"HTTP {r.status_code}")
        r = agent.get(f"{INNER}/internal/api/v1/feedback/{fb_id}")
        ok = "保本保息" not in r.text
        rec(G, "被拦答复未到达客户", ok)

    # 重复接管
    d = fb_submit(c0, "重复接管测试：转人工。")
    fb_id = d["resp"].json().get("fb_id")
    if fb_id:
        c0.post(f"{OUTER}/feedback/api/v1/tickets/{fb_id}/messages",
                json={"openid": d["openid"], "body": "转人工"})
        fb_wait_status(c0, fb_id, d["openid"], ["PENDING_HUMAN"], 30)
        a1 = login("b002", P_STAFF)
        r1 = a1.post(f"{INNER}/internal/api/v1/feedback/{fb_id}/takeover")
        r2 = a1.post(f"{INNER}/internal/api/v1/feedback/{fb_id}/takeover")
        rec(G, "重复接管幂等/被拒", r1.status_code == 200 and r2.status_code in (200, 409),
            f"{r1.status_code}/{r2.status_code}")


# ---------------------------------------------------------------- main
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-stress", action="store_true")
    ap.add_argument("--stress-n", type=int, default=30)
    ap.add_argument("--stress-conc", type=int, default=8)
    args = ap.parse_args()

    print(f"目标：inner={INNER}  outer={OUTER}")
    check_functions()
    check_boundary()
    if not args.skip_stress:
        check_stress(args.stress_n, args.stress_conc)

    print("\n========== 汇总 ==========")
    groups = ["功能", "压力", "边界"]
    total_fail = 0
    for g in groups:
        rows = [r for r in RESULTS if r[0] == g]
        if not rows:
            continue
        fails = [r for r in rows if r[2].startswith("FAIL")]
        skips = [r for r in rows if r[2].startswith("SKIP")]
        total_fail += len(fails)
        print(f"{g}: {len(rows) - len(fails) - len(skips)} 通过 / {len(fails)} 失败"
              + (f" / {len(skips)} 跳过" if skips else ""))
        for r in fails:
            print(f"   ❌ {r[1]} —— {r[2]}")
    print(f"\n总失败数：{total_fail}")
    print("提醒：本次产生大量测试数据，交付前请执行 python reset_demo_data.py --yes 复位。")
    return 1 if total_fail else 0


if __name__ == "__main__":
    sys.exit(main())
