"""站内私信专项测试 DM01–DM05：通讯录、点对点会话、已读回执与越权边界。

私信是纯内网功能：不出域、不经 DMZ、不触模型——验的是"OA 基本功"里
消息这一环：能找到人、能收发、未读数准确、已读可回执、不能凭空发给不存在的人。
"""
from __future__ import annotations

import httpx

INNER = "/internal/api/v1"


def do_login(urls, username: str, password: str, portal: str) -> httpx.Client:
    c = httpx.Client(base_url=urls["inner"], timeout=25)
    r = c.post(f"{INNER}/auth/login",
               json={"username": username, "password": password, "portal": portal})
    assert r.status_code == 200, f"登录失败 {r.status_code}: {r.text}"
    return c


def admin(urls) -> httpx.Client:
    return do_login(urls, "a001", "abc123456", "admin")


# ---------------- DM01：通讯录完整性 ----------------

def test_dm01_contacts_lists_all_others(urls):
    """通讯录应列出除本人外全部在职员工，且带角色与未读数字段"""
    sup = admin(urls)
    r = sup.get(f"{INNER}/dms/contacts")
    assert r.status_code == 200
    d = r.json()
    assert d["me"] == "A001"
    ids = {p["emp_id"] for p in d["items"]}
    assert "A001" not in ids, "通讯录不应包含自己"
    assert {"T001", "B001", "B002", "B003", "B004"} <= ids, "应包含全部其他种子员工"
    for p in d["items"]:
        assert {"emp_id", "name", "role", "unread"} <= set(p.keys())


# ---------------- DM02：发送与双向会话 ----------------

def test_dm02_send_and_thread_both_directions(urls):
    """b001 ↔ a001 互发后，双方会话都能按时间正序看到全部消息"""
    a = admin(urls)
    b = do_login(urls, "b001", "abc122333", "client")
    r = b.post(f"{INNER}/dms", json={"to_emp_id": "A001", "body": "苏总，年费工单有个争议想同步"})
    assert r.status_code == 200 and r.json()["msg_id"] > 0
    r = a.post(f"{INNER}/dms", json={"to_emp_id": "B001", "body": "收到，转给你处理口径"})
    assert r.status_code == 200
    # b001 视角：两条都在，正序
    r = b.get(f"{INNER}/dms/with/A001")
    assert r.status_code == 200
    d = r.json()
    assert d["peer"]["emp_id"] == "A001" and d["peer"]["name"] == "苏总"
    bodies = [m["body"] for m in d["items"]]
    assert "苏总，年费工单有个争议想同步" in bodies and "收到，转给你处理口径" in bodies
    # a001 视角一致
    r = a.get(f"{INNER}/dms/with/B001")
    assert len(r.json()["items"]) == len(d["items"])
    # 会话列表摘要：最近一条与未读数
    r = b.get(f"{INNER}/dms/contacts")
    a_row = next(p for p in r.json()["items"] if p["emp_id"] == "A001")
    assert a_row["last_body"] == "收到，转给你处理口径"


# ---------------- DM03：未读计数与已读回执 ----------------

def test_dm03_unread_and_read_receipt(urls):
    """对方来信计入未读；打开会话即清零且带已读时间；自己发的算已读不计未读"""
    a = admin(urls)
    b = do_login(urls, "b002", "abc122333", "client")
    r = a.post(f"{INNER}/dms", json={"to_emp_id": "B002", "body": "下午例会提前到三点"})
    assert r.status_code == 200
    before = b.get(f"{INNER}/dms/unread").json()["unread"]
    assert before >= 1
    thread = b.get(f"{INNER}/dms/with/A001").json()
    assert thread["unread_total"] == before - 1, "打开会话后该线程未读应清零"
    after = b.get(f"{INNER}/dms/unread").json()["unread"]
    assert after == before - 1
    # 已读回执落在消息上
    mine = [m for m in thread["items"] if m["body"] == "下午例会提前到三点"]
    assert mine and mine[-1]["read_at"], "对方发来的消息应有已读时间"


# ---------------- DM04：越权与边界 ----------------

def test_dm04_boundaries(urls):
    """未登录不可用；不能发给自己；收件人不存在返回 404；空正文被拒；超长被拒"""
    base = urls["inner"]
    with httpx.Client(base_url=base, timeout=25) as c:
        assert c.get(f"{INNER}/dms/contacts").status_code == 401, "未登录不得访问通讯录"
        assert c.post(f"{INNER}/dms", json={"to_emp_id": "A001", "body": "x"}).status_code == 401
    a = admin(urls)
    assert a.post(f"{INNER}/dms", json={"to_emp_id": "A001", "body": "自言自语"}).status_code == 400
    assert a.post(f"{INNER}/dms", json={"to_emp_id": "Z999", "body": "发给不存在的人"}).status_code == 404
    assert a.post(f"{INNER}/dms", json={"to_emp_id": "B001", "body": "   "}).status_code == 400
    assert a.post(f"{INNER}/dms", json={"to_emp_id": "B001", "body": "长" * 501}).status_code == 422
    assert a.get(f"{INNER}/dms/with/A001").status_code == 400, "不能与自己开会话"
    assert a.get(f"{INNER}/dms/with/GHOST").status_code == 404


# ---------------- DM05：审计留痕 ----------------

def test_dm05_audit_trail(urls):
    """DM_SENT 事件入审计：记收发双方与长度，不落正文"""
    a = admin(urls)
    r = a.post(f"{INNER}/dms", json={"to_emp_id": "B003", "body": "audit probe msg"})
    assert r.status_code == 200
    mid = r.json()["msg_id"]
    rows = a.get(f"{INNER}/audit", params={"limit": 500}).json()
    inner_rows = rows.get("inner") or []
    hit = next((x for x in inner_rows if x.get("event") == "DM_SENT" and str(mid) in str(x)), None)
    assert hit is not None, "DM_SENT 审计事件未找到"
    blob = str(hit)
    assert "audit probe" not in blob, "审计不应落私信正文"
    assert "B003" in blob and "length" in blob, "审计应记收件人与消息长度"
