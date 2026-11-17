"""OA 化专项测试 OA01–OA08：通知、请假、个人中心与账号安全流程。

与 T/A 系列的区别：T 系列验"数据出不出去"，A 系列验"人进不进得来"，
OA 系列验"进来之后像不像一个正式产品"——通知触达、审批流转、
口令生命周期这些 OA 基本功，是"专业落地"的验收面。
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


# ---------------- OA01：口令策略与自助改密 ----------------

def test_oa01_password_policy_and_self_change(urls):
    """弱口令拒绝、旧口令校验、改密成功后旧口令失效且当前会话保留"""
    sup = admin(urls)
    # 管理员把 b004 重置为已知口令（须过策略闸），随后关闭强制改密便于测试
    r = sup.post(f"{INNER}/users/B004/password", json={"password": "oa1test99"})
    assert r.status_code == 200 and r.json()["must_change_pwd"] is True
    sup.post(f"{INNER}/users/B004/must-change", json={"enabled": False})

    ag = do_login(urls, "b004", "oa1test99", "client")
    # 弱口令三连：纯数字 / 太短 / 与旧口令相同（422=契约层拒收，400=策略层拒绝）
    for pwd in ("12345678", "ab1", "oa1test99"):
        r = ag.post(f"{INNER}/auth/password",
                    json={"old_password": "oa1test99", "new_password": pwd})
        assert r.status_code in (400, 422), f"弱口令 {pwd} 未被拒绝"
    # 旧口令错误
    r = ag.post(f"{INNER}/auth/password", json={"old_password": "wrong-old", "new_password": "oa1new99x"})
    assert r.status_code == 401
    # 正确改密：成功且保留当前会话
    r = ag.post(f"{INNER}/auth/password", json={"old_password": "oa1test99", "new_password": "oa1new99x"})
    assert r.status_code == 200 and r.json()["must_change_pwd"] is False
    r = ag.get(f"{INNER}/auth/me")
    assert r.status_code == 200, "改密后当前会话不应被吊销"
    # 旧口令立即失效，新口令可登录
    with httpx.Client(base_url=urls["inner"], timeout=25) as c:
        assert c.post(f"{INNER}/auth/login", json={"username": "b004", "password": "oa1test99",
                                                   "portal": "client"}).status_code == 401
        assert c.post(f"{INNER}/auth/login", json={"username": "b004", "password": "oa1new99x",
                                                   "portal": "client"}).status_code == 200
    # 还原 b004 为种子口令，关闭强制改密，不影响其它测试
    sup.post(f"{INNER}/users/B004/password", json={"password": "abc122333"})
    sup.post(f"{INNER}/users/B004/must-change", json={"enabled": False})


# ---------------- OA02：首登强制改密 ----------------

def test_oa02_forced_first_password_change(urls):
    """管理员开户 → 首登必须改密 → 改密后标记清除；管理员重置同样触发"""
    sup = admin(urls)
    r = sup.post(f"{INNER}/users", json={
        "emp_id": "E9001", "name": "钱首登", "username": "e9001",
        "password": "initpass12", "role": "agent"})
    assert r.status_code == 200
    # 首登：返回强制改密标记
    r = httpx.post(f"{urls['inner']}{INNER}/auth/login",
                   json={"username": "e9001", "password": "initpass12", "portal": "client"}, timeout=25)
    assert r.status_code == 200
    assert r.json()["user"]["must_change_pwd"] is True
    # 未改密前可以直接调接口（改密由前端引导强制，服务端业务不阻断——策略声明在前端跳转）
    me_flag = httpx.get(f"{urls['inner']}{INNER}/auth/me", cookies=dict(r.cookies), timeout=25).json()
    assert me_flag["must_change_pwd"] is True
    # 自助改密后标记清除
    c = do_login(urls, "e9001", "initpass12", "client")
    r = c.post(f"{INNER}/auth/password", json={"old_password": "initpass12", "new_password": "selfpwd99a"})
    assert r.status_code == 200
    assert c.get(f"{INNER}/auth/me").json()["must_change_pwd"] is False


# ---------------- OA03：通知发布与已读回执 ----------------

def test_oa03_notice_publish_and_read_receipt(urls):
    """管理员发布 → 坐席未读角标 → 已读回执后归零"""
    sup, ag = admin(urls), do_login(urls, "b001", "abc122333", "client")
    before = ag.get(f"{INNER}/notices").json()["unread"]
    r = sup.post(f"{INNER}/notices", json={
        "title": "OA 验收通知", "body": "用于 OA03 已读回执验收。", "level": "important"})
    assert r.status_code == 200
    nid = r.json()["notice_id"]
    d = ag.get(f"{INNER}/notices").json()
    assert d["unread"] == before + 1, "新通知应计入未读"
    item = next(n for n in d["items"] if n["notice_id"] == nid)
    assert item["read_at"] is None and item["level"] == "important"
    # 已读回执：幂等
    assert ag.post(f"{INNER}/notices/{nid}/read").status_code == 200
    assert ag.get(f"{INNER}/notices").json()["unread"] == before
    assert ag.post(f"{INNER}/notices/{nid}/read").status_code == 200
    assert ag.get(f"{INNER}/notices").json()["unread"] == before
    # 管理端可见已读人数 ≥1
    d = sup.get(f"{INNER}/notices/manage").json()
    assert next(n for n in d["items"] if n["notice_id"] == nid)["read_count"] >= 1


# ---------------- OA04：通知撤回 ----------------

def test_oa04_notice_revoke(urls):
    """撤回后坐席端不再显示，管理端保留为已撤回状态"""
    sup, ag = admin(urls), do_login(urls, "b002", "abc122333", "client")
    r = sup.post(f"{INNER}/notices", json={"title": "待撤回通知", "body": "OA04 撤回验收", "level": "normal"})
    nid = r.json()["notice_id"]
    assert nid in [n["notice_id"] for n in ag.get(f"{INNER}/notices").json()["items"]]
    assert sup.post(f"{INNER}/notices/{nid}/revoke").status_code == 200
    assert nid not in [n["notice_id"] for n in ag.get(f"{INNER}/notices").json()["items"]]
    # 重复撤回被拒
    assert sup.post(f"{INNER}/notices/{nid}/revoke").status_code == 409
    rows = sup.get(f"{INNER}/notices/manage").json()["items"]
    assert next(n for n in rows if n["notice_id"] == nid)["revoked"] == 1


# ---------------- OA05：请假提交与校验 ----------------

def test_oa05_leave_submission_validation(urls):
    """合法提交进入待审批；日期倒挂/超 30 天/早于昨天被拒"""
    ag = do_login(urls, "b003", "abc122333", "client")
    r = ag.post(f"{INNER}/leaves", json={
        "start_date": "2026-12-01", "end_date": "2026-12-03", "reason": "OA05 验收请假"})
    assert r.status_code == 200 and r.json()["status"] == "PENDING"
    lid = r.json()["leave_id"]
    mine = ag.get(f"{INNER}/leaves/mine").json()
    assert next(l for l in mine if l["leave_id"] == lid)["status"] == "PENDING"
    for bad in ({"start_date": "2026-12-03", "end_date": "2026-12-01", "reason": "倒挂"},
                {"start_date": "2026-12-01", "end_date": "2027-01-15", "reason": "超长"},
                {"start_date": "2026-01-01", "end_date": "2026-01-03", "reason": "过去日期"}):
        assert ag.post(f"{INNER}/leaves", json=bad).status_code == 400


# ---------------- OA06：请假审批流转 ----------------

def test_oa06_leave_review_workflow(urls):
    """主管通过后状态与审批人落库；重复审批被乐观锁拒绝"""
    ag = do_login(urls, "b003", "abc122333", "client")
    sup = admin(urls)
    r = ag.post(f"{INNER}/leaves", json={
        "start_date": "2026-12-10", "end_date": "2026-12-11", "reason": "OA06 验收"})
    lid = r.json()["leave_id"]
    pend = sup.get(f"{INNER}/leaves/pending").json()
    assert next(l for l in pend if l["leave_id"] == lid)["applicant_name"] == "小刘"
    r = sup.post(f"{INNER}/leaves/{lid}/review",
                 json={"action": "APPROVED", "comment": "同意，注意交接"})
    assert r.status_code == 200 and r.json()["status"] == "APPROVED"
    mine = next(l for l in ag.get(f"{INNER}/leaves/mine").json() if l["leave_id"] == lid)
    assert mine["status"] == "APPROVED" and mine["review_comment"] == "同意，注意交接"
    assert mine["reviewer_name"] == "苏总"
    # 乐观锁：二次审批 409
    assert sup.post(f"{INNER}/leaves/{lid}/review", json={"action": "REJECTED"}).status_code == 409


# ---------------- OA07：不能审批自己的申请 ----------------

def test_oa07_no_self_approval(urls):
    """主管本人的请假申请不能由自己审批"""
    sup = admin(urls)
    r = sup.post(f"{INNER}/leaves", json={
        "start_date": "2026-12-20", "end_date": "2026-12-21", "reason": "OA07 自审校验"})
    lid = r.json()["leave_id"]
    r = sup.post(f"{INNER}/leaves/{lid}/review", json={"action": "APPROVED"})
    assert r.status_code == 400, "主管不应能审批自己的申请"


# ---------------- OA08：OA 功能角色边界 ----------------

def test_oa08_oa_rbac_boundaries(urls):
    """坐席不能发布/撤回通知、不能看待审批队列；匿名一律 401"""
    ag = do_login(urls, "b001", "abc122333", "client")
    assert ag.post(f"{INNER}/notices", json={"title": "x", "body": "y"}).status_code == 403
    assert ag.get(f"{INNER}/notices/manage").status_code == 403
    assert ag.get(f"{INNER}/leaves/pending").status_code == 403
    assert ag.post(f"{INNER}/users/B002/must-change", json={"enabled": True}).status_code == 403
    with httpx.Client(base_url=urls["inner"], timeout=20) as c:
        for path in (f"{INNER}/notices", f"{INNER}/leaves/mine", f"{INNER}/profile"):
            assert c.get(path).status_code == 401, f"{path} 未拦截匿名访问"
