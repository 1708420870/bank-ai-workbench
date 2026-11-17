"""认证与授权专项测试 A01–A08。

与 T01–T20 的区别：T 系列验的是"数据出不出去"，A 系列验的是"人进不进得来"。
两条链缺一不可——边界再严，只要账号体系可绕过，前面所有控制都归零。

这些测试刻意不复用 conftest 的共享会话，而是各自真实登录，
因为要验证的正是"不同身份拿到不同权限"。
"""
from __future__ import annotations

import httpx
import pytest

INNER = "/internal/api/v1"


def do_login(urls, username: str, password: str, portal: str) -> httpx.Client:
    c = httpx.Client(base_url=urls["inner"], timeout=25)
    r = c.post(f"{INNER}/auth/login",
               json={"username": username, "password": password, "portal": portal})
    assert r.status_code == 200, f"登录失败 {r.status_code}: {r.text}"
    return c


def raw_login(urls, username: str, password: str, portal: str) -> httpx.Response:
    with httpx.Client(base_url=urls["inner"], timeout=25) as c:
        return c.post(f"{INNER}/auth/login",
                      json={"username": username, "password": password, "portal": portal})


# ---------------- A01 ----------------

def test_a01_anonymous_denied(urls):
    """未携带会话访问任何业务接口一律 401，探活接口除外"""
    with httpx.Client(base_url=urls["inner"], timeout=20) as c:
        for path in [f"{INNER}/cases", f"{INNER}/tickets", f"{INNER}/audit",
                     f"{INNER}/stats", f"{INNER}/rules", f"{INNER}/auth/me"]:
            assert c.get(path).status_code == 401, f"{path} 未拦截匿名访问"
        assert c.get(f"{INNER}/health").status_code == 200


# ---------------- A02 ----------------

def test_a02_portal_isolation(urls):
    """坐席账号进不了管理端，管理员账号进不了坐席端——在登录环节就拒绝"""
    r1 = raw_login(urls, "b001", "abc122333", "admin")
    assert r1.status_code == 403, f"坐席闯入管理端未被拒: {r1.status_code}"
    r2 = raw_login(urls, "a001", "abc123456", "client")
    assert r2.status_code == 403, f"管理员闯入坐席端未被拒: {r2.status_code}"


# ---------------- A03 ----------------

def test_a03_bad_password_uniform_message(urls):
    """口令错误与账号不存在返回同一句提示，杜绝账号枚举"""
    r1 = raw_login(urls, "b002", "definitely-wrong", "client")
    r2 = raw_login(urls, "no-such-user", "definitely-wrong", "admin")
    assert r1.status_code == 401 and r2.status_code == 401
    assert "账号或口令错误" in r1.json()["detail"]
    assert "账号或口令错误" in r2.json()["detail"]
    assert "不存在" not in r2.text


# ---------------- A04 ----------------

def test_a04_agent_cannot_read_audit(urls):
    """坐席无权读取全量审计与统计，越权返回 403 且落 AUTHZ_DENIED"""
    agent = do_login(urls, "b001", "abc122333", "client")
    assert agent.get(f"{INNER}/audit").status_code == 403
    assert agent.get(f"{INNER}/stats").status_code == 403
    assert agent.get(f"{INNER}/users").status_code == 403
    # 但本人业务接口可用
    assert agent.get(f"{INNER}/cases").status_code == 200


# ---------------- A05 ----------------

def test_a05_no_impersonation(urls):
    """坐席不得以他人 emp_id 提交工单或申请复原"""
    agent = do_login(urls, "b001", "abc122333", "client")
    r = agent.post(f"{INNER}/cases",
                   json={"case_id": "A01", "emp_id": "B002", "note": None})
    assert r.status_code == 403
    assert "他人身份" in r.json()["detail"]


# ---------------- A06 ----------------

def test_a06_supervisor_on_behalf_logged(urls):
    """主管可代坐席提交，但请求记录的真实操作者仍是坐席，并额外留 ON_BEHALF 审计"""
    boss = do_login(urls, "a001", "abc123456", "admin")
    r = boss.post(f"{INNER}/cases", json={"case_id": "A01", "emp_id": "B001", "note": None})
    assert r.status_code == 200
    rid = r.json()["request_id"]
    ev = boss.get(f"{INNER}/audit", params={"request_id": rid}).json()["inner"]
    assert any(e["event"] == "ON_BEHALF" for e in ev), [e["event"] for e in ev]
    on_behalf = [e for e in ev if e["event"] == "ON_BEHALF"][0]
    assert on_behalf["actor"] == "A001" and "B001" in on_behalf["detail"]


# ---------------- A07 ----------------

def test_a07_lockout_after_repeated_failures(urls):
    """连续 5 次口令错误后锁定，正确口令在锁定期内同样被拒"""
    for i in range(5):
        assert raw_login(urls, "b004", f"bad-{i}", "client").status_code == 401
    r = raw_login(urls, "b004", "abc122333", "client")
    assert r.status_code == 401
    assert "锁定" in r.json()["detail"]


# ---------------- A08 ----------------

def test_a08_revoke_and_logout_invalidate(urls):
    """会话吊销/登出立即生效：签发过的令牌不能继续用"""
    a = do_login(urls, "b001", "abc122333", "client")
    assert a.get(f"{INNER}/auth/me").status_code == 200

    boss = do_login(urls, "a001", "abc123456", "admin")
    live = boss.get(f"{INNER}/auth/sessions").json()
    target = [s for s in live if s["emp_id"] == "B001" and s["portal"] == "client"]
    assert target, "未找到坐席会话"
    boss.post(f"{INNER}/auth/sessions/{target[0]['sid']}/revoke")
    assert a.get(f"{INNER}/auth/me").status_code == 401, "吊销后会话仍然有效"

    b = do_login(urls, "b001", "abc122333", "client")
    b.post(f"{INNER}/auth/logout")
    assert b.get(f"{INNER}/auth/me").status_code == 401, "登出后会话仍然有效"


# ---------------- 补充：审计不含口令 ----------------

def test_a09_audit_never_contains_password(urls):
    """登录相关审计只记元数据，任何口令明文都不得出现在审计库"""
    boss = do_login(urls, "a001", "abc123456", "admin")
    ev = boss.get(f"{INNER}/audit", params={"limit": 500}).json()["inner"]
    blob = "\n".join(str(e.get("detail", "")) for e in ev)
    for secret in ["abc123456", "abc122333", "abc123456x", "definitely-wrong"]:
        assert secret not in blob, f"审计中出现口令明文: {secret}"
    assert any(e["event"] == "LOGIN_OK" for e in ev)


# ---------------- A10 ----------------

def test_a10_single_session_kick(urls):
    """单会话互踢：同一账号第二次登录后，旧会话立即失效"""
    first = do_login(urls, "b001", "abc122333", "client")
    assert first.get(f"{INNER}/auth/me").status_code == 200
    second = do_login(urls, "b001", "abc122333", "client")
    assert second.get(f"{INNER}/auth/me").status_code == 200
    assert first.get(f"{INNER}/auth/me").status_code == 401, "旧会话未被互踢"


# ---------------- A11 ----------------

def test_a11_admin_provision_and_reset(urls):
    """管理员创建账号、重置密码；无权角色创建被拒；弱口令被拒"""
    boss = do_login(urls, "a001", "abc123456", "admin")

    # 坐席无权创建账号（越权 403）
    intruder = do_login(urls, "b001", "abc122333", "client")
    r = intruder.post(f"{INNER}/users", json={
        "emp_id": "X1", "name": "无权", "username": "x1", "password": "Whatever1", "role": "agent"})
    assert r.status_code == 403

    # 弱口令在服务端被拒
    r = boss.post(f"{INNER}/users", json={
        "emp_id": "E1005", "name": "钱新员", "username": "e1005",
        "password": "12345678", "role": "agent"})
    assert r.status_code == 400

    # 正常创建：坐席角色自动归入坐席端入口
    r = boss.post(f"{INNER}/users", json={
        "emp_id": "E1005", "name": "钱新员", "username": "e1005",
        "password": "Join@2026", "role": "agent"})
    assert r.status_code == 200, r.text
    assert r.json()["portal"] == "client"

    # 新账号可登录坐席端，进不了管理端
    new = do_login(urls, "e1005", "Join@2026", "client")
    assert new.get(f"{INNER}/auth/me").status_code == 200
    assert raw_login(urls, "e1005", "Join@2026", "admin").status_code == 403

    # 重置密码：旧口令立即失效，且全部会话被吊销
    assert new.get(f"{INNER}/auth/me").status_code == 200
    r = boss.post(f"{INNER}/users/E1005/password", json={"password": "NewPass@2026"})
    assert r.status_code == 200
    assert raw_login(urls, "e1005", "Join@2026", "client").status_code == 401
    assert new.get(f"{INNER}/auth/me").status_code == 401, "重置密码后旧会话仍有效"


# ---------------- A12 ----------------

def test_a12_device_binding(urls):
    """设备绑定：绑定后异设备与浏览器均无法登录，换设备头访问也会话失效"""
    boss = do_login(urls, "a001", "abc123456", "admin")
    # 确认 e1005 存在（A11 创建）；若单独运行本测试则先创建
    if raw_login(urls, "e1005", "NewPass@2026", "client").status_code == 401:
        boss.post(f"{INNER}/users", json={
            "emp_id": "E1005", "name": "钱新员", "username": "e1005",
            "password": "NewPass@2026", "role": "agent"})

    def dev_login(device):
        with httpx.Client(base_url=urls["inner"], timeout=25) as c:
            return c.post(f"{INNER}/auth/login",
                          json={"username": "e1005", "password": "NewPass@2026", "portal": "client"},
                          headers={"x-device-id": device})

    # 浏览器登录（未绑定时允许），随后绑定设备 A
    assert raw_login(urls, "e1005", "NewPass@2026", "client").status_code == 200
    r = dev_login("DEVICE-AAAA")
    assert r.status_code == 200, "首次设备登录应完成绑定"
    token_a = r.cookies.get("wb_sid") or ""
    assert token_a, "设备登录未返回会话"

    # 异设备与浏览器从此都被拒
    assert dev_login("DEVICE-BBBB").status_code == 403
    assert raw_login(urls, "e1005", "NewPass@2026", "client").status_code == 403

    # 会话级校验：设备 A 的令牌换到设备 B 上使用立即失效
    with httpx.Client(base_url=urls["inner"], timeout=25) as c:
        r = c.get(f"{INNER}/auth/me", cookies={"wb_sid": token_a}, headers={"x-device-id": "DEVICE-AAAA"})
        assert r.status_code == 200
        r = c.get(f"{INNER}/auth/me", cookies={"wb_sid": token_a}, headers={"x-device-id": "DEVICE-BBBB"})
        assert r.status_code == 401, "跨设备复用令牌未被拦截"
