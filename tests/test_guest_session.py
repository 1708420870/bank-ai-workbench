"""访客会话契约（v1.5.4）：客户身份必须由服务端签发，任意手机号不再等于已认证。

任务书 1.2 数据边界 + 13.1「不得让未认证者进入客户视图」。
原实现：客户页把手机号当 openid，谁都能填。
现实现：/feedback/api/v1/guest_session 签发 TTL 2 小时的访客令牌（绑定 demo 租户），
        提交/查询工单必须携带有效 token，伪造或过期一律 401。
"""
from __future__ import annotations

import httpx

from common.config import SERVICE_TOKEN  # noqa: F401  （与其他用例保持一致的导入方式）


def _issue(urls) -> dict:
    r = httpx.post(f"{urls['outer']}/feedback/api/v1/guest_session", timeout=20)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["openid"].startswith("guest-"), d
    assert d["token"] and d["tenant"] == "demo" and d["expires_at"]
    return d


def test_guest_session_issued(urls):
    d = _issue(urls)
    assert len(d["token"]) >= 20


def test_guest_can_submit_and_read_own_ticket(urls):
    d = _issue(urls)
    r = httpx.post(f"{urls['outer']}/feedback/api/v1/tickets",
                   json={"openid": d["openid"], "guest_token": d["token"],
                         "category": "ACCOUNT", "body": "我卡里有一笔 268 元消费不是我刷的"},
                   timeout=40)
    assert r.status_code == 200, r.text
    fb = r.json()["fb_id"]
    q = httpx.get(f"{urls['outer']}/feedback/api/v1/tickets/{fb}",
                  params={"openid": d["openid"], "token": d["token"]}, timeout=30)
    assert q.status_code == 200, q.text
    assert q.json()["fb_id"] == fb


def test_phone_number_cannot_impersonate(urls):
    """原来填任意手机号就能用；现在必须 401。"""
    r = httpx.post(f"{urls['outer']}/feedback/api/v1/tickets",
                   json={"openid": "13800138000", "category": "ACCOUNT", "body": "x"}, timeout=20)
    assert r.status_code == 401, r.text


def test_ticket_query_without_token_rejected(urls):
    d = _issue(urls)
    r = httpx.post(f"{urls['outer']}/feedback/api/v1/tickets",
                   json={"openid": d["openid"], "guest_token": d["token"],
                         "category": "ACCOUNT", "body": "查余额"}, timeout=40)
    fb = r.json()["fb_id"]
    q = httpx.get(f"{urls['outer']}/feedback/api/v1/tickets/{fb}",
                  params={"openid": d["openid"]}, timeout=20)
    assert q.status_code == 401, q.text
    q2 = httpx.get(f"{urls['outer']}/feedback/api/v1/tickets/{fb}",
                   params={"openid": d["openid"], "token": "fake-token-xxx"}, timeout=20)
    assert q2.status_code == 401, q2.text
