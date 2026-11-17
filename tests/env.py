"""测试台共享状态。

会话在这里集中持有：任何打内网的测试都必须带这份 cookie，否则会 401。
这本身就是一条隐含断言——**没有会话就拿不到任何业务数据**。
"""
from __future__ import annotations

from common.config import SERVICE_TOKEN

# 由 conftest 的登录 fixture 填充；测试模块只持有引用，填充后自动可见。
COOKIE: dict[str, str] = {}

# DMZ 的 MCP 网关只认服务凭证
SERVICE_HEADERS = {"x-service-token": SERVICE_TOKEN}

TEST_ACCOUNT = {"username": "a001", "password": "abc123456", "portal": "admin"}


def refresh_admin_cookie(base: str) -> None:
    """就地刷新共享管理员会话。

    背景：SINGLE_SESSION=true 时，任何一次 a001 重新登录都会顶掉上一个会话。
    测试会话 cookie 是全局共享的（COOKIE 字典），所以"别的用例用 a001 登录过一次"
    就会让后续用例拿到 401——这不是产品缺陷，是测试编排问题。
    解决方式：谁需要管理员会话，谁在 module 前后刷新一次，把最新 sid 写回共享字典。
    """
    import httpx

    r = httpx.post(f"{base.rstrip('/')}/internal/api/v1/auth/login", json=TEST_ACCOUNT, timeout=20)
    r.raise_for_status()
    COOKIE.clear()
    COOKIE.update(dict(r.cookies))
