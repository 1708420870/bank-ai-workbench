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
