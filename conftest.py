"""测试台：真实启动三个独立服务进程，用真实 HTTP 跨区调用。

不用 TestClient / 进程内 mock —— 因为"网络隔离"和"fail-closed"只有在真实
进程边界上才有意义。T12、T20 断言的正是这一点。
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent
TEST_DATA = ROOT / "data_test"
REPORT = ROOT / "data" / "acceptance.json"

# 测试端口与演示端口错开，避免与正在运行的 run_local.py 冲突
PORTS = {"inner": 18101, "dmz": 18102, "outer": 18103}
os.environ["ZONE_HOST"] = "127.0.0.1"
os.environ["DATA_DIR"] = str(TEST_DATA)
# 设备绑定开关：测试会真实走"绑定 → 异设备拒绝"链路
os.environ["DEVICE_BINDING"] = "true"
# 测试固定走确定性 Mock，不依赖外网算力——验收必须可离线复现
os.environ["MODEL_IMPL"] = "mock"
for _z, _p in PORTS.items():
    os.environ[f"{_z.upper()}_PORT"] = str(_p)
    os.environ[f"{_z.upper()}_URL"] = f"http://127.0.0.1:{_p}"

TARGETS = {"inner": "inner.app:app", "dmz": "dmz.app:app", "outer": "outer.app:app"}
HEALTH = {
    "inner": "/internal/api/v1/health",
    "dmz": "/dmz/api/v1/health",
    "outer": "/outer/api/v1/health",
}

# 验收项元数据（T01–T20）
ITEMS = {
    "T01": "原始姓名不得出域",
    "T02": "卡号原值不得出域",
    "T03": "映射表不得出域",
    "T04": "上下文最小化",
    "T05": "request_id 关联校验",
    "T06": "跨会话恢复拒绝",
    "T07": "上游超时安全降级",
    "T08": "非法结构响应拒收",
    "T09": "未知意图拒绝自动处理",
    "T10": "规则冲突以内网为准",
    "T11": "提示注入不改变边界",
    "T12": "外网不可直连内网",
    "T13": "MCP 角色越权拒绝",
    "T14": "任意 SQL 工具不存在",
    "T15": "原始客户明细不返回",
    "T16": "规则草稿不影响生产",
    "T17": "变更审批链可查",
    "T18": "审计不含明文",
    "T19": "重放请求幂等阻断",
    "T20": "跨域故障不绕过网关",
    # 认证与授权专项（A 系列）：验"人进不进得来"
    "A01": "匿名访问业务接口拒绝",
    "A02": "坐席端与管理端登录隔离",
    "A03": "登录失败提示统一防枚举",
    "A04": "坐席无权读取全量审计",
    "A05": "不得冒用他人身份提交",
    "A06": "主管代提交留双身份审计",
    "A07": "连续失败锁定账号",
    "A08": "会话吊销与登出即时生效",
    "A09": "审计不含口令明文",
    "A10": "单会话互踢防账号共享",
    "A11": "管理员发号与重置密码",
    "A12": "设备绑定限制登录来源",
    # OA 化专项（OA 系列）：验"进来之后像不像正式产品"
    "OA01": "口令策略与自助改密",
    "OA02": "首登强制改密",
    "OA03": "通知发布与已读回执",
    "OA04": "通知撤回",
    "OA05": "请假提交与校验",
    "OA06": "请假审批流转",
    "OA07": "不得自审请假",
    "OA08": "OA 角色边界",
    # 站内私信专项（DM 系列）：验"消息触达与边界"
    "DM01": "通讯录完整性",
    "DM02": "私信发送与双向会话",
    "DM03": "未读计数与已读回执",
    "DM04": "私信越权与边界",
    "DM05": "私信审计不落正文",
}


class Stack:
    def __init__(self) -> None:
        self.procs: dict[str, subprocess.Popen] = {}

    def _env(self) -> dict:
        e = os.environ.copy()
        e["DATA_DIR"] = str(TEST_DATA)
        e["PYTHONPATH"] = str(ROOT)
        return e

    def start(self, zone: str) -> None:
        p = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", TARGETS[zone], "--host", "127.0.0.1",
             "--port", str(PORTS[zone]), "--log-level", "error"],
            cwd=str(ROOT), env=self._env(),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self.procs[zone] = p
        self._wait(zone)

    def _wait(self, zone: str, timeout: float = 45.0) -> None:
        import httpx

        url = f"http://127.0.0.1:{PORTS[zone]}{HEALTH[zone]}"
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                if httpx.get(url, timeout=1.0).status_code == 200:
                    return
            except Exception:
                pass
            time.sleep(0.3)
        raise RuntimeError(f"{zone} 未能启动")

    def stop(self, zone: str) -> None:
        p = self.procs.pop(zone, None)
        if p and p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=8)
            except subprocess.TimeoutExpired:
                p.kill()

    def restart(self, zone: str) -> None:
        self.stop(zone)
        self.start(zone)

    def shutdown(self) -> None:
        for z in list(self.procs):
            self.stop(z)


@pytest.fixture(scope="session")
def stack():
    if TEST_DATA.exists():
        shutil.rmtree(TEST_DATA, ignore_errors=True)
    TEST_DATA.mkdir(parents=True, exist_ok=True)

    s = Stack()
    s.start("inner")
    s.start("outer")
    s.start("dmz")
    yield s
    s.shutdown()


@pytest.fixture(scope="session")
def urls(stack) -> dict:
    """依赖 stack，确保任何使用 urls 的测试都跑在真实启动的三区之上。"""
    return {z: f"http://127.0.0.1:{p}" for z, p in PORTS.items()}


@pytest.fixture(scope="session", autouse=True)
def session_cookie(urls):
    """用主管账号真实登录一次，与会话共享给后续测试。

    走真实登录接口而不是伪造 cookie：这样"会话签发、角色绑定、Cookie 属性"
    都在测试覆盖范围内，而不是被绕过。
    """
    import httpx

    from tests.env import COOKIE, TEST_ACCOUNT

    r = httpx.post(f"{urls['inner']}/internal/api/v1/auth/login",
                   json=TEST_ACCOUNT, timeout=30)
    assert r.status_code == 200, f"测试登录失败: {r.status_code} {r.text}"
    COOKIE.update(dict(r.cookies))
    assert COOKIE, "登录未返回会话 Cookie"
    yield COOKIE


# ---------------- 验收报告 ----------------

_RESULTS: dict[str, dict] = {}


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    rep = outcome.get_result()
    if rep.when != "call":
        return
    name = item.name
    if name.startswith("test_t"):
        tid = "T" + name[6:8]
    elif name.startswith("test_a"):
        tid = "A" + name[6:8]
    elif name.startswith("test_oa"):
        tid = "OA" + name[7:9]   # "test_oa01"：数字从索引 7 起
    elif name.startswith("test_dm"):
        tid = "DM" + name[7:9]
    else:
        return
    if tid not in ITEMS:
        return
    doc = (item.function.__doc__ or "").strip().replace("\n", " ")
    _RESULTS[tid] = {"status": "pass" if rep.passed else "fail", "evidence": doc[:160]}


def pytest_sessionfinish(session, exitstatus):
    REPORT.parent.mkdir(parents=True, exist_ok=True)
    items = []
    for tid, label in ITEMS.items():
        r = _RESULTS.get(tid, {"status": "fail", "evidence": "未执行"})
        items.append({"id": tid, "name": label, "status": r["status"], "evidence": r["evidence"]})
    passed = sum(1 for i in items if i["status"] == "pass")
    REPORT.write_text(
        json.dumps({"total": len(items), "passed": passed, "items": items}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
