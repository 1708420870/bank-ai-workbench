"""桌面客户端启动器：把三区服务与浏览器外壳装进同一个进程树。

打包后（PyInstaller）这是一个 exe：双击后
  1. 三个线程分别拉起 内网 / DMZ / 外网 三个 FastAPI 服务（端口 8101-8103）
  2. 等待内网健康检查通过
  3. 打开 pywebview 窗口（WebView2 内核，复用系统 Edge），指向登录页

为什么不是三个进程：PyInstaller 的子进程模型在 frozen 环境下要二次解包，
对 PoC 是纯负担。三区隔离的本质是"独立的库、独立的服务边界、互不共享
状态"，线程级隔离 + 独立 SQLite 文件在演示层面同样成立；生产部署仍用
docker-compose 的三网络拓扑（见 docker-compose.yml），那份文件才是边界
的真实形态。
"""
from __future__ import annotations

import os
import sys
import threading
import time

import uvicorn

# 桌面版默认走牛马仕真实算力（GPU 服务器不可达时自动降级确定性 Mock）
os.environ.setdefault("MODEL_IMPL", "real")

APP_TITLE = "银行客服 AI 工作台"
URL = "http://127.0.0.1:8101"


def _serve(app, port: int) -> None:
    # ZONE_HOST 可放宽为 0.0.0.0：第二期真机测试需要局域网内的手机/小程序
    # 直连外区网关（8103）。默认仍 127.0.0.1（不对外暴露）。
    config = uvicorn.Config(app, host=os.getenv("ZONE_HOST", "127.0.0.1"),
                            port=port, log_level="warning")
    uvicorn.Server(config).run()


def _wait_healthy(url: str, timeout: float = 30.0) -> bool:
    import urllib.request

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status == 200:
                    return True
        except Exception:
            time.sleep(0.25)
    return False


def main() -> int:
    from common import audit
    from common.config import APP_VERSION, DMZ_PORT, EGRESS_ENABLED, INNER_PORT, MODEL_IMPL, OUTER_PORT
    from common.logger import console as console_logger

    boot = console_logger("desktop", "boot")
    boot.info("workbench_launching", extra={"extra_data": {
        "version": APP_VERSION, "inner_port": INNER_PORT, "dmz_port": DMZ_PORT,
        "outer_port": OUTER_PORT, "egress_enabled": EGRESS_ENABLED, "model_impl": MODEL_IMPL}})

    from dmz.app import app as dmz_app
    from inner.app import app as inner_app
    from outer.app import app as outer_app

    targets = [(inner_app, INNER_PORT), (dmz_app, DMZ_PORT), (outer_app, OUTER_PORT)]
    threads = []
    for app, port in targets:
        t = threading.Thread(target=_serve, args=(app, port), daemon=True, name=f"zone-{port}")
        t.start()
        threads.append(t)

    if not _wait_healthy(f"{URL}/internal/api/v1/health"):
        print("内网服务未能启动，退出。", file=sys.stderr)
        return 1

    audit.log("inner", "DESKTOP_LAUNCHED", detail={"mode": "pywebview"})

    import webview

    webview.create_window(
        APP_TITLE, f"{URL}/login",
        width=1320, height=900, min_size=(1024, 700),
    )
    webview.start()
    return 0


if __name__ == "__main__":
    sys.exit(main())
