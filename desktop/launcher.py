"""桌面客户端启动器（打包入口）：一个进程拉起三区服务，然后打开浏览器。

打包后（PyInstaller onedir）双击 exe：
  1. 检查 8101-8103 是否被占用；若发现本程序已在运行，直接开浏览器，不重复启动
  2. 三个线程分别拉起 内网 / DMZ / 外网 三个 FastAPI 服务
  3. 等内网健康检查通过后，用系统默认浏览器打开登录页
  4. 控制台保留运行态，Ctrl+C 或关窗口即停三区

为什么不是三个进程：PyInstaller 子进程模型在 frozen 环境下要二次解包，对 PoC 是
纯负担。三区隔离的本质是"独立的库、独立的服务边界、互不共享状态"，线程级隔离
+ 独立 SQLite 文件在演示层面同样成立；生产部署仍用 docker-compose 的三网络拓扑
（见 docker-compose.yml），那份文件才是边界的真实形态。

为什么不用 pywebview 开原生窗口：内嵌窗口依赖 WebView2 运行时，同事机器上缺这个
组件就会白屏或直接崩。系统浏览器一定存在，且与手机端、线上版是同一套页面，
所以默认走浏览器；需要原生窗口时设 WB_SHELL=webview。
"""
from __future__ import annotations

import os
import socket
import sys
import threading
import time
import webbrowser

os.environ.setdefault("MODEL_IMPL", "real")

APP_TITLE = "银行客服 AI 工作台"

# 控制台编码：真实控制台下 Python 走宽字符 API 不受影响，但被重定向/管道时会按
# 系统代码页（简体中文为 GBK）编码，中文提示会乱码。统一成 UTF-8，配合启动.bat
# 里的 chcp 65001，控制台与日志两边都一致。
for _stream in (sys.stdout, sys.stderr):
    try:
        # line_buffering：输出被重定向到文件/管道时（如启动脚本写日志），
        # 不加这一条会攒满 8KB 才落盘，中途被关窗口就看不到就绪提示。
        _stream.reconfigure(encoding="utf-8", errors="replace",
                            line_buffering=True)  # type: ignore[attr-defined]
    except Exception:
        pass


def _port_open(host: str, port: int, timeout: float = 0.4) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0


def _lan_ips() -> list[str]:
    """列出本机可用的局域网 IPv4（排除回环），用于局域网模式下打印手机访问地址。"""
    ips: list[str] = []
    # 主路径：UDP "连接"不会真的发包，只是让系统按路由表选出出口网卡
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            if not ip.startswith("127."):
                ips.append(ip)
    except Exception:
        pass
    # 兜底：无默认路由时按主机名解析
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127.") and ip not in ips:
                ips.append(ip)
    except Exception:
        pass
    return ips


def _healthy(url: str, timeout: float = 1.5) -> bool:
    import urllib.request

    try:
        with urllib.request.urlopen(url, timeout=timeout) as r:
            return r.status == 200
    except Exception:
        return False


def _wait_healthy(url: str, timeout: float = 40.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _healthy(url, timeout=1.0):
            return True
        time.sleep(0.3)
    return False


def _serve(app, host: str, port: int) -> None:
    import uvicorn

    uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="warning")).run()


def _open_shell(url: str) -> None:
    """优先用内嵌窗口（可选），失败或未安装时退回系统浏览器。"""
    if os.getenv("WB_SHELL", "browser").lower() == "webview":
        try:
            import webview  # 可选依赖，未安装时直接回退

            webview.create_window(APP_TITLE, url, width=1320, height=900,
                                  min_size=(1024, 700))
            webview.start()
            return
        except Exception as exc:  # noqa: BLE001 - 任何失败都退回浏览器
            print(f"[i] 内嵌窗口不可用（{exc}），改用系统浏览器。")
    try:
        webbrowser.open(url)
    except Exception:
        pass


def _die(msg: str) -> int:
    print()
    print("!" * 64)
    print(msg)
    print("!" * 64)
    try:
        input("\n按回车键关闭窗口…")
    except Exception:
        pass
    return 1


def main() -> int:
    from common.config import (
        APP_VERSION, DMZ_PORT, EGRESS_ENABLED, HOST, INNER_PORT, MODEL_IMPL, OUTER_PORT,
    )
    from common.logger import console as console_logger

    inner_url = f"http://127.0.0.1:{INNER_PORT}"
    health = f"{inner_url}/internal/api/v1/health"

    print("=" * 64)
    print(f"  {APP_TITLE}  v{APP_VERSION}")
    print("=" * 64)

    # 已在运行：直接开浏览器，避免"端口占用"把用户挡在门外
    if _healthy(health):
        print("[i] 检测到本程序已在运行，直接打开浏览器。")
        _open_shell(f"{inner_url}/login")
        return 0

    busy = [p for p in (INNER_PORT, DMZ_PORT, OUTER_PORT) if _port_open(HOST, p)]
    if busy:
        return _die(
            "端口被占用，无法启动：\n"
            f"  被占端口：{', '.join(map(str, busy))}\n\n"
            "处理办法（任选其一）：\n"
            "  1) 关闭占用该端口的程序后重试；\n"
            "  2) 换一组端口启动：编辑同目录的 启动.bat，把\n"
            "     INNER_PORT / DMZ_PORT / OUTER_PORT 改成 18101 / 18102 / 18103"
        )

    console_logger("desktop", "boot").info("workbench_launching", extra={"extra_data": {
        "version": APP_VERSION, "inner_port": INNER_PORT, "dmz_port": DMZ_PORT,
        "outer_port": OUTER_PORT, "egress_enabled": EGRESS_ENABLED, "model_impl": MODEL_IMPL}})

    from dmz.app import app as dmz_app
    from inner.app import app as inner_app
    from outer.app import app as outer_app

    for app, port in ((inner_app, INNER_PORT), (dmz_app, DMZ_PORT), (outer_app, OUTER_PORT)):
        threading.Thread(target=_serve, args=(app, HOST, port), daemon=True,
                         name=f"zone-{port}").start()

    print("[*] 正在启动内网 / DMZ / 外网三个服务…")
    if not _wait_healthy(health):
        return _die(
            "内网服务启动失败（40 秒内未就绪）。\n"
            "请把本窗口截图发给维护人，并检查是否有杀毒软件拦截。"
        )

    from common import audit

    audit.log("inner", "DESKTOP_LAUNCHED", detail={"mode": os.getenv("WB_SHELL", "browser")})

    print()
    print("  已就绪，浏览器将自动打开。若未自动打开，手动访问：")
    print(f"    员工工作台（坐席 / 管理）  {inner_url}/login")
    print(f"    客户反馈页（客户视角）    http://127.0.0.1:{OUTER_PORT}/")
    if HOST == "0.0.0.0":
        # 局域网模式：把可用地址直接打出来，省得用户去 ipconfig 里翻
        print()
        print("  局域网模式已开启，同一 Wi-Fi 下的手机可访问：")
        for ip in _lan_ips():
            print(f"    客户反馈页  http://{ip}:{OUTER_PORT}/    "
                  f"工作台  http://{ip}:{INNER_PORT}/login")
        if not _lan_ips():
            print("    （未检测到局域网地址，请确认已连上 Wi-Fi 或有线网络）")
        print("    若手机仍打不开：Windows 防火墙提示时选「允许访问」")
    print()
    print("  演示账号：")
    print("    坐席 b001 / abc122333    管理员 a001 / abc123456")
    print("    开发 t001 / Tech@2026")
    print()
    print("  本窗口不要关闭；关闭窗口即停止服务。")
    print("=" * 64)

    if os.getenv("WB_NO_BROWSER", "0") != "1":
        _open_shell(f"{inner_url}/login")

    try:
        while True:
            time.sleep(1)
            if not _healthy(health, timeout=3.0):
                time.sleep(2)
                if not _healthy(health, timeout=3.0):
                    print("[!] 内网服务已停止，程序退出。")
                    return 1
    except KeyboardInterrupt:
        print("\n正在停止服务…")
        return 0


if __name__ == "__main__":
    sys.exit(main())
