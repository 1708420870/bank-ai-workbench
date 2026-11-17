"""本地一键启动：三个独立进程，三个端口，三个独立数据库。

刻意不用单进程多路由：如果三个区跑在一个进程里，"网络隔离"就只是命名，
不是边界。这个脚本本身就是架构声明的一部分。
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

# 演示默认走牛马仕真实算力（GPU 服务器不可达时自动降级确定性 Mock）
os.environ.setdefault("MODEL_IMPL", "real")

# 手机演示开关：LAN_BIND=1 时 inner/outer 监听 0.0.0.0（dmz 永远只绑本机），
# 同一局域网内的手机即可访问演示页（外网面 8103）。默认关闭，仅本机可访。
LAN_BIND = os.getenv("LAN_BIND", "0") == "1"

ROOT = Path(__file__).resolve().parent
ZONES = [
    ("inner", "inner.app:app", 8101, "内网可信域"),
    ("dmz", "dmz.app:app", 8102, "安全交换区 DMZ"),
    ("outer", "outer.app:app", 8103, "外网 AI 协同域"),
]


def main() -> int:
    procs: list[tuple[str, subprocess.Popen]] = []
    print("=" * 62)
    print(" 银行客服 AI 工作台 · 三区 PoC 启动中")
    print("=" * 62)

    for name, target, port, label in ZONES:
        # dmz 是安全交换区，无论何时只绑本机回环——这是边界，不是配置
        host = "127.0.0.1" if name == "dmz" else ("0.0.0.0" if LAN_BIND else "127.0.0.1")
        p = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", target, "--host", host,
             "--port", str(port), "--log-level", "warning"],
            cwd=str(ROOT),
        )
        procs.append((name, p))
        print(f"  [{label:14}] http://{'<局域网IP>' if host == '0.0.0.0' else host}:{port}")
        time.sleep(1.2)

    print("-" * 62)
    print("  工作台入口： http://127.0.0.1:8101")
    if LAN_BIND:
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
        except OSError:
            ip = "<本机局域网IP>"
        print(f"  手机演示页： http://{ip}:8103   （同一局域网/WiFi 下可访问）")
    else:
        print("  （手机演示请用 LAN_BIND=1 启动：set LAN_BIND=1 && python run_local.py）")
    print("  按 Ctrl+C 停止全部服务")
    print("=" * 62)

    def shutdown(*_):
        print("\n正在停止服务…")
        for _, p in procs:
            if p.poll() is None:
                p.terminate()
        for _, p in procs:
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    while True:
        time.sleep(1)
        for name, p in procs:
            if p.poll() is not None:
                print(f"[!] {name} 进程已退出（code={p.returncode}），停止其余服务")
                shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
