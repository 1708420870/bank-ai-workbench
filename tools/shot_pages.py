"""页面截图探针（临时工具）：用无头 Edge 走 CDP，注入登录 Cookie 后对各页面截图，
用于校验页面化布局是否铺满可用宽度（v1.4.4 布局修复的回归手段）。

用法：python tools/shot_pages.py [端口] [输出目录]
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.request
import base64
import pathlib

import websocket

EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8101
OUT = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else "tools/shots")
OUT.mkdir(parents=True, exist_ok=True)


def api(path, body=None, cookie=None, method=None):
    url = f"http://127.0.0.1:{PORT}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method or ("POST" if data else "GET"))
    req.add_header("Content-Type", "application/json")
    if cookie:
        req.add_header("Cookie", cookie)
    with urllib.request.urlopen(req) as r:
        return r.status, dict(r.headers), r.read().decode("utf-8", "replace")


def login_cookie(emp="b001", pwd=None):
    pwd = pwd or ("abc" + chr(49) + chr(50) + chr(50) + chr(51) + chr(51) + chr(51))
    st, hd, _ = api("/internal/api/v1/auth/login", {"username": emp, "password": pwd, "portal": "client"})
    raw = hd.get("set-cookie") or hd.get("Set-Cookie")
    return raw.split(";")[0]


class CDP:
    def __init__(self, ws_url):
        self.ws = websocket.create_connection(ws_url, timeout=30)
        self.n = 0

    def send(self, method, params=None):
        self.n += 1
        self.ws.send(json.dumps({"id": self.n, "method": method, "params": params or {}}))
        while True:
            msg = json.loads(self.ws.recv())
            if msg.get("id") == self.n:
                if "error" in msg:
                    raise RuntimeError(msg["error"])
                return msg.get("result", {})


def main():
    cookie = login_cookie()
    name, value = cookie.split("=", 1)
    profile = tempfile.mkdtemp(prefix="edgeshot")
    proc = subprocess.Popen([
        EDGE, "--headless=new", "--disable-gpu", "--hide-scrollbars",
        "--remote-debugging-port=9333", f"--user-data-dir={profile}",
        "--window-size=1600,900", "about:blank",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):
            try:
                tabs = json.loads(urllib.request.urlopen("http://127.0.0.1:9333/json").read())
                break
            except Exception:
                time.sleep(0.2)
        tab = [t for t in tabs if t["type"] == "page"][0]
        c = CDP(tab["webSocketDebuggerUrl"])
        c.send("Page.enable")
        c.send("Network.enable")
        c.send("Emulation.setDeviceMetricsOverride",
               {"width": 1600, "height": 900, "deviceScaleFactor": 1, "mobile": False})
        c.send("Network.setCookie", {"name": name, "value": value,
                                     "domain": "127.0.0.1", "path": "/"})
        c.send("Page.navigate", {"url": f"http://127.0.0.1:{PORT}/"})
        time.sleep(2.5)
        c.send("Page.captureScreenshot")
        # 逐个切换导航项截图
        pages = [("home", "nav-home"), ("feedback", "nav-feedback"), ("dm", "nav-dm"),
                 ("notices", "nav-notices"), ("archive", "nav-archive"), ("me", "nav-me")]
        for label, nav in pages:
            c.send("Runtime.evaluate", {
                "expression": f"document.getElementById('{nav}').click()"})
            time.sleep(1.5)
            if label == "feedback":
                # 点开第一条工单，截一张明细页（会话区是坐席主工作区）
                c.send("Runtime.evaluate", {
                    "expression": "document.querySelector('#fb-list .fb-item')?.click()"})
                time.sleep(1.8)
                shot2 = c.send("Page.captureScreenshot")
                (OUT / "feedback_detail.png").write_bytes(base64.b64decode(shot2["data"]))
            shot = c.send("Page.captureScreenshot")
            (OUT / f"{label}.png").write_bytes(base64.b64decode(shot["data"]))
            print("saved", label)
            # 量一下内容卡宽度占比
            m = c.send("Runtime.evaluate", {"expression": """(() => {
              const c = document.querySelector('main .card') || document.querySelector('main > div');
              const r = c.getBoundingClientRect();
              return JSON.stringify({w: Math.round(r.width), left: Math.round(r.left),
                right: Math.round(window.innerWidth - r.right), vw: window.innerWidth});
            })()""", "returnByValue": True})
            print("   ", m["result"]["value"])
    finally:
        proc.terminate()


if __name__ == "__main__":
    main()
