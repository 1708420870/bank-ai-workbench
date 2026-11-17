"""手机视口布局探针：用无头 Edge + CDP 按移动设备视口逐页截图/量宽。

用法：python tools/shot_mobile.py [端口] [宽] [高] [输出目录]
默认 390x844（iPhone 12/13/14 逻辑分辨率）。
"""
from __future__ import annotations

import base64
import json
import pathlib
import subprocess
import sys
import tempfile
import time
import urllib.request

import websocket

sys.path.insert(0, str(pathlib.Path(__file__).parent))
from shot_pages import CDP, EDGE, api  # noqa: E402

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8101
W = int(sys.argv[2]) if len(sys.argv) > 2 else 390
H = int(sys.argv[3]) if len(sys.argv) > 3 else 844
OUT = pathlib.Path(sys.argv[4] if len(sys.argv) > 4 else "tools/shots_mobile")
OUT.mkdir(parents=True, exist_ok=True)

PAGES = [("home", "nav-home"), ("feedback", "nav-feedback"), ("dm", "nav-dm"),
         ("notices", "nav-notices"), ("archive", "nav-archive"), ("me", "nav-me")]

MEASURE = """(() => {
  const pick = s => { const el = document.querySelector(s); if (!el) return null;
    const b = el.getBoundingClientRect();
    return {w: Math.round(b.width), h: Math.round(b.height), top: Math.round(b.top),
            bottom: Math.round(b.bottom), sw: el.scrollWidth, cw: el.clientWidth}; };
  const de = document.documentElement;
  return JSON.stringify({
    vw: window.innerWidth, vh: window.innerHeight,
    docScrollW: de.scrollWidth, docClientW: de.clientWidth,
    bodyOverflowX: de.scrollWidth > de.clientWidth,
    topbar: pick('.topbar'), sidenav: pick('.sidenav'), main: pick('main'),
    card: pick('main .card'), pageBody: pick('.page-body'),
    cardH: pick('.card-h'), tabs: pick('.fb-tabs'), list: pick('#fb-list'),
    chat: pick('#fb-chat'), msgs: pick('#fb-msgs'), input: pick('.dm-input')
  }, null, 1);
})()"""


def main() -> None:
    pwd = "abc" + chr(49) + chr(50) + chr(50) + chr(51) + chr(51) + chr(51)
    st, hd, _ = api("/internal/api/v1/auth/login",
                    {"username": "b001", "password": pwd, "portal": "client"})
    name, value = (hd.get("set-cookie") or hd.get("Set-Cookie")).split(";")[0].split("=", 1)
    prof = tempfile.mkdtemp(prefix="edgem")
    proc = subprocess.Popen([
        EDGE, "--headless=new", "--disable-gpu", "--hide-scrollbars",
        "--remote-debugging-port=9336", f"--user-data-dir={prof}", "about:blank",
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        tabs = None
        for _ in range(60):
            try:
                tabs = json.loads(urllib.request.urlopen("http://127.0.0.1:9336/json").read())
                break
            except Exception:
                time.sleep(0.2)
        tab = [t for t in tabs if t["type"] == "page"][0]
        c = CDP(tab["webSocketDebuggerUrl"])
        c.send("Page.enable")
        c.send("Network.enable")
        c.send("Emulation.setDeviceMetricsOverride",
               {"width": W, "height": H, "deviceScaleFactor": 2, "mobile": True})
        c.send("Emulation.setTouchEmulationEnabled", {"enabled": True, "maxTouchPoints": 5})
        c.send("Network.setCookie", {"name": name, "value": value,
                                     "domain": "127.0.0.1", "path": "/"})
        c.send("Page.navigate", {"url": f"http://127.0.0.1:{PORT}/"})
        time.sleep(2.5)
        as_png = lambda r: base64.b64decode(r["data"])
        (OUT / "00_home.png").write_bytes(as_png(c.send("Page.captureScreenshot")))
        print("home:", c.send("Runtime.evaluate", {"expression": MEASURE, "returnByValue": True})["result"]["value"])
        for label, nav in PAGES[1:]:
            c.send("Runtime.evaluate", {"expression": f"document.getElementById('{nav}').click()"})
            time.sleep(1.6)
            (OUT / f"{label}.png").write_bytes(as_png(c.send("Page.captureScreenshot")))
            if label == "feedback":
                # 列表态先落图，再点开第一条验证「列表 → 会话」切换
                c.send("Runtime.evaluate", {
                    "expression": "document.querySelector('#fb-list .fb-item')?.click()"})
                time.sleep(1.8)
                (OUT / "02_feedback_detail.png").write_bytes(as_png(c.send("Page.captureScreenshot")))
                # 再点返回，验证回到列表
                c.send("Runtime.evaluate", {
                    "expression": "document.getElementById('fb-back')?.click()"})
                time.sleep(1.0)
                (OUT / "03_feedback_back.png").write_bytes(as_png(c.send("Page.captureScreenshot")))
                state = c.send("Runtime.evaluate", {"returnByValue": True, "expression":
                    "JSON.stringify({cls: document.getElementById('fb-body').className,"
                    " hasBack: !!document.getElementById('fb-back'),"
                    " listVisible: document.getElementById('fb-list').offsetParent !== null})"})
                print("back-state:", state["result"]["value"])
            print(label + ":", c.send("Runtime.evaluate", {
                "expression": MEASURE, "returnByValue": True})["result"]["value"])
    finally:
        proc.terminate()


if __name__ == "__main__":
    main()
