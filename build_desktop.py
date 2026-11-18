"""构建分发包：python build_desktop.py

产物：
  dist/BankAIWorkbench/                      PyInstaller 原始目录（调试用）
  release/银行客服AI工作台-v<版本>-win64/     可直接分发的绿色包
  release/银行客服AI工作台-v<版本>-win64.zip  打包好的压缩包（发给同事的就是这个）

同事拿到 zip 后：解压 → 双击「启动.bat」→ 浏览器自动打开，不需要装 Python。
数据落在包内 data/ 目录，删除该目录即恢复演示初始状态。
"""
from __future__ import annotations

import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from common.config import APP_VERSION  # noqa: E402

APP_CN = "银行客服AI工作台"
PKG_NAME = f"{APP_CN}-v{APP_VERSION}-win64"
RELEASE = ROOT / "release"

# 每次构建落到独立目录：PyInstaller 的 --noconfirm 会先整目录删除，遇到文件数
# 上千时可能被系统的批量删除保护拦下。用时间戳目录既避开删除，也留下可回溯的
# 构建现场（旧的 dist 目录不再被覆盖）。
STAMP = time.strftime("%m%d_%H%M%S")
DISTPATH = ROOT / "dist" / STAMP
WORKPATH = ROOT / "build" / STAMP
DIST = DISTPATH / "BankAIWorkbench"

# 批处理一律写成纯 ASCII。
# 原因：cmd.exe 解析 .bat 是按当前代码页逐字节读的，UTF-8 中文行会被按字节边界截断，
# 出现 "xxx' is not recognized as an internal or external command" 这类报错；改成 GBK
# 又依赖系统区域设置（英文版 Windows 会变乱码，且 GBK 尾字节可能落在 | & 之类元字符上）。
# 所有中文提示改由 exe 自己打印（Python 走宽字符控制台 API，不存在这个问题）。
LAUNCH_BAT = r"""@echo off
chcp 65001 >nul
title Bank AI Workbench
cd /d "%~dp0"

rem MODEL_IMPL=real: call the private GPU endpoint; auto-degrades to mock if unreachable
set MODEL_IMPL=real

"%~dp0BankAIWorkbench.exe"
if errorlevel 1 (
  echo.
  echo Startup failed. Please screenshot this window and send it to the maintainer.
  pause
)
"""

LAN_BAT = r"""@echo off
chcp 65001 >nul
title Bank AI Workbench (LAN mode)
cd /d "%~dp0"
set MODEL_IMPL=real
rem Bind 0.0.0.0 so phones on the same Wi-Fi can reach port 8103
set ZONE_HOST=0.0.0.0

"%~dp0BankAIWorkbench.exe"
if errorlevel 1 (
  echo.
  echo Startup failed. Please screenshot this window and send it to the maintainer.
  pause
)
"""

RESET_BAT = r"""@echo off
chcp 65001 >nul
title Reset demo data
cd /d "%~dp0"


echo This will delete the data folder (database, audit logs, archive).
set /p ok=Type Y and press Enter to confirm:
if /i not "%ok%"=="Y" (
  echo Cancelled.
  pause
  exit /b 0
)
if exist "data" rmdir /s /q "data"
echo Done. The next start will rebuild the database with demo seed data.
pause
"""

README = """银行客服 AI 工作台（PoC 演示包）  v{ver}

一、怎么跑起来
  1. 解压整个文件夹到本地磁盘（不要放在压缩包里直接双击，也不要放在只读目录）
  2. 双击「启动.bat」
  3. 等 5-10 秒，浏览器会自动打开登录页；若没打开，手动访问 http://127.0.0.1:8101/login
  4. 黑色控制台窗口不要关，关掉就停止服务

  不需要安装 Python、数据库或任何依赖，解压即用。

二、演示账号
  坐席     b001 / abc122333        （工单处理、站内私信、客户反馈）
  坐席     b002 / abc122333
  管理员   a001 / abc123456        （管理控制台 /admin：观测、变更审批、审计导出）
  开发     t001 / Tech@2026

  客户视角（客户反馈页）：http://127.0.0.1:8103/

三、三个区是什么
  内网可信域   8101   客户原始数据、规则、工单、审计（数据不出这一区）
  安全交换区   8102   DMZ，唯一咽喉点：脱敏、规则裁决、限流、出入域审计
  外网协同域   8103   客户反馈入口 + 模型调用出口（只拿得到脱敏上下文）
  三个区三个独立数据库，跑在同一个进程的不同线程里——演示够用；
  真实隔离形态见项目内 docker-compose.yml 的三网络拓扑。

四、手机怎么看
  手机和电脑连同一个 WiFi，双击「启动-局域网.bat」，
  窗口里会打印手机访问地址（形如 http://192.168.x.x:8103/）。
  首次运行 Windows 会弹防火墙提示，选「允许访问」。

五、常见问题
  1. 提示端口被占用：8101-8103 被别的程序占了。关掉占用程序，
     或编辑「启动.bat」在 set MODEL_IMPL 那行下面加三行：
         set INNER_PORT=18101
         set DMZ_PORT=18102
         set OUTER_PORT=18103
     然后浏览器改用 http://127.0.0.1:18101/login
  2. 浏览器打开是空白：地址栏确认端口是 8101；换 Chrome/Edge 再试。
  3. 杀毒软件拦截 exe：加入信任后重试（PyInstaller 打包的程序常被误报）。
  4. 想恢复初始数据：双击「重置演示数据.bat」，或在关闭程序后删除 data 目录。
  5. 数据会丢吗：所有数据在包内 data 目录，整个文件夹拷走即带着走。

六、这包是什么
  PoC 演示件，不是生产系统。口令、密钥、会话签名都是演示级常量，
  真实投产需替换为行内 SSO、KMS/HSM 与堡垒机审计。
  版本 {ver}，构建时间 {built}。
"""


def sh(cmd: list[str]) -> None:
    print("+", " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)


def build() -> None:
    sh([sys.executable, "-m", "PyInstaller", "--noconfirm",
        "--name", "BankAIWorkbench",
        "--paths", str(ROOT),
        "--distpath", str(DISTPATH),
        "--workpath", str(WORKPATH),
        "--add-data", f"{ROOT / 'web'};web",
        "--add-data", f"{ROOT / 'h5'};h5",
        "--console",
        str(ROOT / "desktop" / "launcher.py")])


def assemble() -> Path:
    from datetime import datetime

    target = RELEASE / PKG_NAME
    if target.exists():
        # 不直接删除旧包：整目录删除可能触发批量删除保护，改名留档更稳
        target.rename(target.with_name(f"{target.name}.old-{STAMP}"))
    target.mkdir(parents=True)
    shutil.copytree(DIST, target, dirs_exist_ok=True)

    (target / "启动.bat").write_text(LAUNCH_BAT, encoding="utf-8", newline="\r\n")
    (target / "启动-局域网.bat").write_text(LAN_BAT, encoding="utf-8", newline="\r\n")
    (target / "重置演示数据.bat").write_text(RESET_BAT, encoding="utf-8", newline="\r\n")
    (target / "使用说明.txt").write_text(
        README.format(ver=APP_VERSION, built=datetime.now().strftime("%Y-%m-%d %H:%M")),
        encoding="utf-8", newline="\r\n")
    return target


def zipit(target: Path) -> Path:
    # 注意：不能用 with_suffix(".zip")——目标目录名里有 "v1.4.5-win64"，
    # with_suffix 会把 ".5-win64" 当成扩展名替换掉，生成 "…-v1.4.zip"
    archive = target.parent / f"{target.name}.zip"
    if archive.exists():
        archive.unlink()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for f in target.rglob("*"):
            if f.is_file():
                zf.write(f, target.name + "/" + str(f.relative_to(target)))
    return archive


def main() -> None:
    build()
    target = assemble()
    archive = zipit(target)

    size = archive.stat().st_size / 1024 / 1024
    print()
    print("构建完成。")
    print(f"  目录：{target}")
    print(f"  压缩包：{archive}  （{size:.1f} MB）")
    print("  分发：把 zip 发给同事，解压后双击「启动.bat」。")


if __name__ == "__main__":
    main()
