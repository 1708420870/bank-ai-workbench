"""构建桌面客户端：python build_desktop.py

产物：dist/BankAIWorkbench/ 目录（绿色免安装，整目录拷走即可分发）。
入口：dist/BankAIWorkbench/BankAIWorkbench.exe
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main() -> None:
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean",
        "--name", "BankAIWorkbench",
        "--paths", str(ROOT),
        "--add-data", f"{ROOT / 'web'};web",
        str(ROOT / "desktop" / "launcher.py"),
    ]
    print("构建中：", " ".join(cmd))
    subprocess.run(cmd, cwd=ROOT, check=True)
    exe = ROOT / "dist" / "BankAIWorkbench" / "BankAIWorkbench.exe"
    print()
    print("构建完成。")
    print(f"  入口：{exe}")
    print("  分发：整个 dist/BankAIWorkbench 目录拷贝给同事，双击 exe 即用。")
    print("  数据：数据库与审计落在 exe 同级的 data/ 目录，删除该目录即重置。")


if __name__ == "__main__":
    main()
