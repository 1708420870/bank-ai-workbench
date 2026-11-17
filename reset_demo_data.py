"""演示数据一键重置：清空三区数据库，下次 run_local.py 启动时自动重建种子数据。

用法：
    python reset_demo_data.py          # 确认后重置
    python reset_demo_data.py --yes    # 跳过确认直接重置
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"


def main() -> None:
    if not DATA.exists():
        print("data/ 目录不存在，无需重置（首次启动会自动创建种子数据）")
        return
    if "--yes" not in sys.argv:
        print("即将删除以下目录（三区数据库与日志，重置后演示数据清零）：")
        print(f"  {DATA}")
        if input("确认重置？(y/N): ").strip().lower() != "y":
            print("已取消")
            return
    # 仅删除三区库与日志，不动其他演示产物
    removed = []
    skipped = []
    for name in ("inner.db", "dmz.db", "outer.db"):
        p = DATA / name
        if p.exists():
            try:
                p.unlink()
                removed.append(name)
            except OSError as exc:
                skipped.append(f"{name}（{exc.__class__.__name__}，请先停止服务）")
    logs = DATA / "logs"
    if logs.exists():
        try:
            shutil.rmtree(logs)
            removed.append("logs/")
        except OSError:
            skipped.append("logs/（被运行中的服务占用，重启后自动重建，可忽略）")
    print("已删除：", ", ".join(removed) if removed else "（无）")
    if skipped:
        print("已跳过：", ", ".join(skipped))
    print("完成。下次 python run_local.py 启动将自动重建种子数据：")
    print("  管理员 a001 · 坐席 b001-b004 · 客户 a001 门户 · 工单/反馈/私信全部清零")


if __name__ == "__main__":
    main()
