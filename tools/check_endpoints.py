"""端点登记表一致性检查（R9 / M14 的复验工具）。

问题：文档说一套、代码跑另一套，是审计最常见的翻车点。
做法：把 docs/17 的 Markdown 表格解析成字典，与 inner/agent.py:ENDPOINTS 逐字段比对，
      任一不一致 → 退出码 1。

用法：
  python tools/check_endpoints.py
  python tools/check_endpoints.py --doc docs/17-模型端点登记表.md
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from inner.agent import ENDPOINTS  # noqa: E402

ROW = re.compile(r"^\|\s*`(ep-[a-z0-9\-]+)`\s*\|(.+)\|\s*$")


def parse_doc(path: Path) -> dict[str, dict]:
    rows: dict[str, dict] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        m = ROW.match(line.strip())
        if not m:
            continue
        eid = m.group(1)
        cells = [c.strip() for c in m.group(2).split("|")]
        # 列序：供应商 | 版本 | 所在域 | region | auth | 数据等级 | 出域 | 审批人 | 生效日期 | 可调用
        if len(cells) < 10:
            continue
        rows[eid] = {
            "supplier": cells[0],
            "version": cells[1].strip("`"),
            "egress": cells[6].startswith("是"),
            "region": cells[3].strip("`"),
            "auth": cells[4].strip("`").lower(),
            "max_data_level": re.sub(r"[^A-Z0-9]", "", cells[5])[:2],
            "approved_by": cells[7],
            "effective_from": cells[8],
        }
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--doc", default=str(ROOT / "docs" / "17-模型端点登记表.md"))
    args = ap.parse_args()

    doc = parse_doc(Path(args.doc))
    problems: list[str] = []

    if not doc:
        print("✗ 未能从文档解析出任何端点行（表格格式可能被改动）")
        return 1

    for eid, ep in ENDPOINTS.items():
        if eid not in doc:
            problems.append(f"文档缺少端点 {eid}")
            continue
        d = doc[eid]
        pairs = [
            ("supplier", ep.supplier, d["supplier"]),
            ("version", ep.version, d["version"]),
            ("egress", ep.egress, d["egress"]),
            ("region", ep.region, d["region"]),
            ("auth", ep.auth.lower(), d["auth"]),
            ("max_data_level", ep.max_data_level, d["max_data_level"]),
            ("approved_by空否", bool(ep.approved_by), bool(d["approved_by"].strip("— "))),
            ("effective_from", ep.effective_from, d["effective_from"]),
        ]
        for field, a, b in pairs:
            if a != b:
                problems.append(f"{eid}.{field} 不一致：代码={a!r} 文档={b!r}")

    for eid in doc:
        if eid not in ENDPOINTS:
            problems.append(f"文档登记了代码中不存在的端点 {eid}（幻觉端点）")

    # 额外硬约束：出域端点不得被批为 L2
    for eid, ep in ENDPOINTS.items():
        if ep.egress and ep.max_data_level != "L1":
            problems.append(f"{eid} 位于外网但数据等级为 {ep.max_data_level}（外网只允许 L1）")

    if problems:
        print("✗ 端点登记表与代码不一致：")
        for p in problems:
            print("  -", p)
        return 1
    print(f"✓ {len(ENDPOINTS)} 个端点，文档与代码逐字段一致；外网端点数据等级均为 L1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
