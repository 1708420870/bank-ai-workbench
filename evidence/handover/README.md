# handover · 换人接手证据

| 文件 | 性质 | 可否作 M10 证据 |
|---|---|---|
| `接手演练记录-20261117-165732.md/.json` | 交付方自测（executor-role=self-test） | **不可**（记录自带水印） |
| `screenshots/` | 待接手人补 H1–H5 | — |

**关闭条件**：由未参与开发人员执行
`python tools/handover_drill.py --operator "<真实姓名>" --executor-role independent`
→ 8/8 PASS、耗时 ≤45 分钟、`usable_as_audit_evidence=true`、记录表签字齐备。

当前状态：**M10 未关闭**。
