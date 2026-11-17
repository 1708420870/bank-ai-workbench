# audit · 审计导出样本

| 文件 | 内容 |
|---|---|
| `audit-export-all-*.json` | 全量事件（含 trace_id/actor/detail），供审计抽样 |
| `audit-export-all-*.csv` | 同上 CSV，便于 Excel 复核 |

样本特征（2026-11-17 导出）：449 条事件 / 50 类事件 / **PII 命中 0** / **trace 空值 0**。
覆盖事件：`EGRESS_ACCEPTED`、`EGRESS_DENIED`、`TOKENIZED`、`RESTORED`、`RESTORE_DENIED`、
`ADJUDICATED`、`ON_BEHALF`、`MCP_CALL`、`MCP_DENIED`、`RATE_LIMITED`、
`DRAFT_APPROVED`、`GATE_CHECKED`、`DRAFT_PUBLISHED`、`DRAFT_ROLLBACK`、`MFA_*`。

复验：`python tools/audit_export.py --data-dir data_test`
