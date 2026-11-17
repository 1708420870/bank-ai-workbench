# screenshots · 截图与录屏清单

> 状态：**未采集**（需现场人工操作录制）。清单先定死，避免验收时"拍了但没覆盖"。

## 必拍清单

| 编号 | 内容 | 对应条款 | 文件名 |
|---|---|---|---|
| S1 | 坐席登录页（含 MFA 输入框出现的一次） | C1 | S1-login-mfa.png |
| S2 | 工单详情：AI 建议 + 出域快照（令牌形态） | A1/C3 | S2-ticket-masked.png |
| S3 | 复原后真实值（三元匹配成功） | C3 | S3-restored.png |
| S4 | 人工四动作（采纳/修改/转人工/驳回） | B5 | S4-confirm.png |
| S5 | 管理端·变更审批（状态机 + 门槛结果弹窗） | C10 | S5-change-pipeline.png |
| S6 | 管理端·运行观测（8 指标） | C9 | S6-observe.png |
| S7 | 审计导出（单 request_id 六要素） | D4 | S7-audit.png |
| S8 | MCP 禁止工具被拒（404/403 响应） | D3 | S8-mcp-denied.png |
| S9 | 限流 429 与 RATE_LIMITED 审计 | C6 | S9-rate-limit.png |
| S10 | 回滚前后状态对比 | M16 | S10-rollback.png |
| B1–B5 | 五类禁止操作被拒绝的连续录屏（30–60s） | D3 | B{n}-denied.mp4 |

## 命名与存放
- 全部放本目录，按上表命名；
- 录屏不超过 90 秒，保留声音（讲解）；
- 截图必须包含**浏览器地址栏或时间戳**，否则无法证明环境。
