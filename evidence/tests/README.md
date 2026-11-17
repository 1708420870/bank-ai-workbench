# tests · 测试与压测证据

| 文件 | 内容 |
|---|---|
| `回归测试-*.txt` | 全量 pytest 输出（90 passed / 0 failed） |
| `限流压测-*.json` | MCP 网关限流实测（45 请求 → 30×200 + 15×429） |

复验：
```bash
python -m pytest tests/ -q
python tools/rate_limit_drill.py --n 45 --concurrency 5
```
