"""运行日志：与审计日志双轨分离的工程运维通道。

职责区分（软件工程中的横切关注点分离）：
- 审计（common/audit.py）：面向合规取证。只记业务元数据、强制脱敏、
  落各分区独立 SQLite，记录不可删改。
- 运行日志（本模块）：面向工程排障。记程序运行事件（启动、模型降级、
  异常栈），JSON Lines 格式落 data/logs/<zone>.log，可按天清理。

两条通道互不替代：审计回答"业务上发生了什么"，运行日志回答"程序为什么
出现这个行为"。排障时以 request_id / trace_id 关联两路证据。
"""
from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any

from .config import APP_VERSION, LOG_DIR

_LEVELS: dict[str, int] = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
}
LOG_LEVEL = _LEVELS.get(os.getenv("LOG_LEVEL", "info").lower(), logging.INFO)


class JsonFormatter(logging.Formatter):
    """JSON Lines 格式化：每行一个自包含 JSON 对象，机器可解析。"""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).astimezone().isoformat(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "zone": getattr(record, "zone", "app"),
            "logger": record.name,
            "event": record.getMessage(),
            "version": APP_VERSION,
        }
        data = getattr(record, "extra_data", None)
        if data is not None:
            payload["data"] = data
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


def _build(zone: str, name: str) -> logging.Logger:
    logger = logging.getLogger(f"{zone}.{name}")
    if logger.handlers:  # 已初始化，直接复用（模块可重复导入）
        return logger
    logger.setLevel(LOG_LEVEL)
    handler = logging.FileHandler(LOG_DIR / f"{zone}.log", encoding="utf-8")
    handler.setFormatter(JsonFormatter())
    logger.addHandler(handler)
    logger.propagate = False
    return logger


def get(zone: str, name: str = "app") -> logging.Logger:
    """取分区运行日志器。zone ∈ {inner, dmz, outer, desktop}。"""
    return _build(zone, name)


def console(zone: str, name: str = "boot") -> logging.Logger:
    """控制台日志器：桌面端启动阶段无文件查看条件，同步输出到 stdout。"""
    logger = _build(zone, name)
    if not any(isinstance(h, logging.StreamHandler) and not isinstance(h, logging.FileHandler)
               for h in logger.handlers):
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(JsonFormatter())
        logger.addHandler(h)
    return logger
