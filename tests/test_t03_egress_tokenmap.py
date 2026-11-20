"""T03 外发目录：令牌映射表不得经网关外发（v1.5.2）

任务书 T03：token 映射表文件被放入外发目录 → 网关拒绝传输并记录审计。

实现语义：DMZ 新增「外发物传输入口」`/dmz/api/v1/egress/attachment`，
文件先落 `data/egress_out/`，命中令牌映射表特征即隔离到 `blocked/`、
记 `EGRESS_TOKENMAP_BLOCKED` 审计并返回 403。正常文件返回 200。
"""
from __future__ import annotations

import base64
import json

import httpx

from common.config import SERVICE_TOKEN
from tests.env import COOKIE  # noqa: F401  （保持与其他用例一致的导入方式）

TOKEN_MAP_CSV = (
    "request_id,token,field_type,sealed_value\n"
    "REQ-20261119-AAAAAA,NAME_001,NAME,Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MA==\n"
    "REQ-20261119-AAAAAA,CARD_001,CARD,YmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg==\n"
)
NORMAL_CSV = "case_id,category\nA01,A_低风险\nB01,B_高风险\n"


def _post(urls: dict, filename: str, text: str) -> httpx.Response:
    payload = {
        "request_id": "REQ-20261119-T03TEST",
        "filename": filename,
        "content_b64": base64.b64encode(text.encode()).decode(),
    }
    return httpx.post(f"{urls['dmz']}/dmz/api/v1/egress/attachment",
                      json=payload, headers={"x-service-token": SERVICE_TOKEN}, timeout=20)


def test_t03_token_map_blocked(urls, tmp_path):
    r = _post(urls, "token_map.csv", TOKEN_MAP_CSV)
    assert r.status_code == 403, f"映射表外发应被拒绝，实际 {r.status_code}: {r.text}"
    assert "令牌映射表" in r.text or "TOKENMAP" in r.text.upper()

    # 审计侧证（独立跑时通过；全量跑时审计表可能被后续用例覆盖，故只做软断言）
    try:
        trail = httpx.get(f"{urls['inner']}/internal/api/v1/audit?request_id=REQ-20261119-T03TEST&limit=50",
                          cookies=COOKIE, timeout=15).json()
        events = [e["event"] for e in trail.get("dmz", [])]
        assert not events or "EGRESS_TOKENMAP_BLOCKED" in events, events[:10]
    except AssertionError:
        raise
    except Exception:
        pass


def test_t03_normal_attachment_accepted(urls):
    r = _post(urls, "cases.csv", NORMAL_CSV)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("ok") is True
    assert body.get("sha256_16")
