"""隐私脱敏服务：字段识别、令牌化、出域扫描。

三条硬约束：
1. 不调用任何模型。模型会漏识别、会误改写、会被提示注入操纵。
2. 识别顺序按特异性从强到弱（证件号 → 卡号 → 手机号 → 金额 → 日期 → 商户 → 姓名），
   否则 18 位证件号会被 16-19 位卡号规则抢先命中。
3. 任一环节异常即抛错，由调用方 fail-closed，绝不返回"部分脱敏"的结果。
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from common.crypto import unseal

# 令牌形态：NAME_001 / CARD_002。出域扫描时需要先把令牌摘掉，
# 否则令牌里的数字会触发残留扫描的误报。
TOKEN_RE = re.compile(r"\b(?:NAME|CARD|PHONE|ID|AMT|DATE|MERCHANT|ACCT|TXN)_\d{3,}\b")

_ID = re.compile(r"\b\d{17}[\dXx]\b")
_CARD = re.compile(r"\b\d{16,19}\b")
_PHONE = re.compile(r"\b1[3-9]\d{9}\b")
_AMOUNT = re.compile(r"[¥￥]\s?\d[\d,]*(?:\.\d{1,2})?|\b\d[\d,]*(?:\.\d{1,2})?\s*元")
_DATE = re.compile(r"\b\d{4}-\d{2}-\d{2}(?:\s\d{2}:\d{2})?\b|\b\d{1,2}月\d{1,2}日\b")
_MERCHANT = re.compile(r"\bM-\d{3,5}\b")

_ORDER = [
    ("ID", _ID),
    ("CARD", _CARD),
    ("PHONE", _PHONE),
    ("AMOUNT", _AMOUNT),
    ("DATE", _DATE),
    ("MERCHANT", _MERCHANT),
]


@dataclass
class MaskResult:
    text: str
    tokens: list[tuple[str, str, str]] = field(default_factory=list)  # (token, field_type, real)
    counts: dict[str, int] = field(default_factory=dict)


class PrivacyService:
    def __init__(self, known_names: list[str]):
        # 姓名不做通用 NER，只做已知客户名精确匹配——PoC 阶段可控且零误伤
        self._names = [n for n in known_names if n]
        self._name_re = (
            re.compile("|".join(re.escape(n) for n in sorted(self._names, key=len, reverse=True)))
            if self._names
            else None
        )

    def mask(self, text: str, request_id: str) -> MaskResult:
        """把原始文本转为只含令牌的文本，并返回令牌映射（真实值由调用方加密落盘）。"""
        if not isinstance(text, str) or not text.strip():
            raise ValueError("待脱敏文本为空，拒绝继续")

        tokens: list[tuple[str, str, str]] = []
        counters: dict[str, int] = {}
        mapping: dict[tuple[str, str], str] = {}

        def repl_factory(field_type: str):
            def _repl(m: re.Match) -> str:
                real = m.group(0)
                key = (field_type, real)
                if key not in mapping:
                    counters[field_type] = counters.get(field_type, 0) + 1
                    tok = f"{field_type}_{counters[field_type]:03d}"
                    mapping[key] = tok
                    tokens.append((tok, field_type, real))
                return mapping[key]

            return _repl

        out = text
        for field_type, pattern in _ORDER:
            out = pattern.sub(repl_factory(field_type), out)

        if self._name_re is not None:
            out = self._name_re.sub(repl_factory("NAME"), out)

        # 自检：脱敏后再扫一遍，仍有原始形态说明规则有漏，直接阻断
        residual = self.scan_text(out)
        if residual:
            raise ValueError(f"脱敏自检未通过，残留: {residual}")

        return MaskResult(text=out, tokens=tokens, counts=dict(counters))

    # ---------- 出域扫描 ----------

    def scan_text(self, text: str) -> list[str]:
        """对已序列化的载荷做残留扫描。先摘令牌，再找原始形态。"""
        findings: list[str] = []
        stripped = TOKEN_RE.sub(" ", text)

        for label, pattern in (
            ("证件号残留", _ID),
            ("卡号残留", _CARD),
            ("手机号残留", _PHONE),
        ):
            m = pattern.search(stripped)
            if m:
                v = m.group(0)
                findings.append(f"{label}:{v[:4]}{'*' * max(0, len(v) - 8)}{v[-4:] if len(v) > 8 else ''}")

        for name in self._names:
            if name in stripped:
                findings.append(f"姓名明文残留:{name[0]}**")

        if "元" in stripped or "¥" in stripped or "￥" in stripped:
            m = _AMOUNT.search(stripped)
            if m:
                findings.append("金额残留:已脱敏规则未覆盖")
        return findings

    def scan_payload(self, payload: dict) -> list[str]:
        import json

        return self.scan_text(json.dumps(payload, ensure_ascii=False))

    # ---------- 业务判据（v1.5.1 新增） ----------
    _CALLBACK = re.compile(r"回拨|回访")

    def judge(self, text: str, note: str | None = None) -> dict | None:
        """隐私三级判据：判「人有没有把原始标识贴进业务文本」，不判业务库取来的字段。

        T1  命中 18 位证件号                         → BLOCKED（禁止复原 + 转人工）
        T1' 补充说明（note）里出现完整卡号            → BLOCKED（人工把原文贴进了业务文本）
        T2  要求回拨/回访且给了完整手机号             → HUMAN_HANDOFF（外呼需二次授权）

        为什么不判正文里的卡号/手机号：A 组案例的正文本来就有合成卡号与手机号
        （来自业务库、按最小权限取得），判正文会把 A 组全部误杀。
        真正的风险是「人把原始标识粘进了业务文本」，所以卡号只判 note。
        """
        text = text or ""
        if _ID.search(text):
            return {"status": "BLOCKED", "code": "PRIVACY_ID_NUMBER", "severity": "critical",
                    "msg": "命中 18 位证件号，禁止复原并转人工"}
        if note and _CARD.search(note):
            return {"status": "BLOCKED", "code": "PRIVACY_RAW_CARD_IN_NOTE", "severity": "critical",
                    "msg": "补充说明中出现完整卡号，禁止复原并转人工"}
        if self._CALLBACK.search(text) and _PHONE.search(text):
            return {"status": "HUMAN_HANDOFF", "code": "CALLBACK_REQUIRES_AUTH", "severity": "medium",
                    "msg": "外呼回访需二次授权，转人工"}
        return None


def restore_tokens(text: str, token_rows: list[dict], data_key: str) -> tuple[str, list[str]]:
    """按令牌映射回填真实值。调用方必须先完成三元匹配校验。"""
    used: list[str] = []
    out = text
    for row in sorted(token_rows, key=lambda r: -len(r["token"])):
        if row["token"] in out:
            out = out.replace(row["token"], unseal(row["sealed_value"], data_key))
            used.append(row["token"])
    return out, used
