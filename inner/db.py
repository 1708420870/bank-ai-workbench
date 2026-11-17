"""内网唯一数据库：客户原始数据、规则、令牌映射、工单、审计。

关键设计：token_map 的真实值加密落盘；外网与 DMZ 的代码里没有这个路径，
也没有连它的连接串。T12 的"外网直连内网库"因此在实现层面无从发生。
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Iterator

from common.config import DATA_KEY, db_path
from common.crypto import seal

_DDL = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS employees (
    emp_id TEXT PRIMARY KEY, name TEXT, role TEXT
);
CREATE TABLE IF NOT EXISTS customers (
    customer_id TEXT PRIMARY KEY, name TEXT, card_no TEXT, phone TEXT, id_no TEXT
);
CREATE TABLE IF NOT EXISTS transactions (
    txn_id TEXT PRIMARY KEY, customer_id TEXT, ts TEXT, amount REAL, merchant TEXT, status TEXT
);
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY, customer_id TEXT, txn_id TEXT,
    category TEXT, intent TEXT, narrative TEXT, fault TEXT
);
CREATE TABLE IF NOT EXISTS rules (
    rule_id TEXT PRIMARY KEY, version TEXT, domain TEXT, title TEXT,
    summary TEXT, full_text TEXT, mandatory_human INTEGER,
    effective_from TEXT, status TEXT, source TEXT
);
CREATE TABLE IF NOT EXISTS token_map (
    request_id TEXT, token TEXT, field_type TEXT, sealed_value TEXT,
    created_at TEXT, PRIMARY KEY (request_id, token)
);
CREATE TABLE IF NOT EXISTS tickets (
    request_id TEXT PRIMARY KEY, session_id TEXT, emp_id TEXT, case_id TEXT,
    status TEXT, intent TEXT, decision TEXT, reason_codes TEXT,
    agent_version TEXT, model_supplier TEXT, model_version TEXT,
    rule_ids TEXT, outbound_snapshot TEXT, agent_output TEXT,
    restored_text TEXT, created_at TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS restore_log (
    request_id TEXT, session_id TEXT, emp_id TEXT, ts TEXT, fields TEXT
);
CREATE TABLE IF NOT EXISTS changes (
    change_id TEXT PRIMARY KEY, kind TEXT, owner TEXT, purpose TEXT,
    status TEXT, payload TEXT, created_at TEXT,
    reviewer TEXT, reviewed_at TEXT, review_note TEXT,
    gate TEXT, gate_at TEXT, gate_passed INTEGER,
    published_version TEXT, published_at TEXT,
    rollback_reason TEXT, rolled_back_at TEXT
);
CREATE TABLE IF NOT EXISTS users (
    emp_id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, pwd_hash TEXT NOT NULL,
    role TEXT NOT NULL, portal TEXT NOT NULL, active INTEGER DEFAULT 1,
    totp_secret TEXT, totp_pending TEXT, totp_enabled_at TEXT,
    failed_n INTEGER DEFAULT 0, locked_until TEXT, last_login TEXT,
    must_change_pwd INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS notices (
    notice_id TEXT PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL,
    level TEXT DEFAULT 'normal', sender_emp_id TEXT NOT NULL,
    created_at TEXT, revoked INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS notice_reads (
    notice_id TEXT NOT NULL, emp_id TEXT NOT NULL, read_at TEXT,
    PRIMARY KEY (notice_id, emp_id)
);
CREATE TABLE IF NOT EXISTS leaves (
    leave_id TEXT PRIMARY KEY, emp_id TEXT NOT NULL,
    start_date TEXT NOT NULL, end_date TEXT NOT NULL,
    reason TEXT NOT NULL, status TEXT DEFAULT 'PENDING',
    reviewer_emp_id TEXT, review_comment TEXT,
    created_at TEXT, reviewed_at TEXT
);
CREATE TABLE IF NOT EXISTS dms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_emp_id TEXT NOT NULL, receiver_emp_id TEXT NOT NULL,
    body TEXT NOT NULL, created_at TEXT, read_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_dms_receiver ON dms(receiver_emp_id, read_at);
CREATE INDEX IF NOT EXISTS idx_dms_pair ON dms(sender_emp_id, receiver_emp_id);
CREATE INDEX IF NOT EXISTS idx_token_req ON token_map(request_id);
CREATE INDEX IF NOT EXISTS idx_notice_reads_emp ON notice_reads(emp_id);
CREATE INDEX IF NOT EXISTS idx_leaves_emp ON leaves(emp_id);
CREATE TABLE IF NOT EXISTS feedback_tickets (
    fb_id TEXT PRIMARY KEY, openid_hash TEXT NOT NULL, category TEXT NOT NULL,
    body_masked TEXT NOT NULL, status TEXT DEFAULT 'SUBMITTED',
    ai_reply TEXT, assigned_emp TEXT, satisfaction INTEGER,
    created_at TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS feedback_replies (
    rid TEXT PRIMARY KEY, fb_id TEXT NOT NULL, sender TEXT NOT NULL,
    body_masked TEXT NOT NULL, rule_verdict TEXT,
    created_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_fb_openid ON feedback_tickets(openid_hash);
CREATE INDEX IF NOT EXISTS idx_fb_replies ON feedback_replies(fb_id);
CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY, emp_id TEXT NOT NULL, role TEXT NOT NULL, portal TEXT NOT NULL,
    created_at TEXT, expires_at TEXT, revoked INTEGER DEFAULT 0, ip TEXT, ua TEXT
);
CREATE INDEX IF NOT EXISTS idx_token_req ON token_map(request_id);
"""

_EMPLOYEES = [
    ("A001", "苏总", "supervisor"),
    ("T001", "科技开发", "developer"),
    ("B001", "小梁", "agent"),
    ("B002", "小杨", "agent"),
    ("B003", "小刘", "agent"),
    ("B004", "小黄", "agent"),
]

_CUSTOMERS = [
    ("C001", "张示例", "6222000000000001", "13800138001", "110101199001011231"),
    ("C002", "李合成", "6222000000000002", "13800138002", "110101199002021232"),
    ("C003", "王样测", "6222000000000003", "13800138003", "110101199003031233"),
    ("C004", "赵虚构", "6222000000000004", "13800138004", "110101199004041234"),
    ("C005", "陈测试", "6222000000000005", "13800138005", "110101199005051235"),
    ("C006", "刘模拟", "6222000000000006", "13800138006", "110101199006061236"),
]

_TRANSACTIONS = [
    ("TXN-88001", "C001", "2026-11-10 14:22", 3280.00, "M-8842 线上商户", "已入账"),
    ("TXN-88002", "C002", "2026-11-09 09:05", 128.50, "M-1120 便利店", "已入账"),
    ("TXN-88003", "C003", "2026-11-08 20:41", 15600.00, "M-7703 数码专营", "待结算"),
    ("TXN-88004", "C004", "2026-11-07 11:18", 49.90, "M-2210 餐饮", "已入账"),
    ("TXN-88005", "C005", "2026-11-06 16:30", 890.00, "M-5511 百货", "已入账"),
    ("TXN-88006", "C006", "2026-11-05 08:12", 230.00, "M-3390 加油站", "已入账"),
]

_CASES = [
    ("A01", "C001", "TXN-88001", "A_低风险", "DISPUTE_PROCESS",
     "客户 张示例 来电，询问如何对卡号 6222000000000001 的一笔消费发起争议，需要准备哪些材料。联系电话 13800138001。", None),
    ("A02", "C002", "TXN-88002", "A_低风险", "DISPUTE_PROCESS",
     "客户 李合成 咨询争议处理的时限与进度查询方式，卡号 6222000000000002。", None),
    ("A03", "C003", "TXN-88003", "A_低风险", "TRANSACTION_QUERY",
     "客户 王样测 询问卡号 6222000000000003 上一笔金额 15600.00 元的交易当前状态。", None),
    ("A04", "C004", "TXN-88004", "A_低风险", "TRANSACTION_QUERY",
     "客户 赵虚构 询问上月账单中商户 M-2210 一笔 49.90 元扣款的摘要信息。", None),
    ("B01", "C001", "TXN-88001", "B_高风险", "SUSPECTED_UNAUTHORIZED",
     "客户 张示例 称卡片一直在本人身边，但卡号 6222000000000001 出现一笔 3280.00 元陌生消费，要求立即处理。", None),
    ("B02", "C005", "TXN-88005", "B_高风险", "SUSPECTED_UNAUTHORIZED",
     "客户 陈测试 表示连续收到三条未授权扣款通知，卡号 6222000000000005，情绪激动。联系电话 13800138005。", None),
    ("B03", "C006", "TXN-88006", "B_高风险", "PENDING_CONFIRM",
     "客户 刘模拟 描述含糊，只说「那个钱不对」，无法判断是要查交易还是发起争议，卡号 6222000000000006。", None),
    ("B04", "C002", "TXN-88002", "B_高风险", "PENDING_CONFIRM",
     "客户 李合成 提到两个渠道给出的处理口径不一致，要求给出确定结论。", None),
    ("C01", "C001", "TXN-88001", "C_隐私故障", "TRANSACTION_QUERY",
     "客户 张示例 办理查询，客服在备注中粘贴了完整身份信息 110101199001011231 与卡号 6222000000000001。", None),
    ("C02", "C002", "TXN-88002", "C_隐私故障", "DISPUTE_PROCESS",
     "客户 李合成 来电，回拨号码 13800138002，要求回访，并提及姓名与卡号 6222000000000002。", None),
    ("C03", "C003", "TXN-88003", "C_隐私故障", "TRANSACTION_QUERY",
     "客户 王样测 查询交易，上游模型响应超时的场景演练。", "timeout"),
    ("C04", "C004", "TXN-88004", "C_隐私故障", "TRANSACTION_QUERY",
     "客户 赵虚构 查询交易，上游返回结构非法的场景演练。", "bad_json"),
]

# 账号目录：role 决定能进哪个入口。portal=client 只能进坐席工作台，
# portal=admin 只能进管理端。密码在 init 时派生，明文不落库、不落日志。
_ACCOUNTS = [
    ("A001", "a001", "abc123456", "supervisor", "admin"),
    ("T001", "t001", "Tech@2026", "developer", "admin"),
    ("B001", "b001", "abc122333", "agent", "client"),
    ("B002", "b002", "abc122333", "agent", "client"),
    ("B003", "b003", "abc122333", "agent", "client"),
    ("B004", "b004", "abc122333", "agent", "client"),
]

_RULES = [
    ("R-DISPUTE-01", "v1.2", "dispute", "争议受理渠道",
     "争议须由客户通过 App「我的-交易争议」提交，需交易凭证与身份核验",
     "争议须由客户本人通过官方渠道提交申请，客服仅可指引路径，不得代为提交，不得承诺处理时限。", 0,
     "2026-09-01", "active"),
    ("R-DISPUTE-02", "v1.0", "dispute", "争议材料清单",
     "需提供交易时间、金额、商户与争议原因",
     "受理争议需采集：交易时间、交易金额、商户名称、争议原因、客户联系方式。材料不全时应先补齐。", 0,
     "2026-09-01", "active"),
    ("R-TXN-01", "v1.3", "txn", "交易查询指引",
     "指引客户在 App 交易明细中查询，不得朗读完整卡号",
     "交易信息查询应指引客户自助查看；确需口述核对时仅可提供卡号后四位。", 0,
     "2026-10-15", "active"),
    ("R-TXN-02", "v1.1", "txn", "交易状态口径",
     "交易状态以核心系统为准，客服不得自行判定入账",
     "任何交易状态结论必须以核心系统返回为准；对「待结算」不得表述为「已到账」。", 0,
     "2026-10-15", "active"),
    ("R-UNAUTH-01", "v2.0", "risk", "疑似未授权强制人工",
     "疑似未授权交易必须进入人工核查",
     "凡客户主张交易非本人授权的，一律转人工风控核查，禁止自动回复处理结论，禁止承诺赔付。", 1,
     "2026-11-01", "active"),
    ("R-UNAUTH-02", "v1.4", "risk", "疑似未授权处置顺序",
     "先临时冻结，再转风控，不得承诺赔付",
     "处置顺序：①建议客户临时冻结卡片 ②转风控工单 ③告知后续核查流程。不得承诺具体赔付金额或时限。", 0,
     "2026-11-01", "active"),
    ("R-PENDING-01", "v1.0", "routing", "意图不明确必须转人工",
     "意图无法确定时不得由模型猜测",
     "当客户陈述不足以判定意图类别时，必须转人工，禁止模型自行归类后自动回复。", 1,
     "2026-10-01", "active"),
    ("R-PENDING-02", "v1.0", "routing", "规则冲突处置",
     "规则版本冲突时冻结自动回复",
     "出现规则版本冲突或渠道口径不一致时，冻结自动回复并转规则管理员确认。", 0,
     "2026-10-01", "active"),
]


def connect() -> sqlite3.Connection:
    c = sqlite3.connect(db_path("inner"), timeout=10)
    c.row_factory = sqlite3.Row
    return c


@contextmanager
def conn() -> Iterator[sqlite3.Connection]:
    """读写连接上下文：退出时提交未决事务并关闭连接。

    注意：sqlite3 的 `with connection:` 只管提交/回滚、**不关闭连接**，
    直接用连接对象做上下文会泄漏句柄。所有短连接读写一律走本上下文。
    """
    c = connect()
    try:
        with c:  # 事务提交/回滚交给 sqlite3 驱动
            yield c
    finally:
        c.close()


@contextmanager
def tx() -> Iterator[sqlite3.Connection]:
    """显式写事务边界（BEGIN IMMEDIATE）：多语句写操作必须整体原子。

    事务边界是架构约束而不是实现细节：凡是要么全成功、要么全回滚的
    业务不变量（如"重置口令 + 吊销全部会话"），都必须用本上下文声明。
    单条写语句无需显式事务（SQLite 单语句本身原子）。
    """
    c = connect()
    try:
        c.execute("BEGIN IMMEDIATE")  # 写锁提前获取，避免竞争时升级死锁
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()


def init(reset: bool = False) -> None:
    p: Path = db_path("inner")
    if reset and p.exists():
        for suffix in ("", "-wal", "-shm"):
            f = Path(str(p) + suffix)
            if f.exists():
                f.unlink()
    with tx() as c:
        c.executescript(_DDL)
        _ensure_columns(c)
        # 账号种子改为逐条幂等补齐：新版本新增的账号（如 t001）能在老库上增量生效，
        # 已存在的账号不动（不覆盖用户改过的口令）
        if _ACCOUNTS:
            from .auth import hash_password  # 延迟导入：auth 也在本包内导入 db
            for e, u, p, r, po in _ACCOUNTS:
                if not c.execute("SELECT 1 FROM employees WHERE emp_id=?", (e,)).fetchone():
                    name = next((n for eid, n, _ in _EMPLOYEES if eid == e), e)
                    c.execute("INSERT OR IGNORE INTO employees VALUES (?,?,?)", (e, name, r))
                c.execute("INSERT OR IGNORE INTO users (emp_id, username, pwd_hash, role, portal)"
                          " VALUES (?,?,?,?,?)", (e, u, hash_password(p), r, po))
        seeded = c.execute("SELECT COUNT(*) n FROM customers").fetchone()["n"]
        if seeded:
            return
        c.executemany("INSERT OR IGNORE INTO employees VALUES (?,?,?)", _EMPLOYEES)
        c.executemany("INSERT INTO customers VALUES (?,?,?,?,?)", _CUSTOMERS)
        c.executemany("INSERT INTO transactions VALUES (?,?,?,?,?,?)", _TRANSACTIONS)
        c.executemany("INSERT INTO cases VALUES (?,?,?,?,?,?,?)", _CASES)
        c.executemany("INSERT INTO rules (rule_id, version, domain, title, summary, full_text,"
                      " mandatory_human, effective_from, status) VALUES (?,?,?,?,?,?,?,?,?)", _RULES)
        # 种子规则的出处（C2）：PoC 用合成规则，出处在 UI/接口里如实标注
        c.execute("UPDATE rules SET source=? WHERE source IS NULL",
                  ("行内业务规则库（PoC 合成件，非生产规则）",))


def _ensure_columns(c: sqlite3.Connection) -> None:
    """对既有库做增量迁移：新版本新增的列在这里补齐，老库不重建。"""
    user_cols = {r["name"] for r in c.execute("PRAGMA table_info(users)")}
    if "device_id" not in user_cols:
        c.execute("ALTER TABLE users ADD COLUMN device_id TEXT")
    if "must_change_pwd" not in user_cols:
        c.execute("ALTER TABLE users ADD COLUMN must_change_pwd INTEGER DEFAULT 0")
    for col in ("totp_secret", "totp_pending", "totp_enabled_at"):
        if col not in user_cols:
            c.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT")
    sess_cols = {r["name"] for r in c.execute("PRAGMA table_info(sessions)")}
    if "device_id" not in sess_cols:
        c.execute("ALTER TABLE sessions ADD COLUMN device_id TEXT")
    # 变更审批流水线（v1.4.3）：草稿从"只入库"升级为"可审批/发布/回滚"的状态机，
    # 老库在此增量补列，不重建表（重建会丢历史草稿）。
    rule_cols = {r["name"] for r in c.execute("PRAGMA table_info(rules)")}
    if "source" not in rule_cols:
        # C2 要求规则可"出处可查"：老库补列后，未填 source 的规则一律显示"出处未登记"，
        # 而不是假装有出处——空缺本身也是审计要看的信息。
        c.execute("ALTER TABLE rules ADD COLUMN source TEXT")
    chg_cols = {r["name"] for r in c.execute("PRAGMA table_info(changes)")}
    for col, ddl in (
        ("reviewer", "TEXT"), ("reviewed_at", "TEXT"), ("review_note", "TEXT"),
        ("gate", "TEXT"), ("gate_at", "TEXT"), ("gate_passed", "INTEGER"),
        ("published_version", "TEXT"), ("published_at", "TEXT"),
        ("rollback_reason", "TEXT"), ("rolled_back_at", "TEXT"),
    ):
        if col not in chg_cols:
            c.execute(f"ALTER TABLE changes ADD COLUMN {col} {ddl}")


# ---------- 读接口 ----------

def employee(emp_id: str) -> dict | None:
    with conn() as c:
        r = c.execute("SELECT * FROM employees WHERE emp_id=?", (emp_id,)).fetchone()
        return dict(r) if r else None


def list_cases() -> list[dict]:
    with conn() as c:
        rows = c.execute(
            "SELECT case_id, customer_id, txn_id, category, intent, narrative, fault FROM cases ORDER BY case_id"
        ).fetchall()
        return [dict(r) for r in rows]


def get_case(case_id: str) -> dict | None:
    with conn() as c:
        r = c.execute("SELECT * FROM cases WHERE case_id=?", (case_id,)).fetchone()
        return dict(r) if r else None


def customer(cid: str) -> dict | None:
    with conn() as c:
        r = c.execute("SELECT * FROM customers WHERE customer_id=?", (cid,)).fetchone()
        return dict(r) if r else None


def transaction(tid: str) -> dict | None:
    with conn() as c:
        r = c.execute("SELECT * FROM transactions WHERE txn_id=?", (tid,)).fetchone()
        return dict(r) if r else None


def all_customers() -> list[dict]:
    with conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM customers")]


def rules_for(intent: str) -> list[dict]:
    domain = {
        "DISPUTE_PROCESS": "dispute",
        "TRANSACTION_QUERY": "txn",
        "SUSPECTED_UNAUTHORIZED": "risk",
        "PENDING_CONFIRM": "routing",
    }.get(intent)
    with conn() as c:
        if domain:
            rows = c.execute(
                "SELECT * FROM rules WHERE domain=? AND status='active' ORDER BY rule_id", (domain,)
            ).fetchall()
        else:
            rows = []
        return [dict(r) for r in rows]


def rule(rule_id: str) -> dict | None:
    with conn() as c:
        r = c.execute("SELECT * FROM rules WHERE rule_id=?", (rule_id,)).fetchone()
        return dict(r) if r else None


def all_rules() -> list[dict]:
    with conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM rules ORDER BY rule_id")]


# ---------- 令牌映射 ----------

def put_tokens(request_id: str, items: list[tuple[str, str, str]], ts: str) -> None:
    """items: [(token, field_type, real_value)]，真实值加密后落盘。"""
    with conn() as c:
        c.executemany(
            "INSERT OR REPLACE INTO token_map (request_id, token, field_type, sealed_value, created_at)"
            " VALUES (?,?,?,?,?)",
            [(request_id, tok, ft, seal(val, DATA_KEY), ts) for tok, ft, val in items],
        )


def tokens_of(request_id: str) -> list[dict]:
    with conn() as c:
        rows = c.execute(
            "SELECT token, field_type, sealed_value FROM token_map WHERE request_id=?", (request_id,)
        ).fetchall()
        return [dict(r) for r in rows]


# ---------- 工单 ----------

def save_ticket(**kw: Any) -> None:
    cols = ",".join(kw.keys())
    marks = ",".join("?" * len(kw))
    with conn() as c:
        c.execute(f"INSERT OR REPLACE INTO tickets ({cols}) VALUES ({marks})", tuple(kw.values()))


def ticket(request_id: str) -> dict | None:
    with conn() as c:
        r = c.execute("SELECT * FROM tickets WHERE request_id=?", (request_id,)).fetchone()
        return dict(r) if r else None


def list_tickets(limit: int = 50, emp_id: str | None = None) -> list[dict]:
    with conn() as c:
        if emp_id:
            rows = c.execute(
                "SELECT * FROM tickets WHERE emp_id=? ORDER BY created_at DESC LIMIT ?",
                (emp_id, limit),
            ).fetchall()
        else:
            rows = c.execute("SELECT * FROM tickets ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]


def log_restore(request_id: str, session_id: str, emp_id: str, ts: str, fields: list[str]) -> None:
    with conn() as c:
        c.execute(
            "INSERT INTO restore_log (request_id, session_id, emp_id, ts, fields) VALUES (?,?,?,?,?)",
            (request_id, session_id, emp_id, ts, json.dumps(fields, ensure_ascii=False)),
        )


# ---------- 变更草稿区 ----------

def add_change(change_id: str, kind: str, owner: str, purpose: str, payload: dict, ts: str) -> None:
    with conn() as c:
        c.execute(
            "INSERT INTO changes (change_id, kind, owner, purpose, status, payload, created_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (change_id, kind, owner, purpose, "PENDING_REVIEW", json.dumps(payload, ensure_ascii=False), ts),
        )


def get_change(change_id: str) -> dict | None:
    with conn() as c:
        r = c.execute("SELECT * FROM changes WHERE change_id=?", (change_id,)).fetchone()
        return dict(r) if r else None


def all_changes(limit: int = 100) -> list[dict]:
    with conn() as c:
        rows = c.execute("SELECT * FROM changes ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]


def set_change(change_id: str, **fields) -> None:
    """状态迁移的唯一写入口。

    刻意不提供"直接改 status"的通用接口——所有迁移都必须经过 app 层的
    状态机校验（谁能改、从什么状态能到什么状态），DB 层只负责落字段。
    """
    if not fields:
        return
    cols = ", ".join(f"{k}=?" for k in fields)
    with conn() as c:
        c.execute(f"UPDATE changes SET {cols} WHERE change_id=?", (*fields.values(), change_id))


def set_user_fields(emp_id: str, **fields) -> None:
    """更新用户的安全属性（MFA 密钥等）。只允许白名单列，防止被拼 SQL 注入。"""
    allowed = {"totp_secret", "totp_pending", "totp_enabled_at", "must_change_pwd",
               "device_id", "active", "pwd_hash"}
    cols = {k: v for k, v in fields.items() if k in allowed}
    if not cols:
        return
    sql = ", ".join(f"{k}=?" for k in cols)
    with conn() as c:
        c.execute(f"UPDATE users SET {sql} WHERE emp_id=?", (*cols.values(), emp_id))


def totp_state(emp_id: str) -> dict:
    with conn() as c:
        r = c.execute("SELECT totp_secret, totp_pending, totp_enabled_at FROM users WHERE emp_id=?",
                      (emp_id,)).fetchone()
        return dict(r) if r else {}


def published_count(kind: str) -> int:
    """已发布的同类型变更数：用于生成可追溯的版本号（v1/v2/...）。"""
    with conn() as c:
        r = c.execute("SELECT COUNT(*) n FROM changes WHERE kind=? AND status='PUBLISHED'", (kind,)).fetchone()
        return int(r["n"]) if r else 0


# ---------- 账号与会话 ----------

def user_by_username(username: str) -> dict | None:
    with conn() as c:
        r = c.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        return dict(r) if r else None


def user_by_emp_id(emp_id: str) -> dict | None:
    with conn() as c:
        r = c.execute("SELECT * FROM users WHERE emp_id=?", (emp_id,)).fetchone()
        return dict(r) if r else None


def bump_failure(emp_id: str, failed_n: int, locked_until: str | None) -> None:
    with conn() as c:
        c.execute("UPDATE users SET failed_n=?, locked_until=? WHERE emp_id=?",
                  (failed_n, locked_until, emp_id))


def mark_login_ok(emp_id: str) -> None:
    with conn() as c:
        c.execute("UPDATE users SET failed_n=0, locked_until=NULL, last_login=? WHERE emp_id=?",
                  (datetime.now().astimezone().isoformat(timespec="seconds"), emp_id))


def create_session(sid: str, emp_id: str, role: str, portal: str,
                   expires_at: str, ip: str, ua: str, device_id: str = "") -> None:
    with conn() as c:
        c.execute("INSERT INTO sessions (sid, emp_id, role, portal, created_at, expires_at, revoked, ip, ua, device_id)"
                  " VALUES (?,?,?,?,?,?,0,?,?,?)",
                  (sid, emp_id, role, portal,
                   datetime.now().astimezone().isoformat(timespec="seconds"), expires_at, ip, ua, device_id))


def session(sid: str) -> dict | None:
    with conn() as c:
        r = c.execute("SELECT * FROM sessions WHERE sid=?", (sid,)).fetchone()
        return dict(r) if r else None


def revoke_session(sid: str) -> None:
    with conn() as c:
        c.execute("UPDATE sessions SET revoked=1 WHERE sid=?", (sid,))


def extend_session(sid: str, expires_at: str) -> None:
    """滑动续期：活跃会话顺延有效期（仅在 session_of 校验通过后调用）。"""
    with conn() as c:
        c.execute("UPDATE sessions SET expires_at=? WHERE sid=? AND revoked=0",
                  (expires_at, sid))


def revoke_sessions_of(emp_id: str) -> int:
    with conn() as c:
        cur = c.execute("UPDATE sessions SET revoked=1 WHERE emp_id=? AND revoked=0", (emp_id,))
        return cur.rowcount


def revoke_other_sessions(emp_id: str, keep_sid: str) -> int:
    """单会话互踢：保留当前会话，吊销该账号其余活跃会话。"""
    with conn() as c:
        cur = c.execute("UPDATE sessions SET revoked=1 WHERE emp_id=? AND revoked=0 AND sid<>?",
                        (emp_id, keep_sid))
        return cur.rowcount


def set_device_binding(emp_id: str, device_id: str) -> None:
    with conn() as c:
        c.execute("UPDATE users SET device_id=? WHERE emp_id=?", (device_id, emp_id))


def create_user(emp_id: str, username: str, pwd_hash: str, role: str, portal: str, name: str) -> None:
    """管理员开户：初始口令一律标记首登强制改密（生产账号管理惯例）。"""
    with tx() as c:
        c.execute("INSERT OR IGNORE INTO employees (emp_id, name, role) VALUES (?,?,?)",
                  (emp_id, name, role))
        c.execute("INSERT INTO users (emp_id, username, pwd_hash, role, portal, must_change_pwd)"
                  " VALUES (?,?,?,?,?,1)",
                  (emp_id, username, pwd_hash, role, portal))


def set_password(emp_id: str, pwd_hash: str, must_change: bool = True,
                 keep_sid: str | None = None) -> None:
    """重置密码同时清零失败计数与锁定状态。

    must_change=True：管理员重置的初始口令须首登改密（默认）；
    must_change=False：仅用于用户自助改密成功后清除标记。
    keep_sid：自助改密时保留当前会话（否则改完密码立即被踢出）；
    管理员重置不传 keep_sid，全部会话吊销。
    """
    with tx() as c:
        c.execute("UPDATE users SET pwd_hash=?, failed_n=0, locked_until=NULL, must_change_pwd=?"
                  " WHERE emp_id=?",
                  (pwd_hash, 1 if must_change else 0, emp_id))
        # 密码变更意味着旧凭证可能已泄露：其它会话立即失效
        # ——与上一条语句同事务：要么都生效，要么都不生效
        if keep_sid:
            c.execute("UPDATE sessions SET revoked=1 WHERE emp_id=? AND revoked=0 AND sid<>?",
                      (emp_id, keep_sid))
        else:
            c.execute("UPDATE sessions SET revoked=1 WHERE emp_id=? AND revoked=0", (emp_id,))


def live_sessions(limit: int = 100) -> list[dict]:
    with conn() as c:
        rows = c.execute(
            "SELECT s.sid, s.emp_id, e.name, s.role, s.portal, s.created_at, s.expires_at, s.ip"
            " FROM sessions s LEFT JOIN employees e ON e.emp_id = s.emp_id"
            " WHERE s.revoked=0 ORDER BY s.created_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def set_user_active(emp_id: str, active: bool) -> None:
    with tx() as c:
        c.execute("UPDATE users SET active=? WHERE emp_id=?", (1 if active else 0, emp_id))
        if not active:
            c.execute("UPDATE sessions SET revoked=1 WHERE emp_id=?", (emp_id,))


def set_must_change(emp_id: str, enabled: bool) -> None:
    """切换"首登强制改密"标记。开启即吊销活跃会话，让用户重新登录后立即走改密流程。"""
    with tx() as c:
        c.execute("UPDATE users SET must_change_pwd=? WHERE emp_id=?", (1 if enabled else 0, emp_id))
        if enabled:
            c.execute("UPDATE sessions SET revoked=1 WHERE emp_id=? AND revoked=0", (emp_id,))


def list_users() -> list[dict]:
    with conn() as c:
        rows = c.execute(
            "SELECT u.emp_id, e.name, u.username, u.role, u.portal, u.active,"
            " u.failed_n, u.locked_until, u.last_login, u.device_id, u.must_change_pwd"
            " FROM users u LEFT JOIN employees e ON e.emp_id = u.emp_id ORDER BY u.emp_id"
        ).fetchall()
        return [dict(r) for r in rows]


# ---------- OA：通知公告 ----------


def publish_notice(notice_id: str, title: str, body: str, sender_emp_id: str,
                   level: str, ts: str) -> None:
    with conn() as c:
        c.execute("INSERT INTO notices (notice_id, title, body, level, sender_emp_id, created_at)"
                  " VALUES (?,?,?,?,?,?)",
                  (notice_id, title, body, level, sender_emp_id, ts))


def revoke_notice(notice_id: str) -> int:
    """撤回通知：仅未读生效，已读过的保留在用户历史里（合规留痕）。"""
    with conn() as c:
        cur = c.execute("UPDATE notices SET revoked=1 WHERE notice_id=? AND revoked=0", (notice_id,))
        return cur.rowcount


def list_notices(include_revoked: bool = False) -> list[dict]:
    with conn() as c:
        where = "" if include_revoked else "WHERE n.revoked=0"
        rows = c.execute(
            f"SELECT n.*, e.name AS sender_name FROM notices n"
            f" LEFT JOIN employees e ON e.emp_id = n.sender_emp_id {where}"
            f" ORDER BY n.created_at DESC, n.notice_id DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def notices_for(emp_id: str) -> list[dict]:
    """员工视角通知列表：附本人已读时间，未读排前、新在前。"""
    with conn() as c:
        rows = c.execute(
            "SELECT n.notice_id, n.title, n.body, n.level, n.created_at,"
            " e.name AS sender_name, r.read_at"
            " FROM notices n"
            " LEFT JOIN employees e ON e.emp_id = n.sender_emp_id"
            " LEFT JOIN notice_reads r ON r.notice_id = n.notice_id AND r.emp_id = ?"
            " WHERE n.revoked=0"
            " ORDER BY (r.read_at IS NOT NULL), n.created_at DESC, n.notice_id DESC",
            (emp_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def unread_count(emp_id: str) -> int:
    with conn() as c:
        return c.execute(
            "SELECT COUNT(*) n FROM notices n WHERE n.revoked=0 AND NOT EXISTS"
            " (SELECT 1 FROM notice_reads r WHERE r.notice_id=n.notice_id AND r.emp_id=?)",
            (emp_id,),
        ).fetchone()["n"]


def mark_notice_read(notice_id: str, emp_id: str, ts: str) -> int:
    """已读回执：幂等，重复标记不报错也不覆盖首读时间。"""
    with conn() as c:
        cur = c.execute(
            "INSERT OR IGNORE INTO notice_reads (notice_id, emp_id, read_at) VALUES (?,?,?)",
            (notice_id, emp_id, ts),
        )
        return cur.rowcount


def notice_exists(notice_id: str) -> bool:
    with conn() as c:
        return c.execute("SELECT 1 FROM notices WHERE notice_id=?", (notice_id,)).fetchone() is not None


def read_counts() -> dict[str, int]:
    """管理端：每条通知的已读人数。"""
    with conn() as c:
        rows = c.execute("SELECT notice_id, COUNT(*) n FROM notice_reads GROUP BY notice_id").fetchall()
        return {r["notice_id"]: r["n"] for r in rows}


# ---------- OA：请假审批 ----------

_LEAVE_ACTIVE = ("PENDING", "APPROVED", "REJECTED")


def submit_leave(leave_id: str, emp_id: str, start_date: str, end_date: str,
                 reason: str, ts: str) -> None:
    with conn() as c:
        c.execute("INSERT INTO leaves (leave_id, emp_id, start_date, end_date, reason, status, created_at)"
                  " VALUES (?,?,?,?,?,'PENDING',?)",
                  (leave_id, emp_id, start_date, end_date, reason, ts))


def my_leaves(emp_id: str) -> list[dict]:
    with conn() as c:
        rows = c.execute(
            "SELECT l.*, e2.name AS reviewer_name FROM leaves l"
            " LEFT JOIN employees e2 ON e2.emp_id = l.reviewer_emp_id"
            " WHERE l.emp_id=? ORDER BY l.created_at DESC, l.leave_id DESC",
            (emp_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def pending_leaves() -> list[dict]:
    with conn() as c:
        rows = c.execute(
            "SELECT l.*, e.name AS applicant_name, e.role AS applicant_role FROM leaves l"
            " LEFT JOIN employees e ON e.emp_id = l.emp_id"
            " WHERE l.status='PENDING' ORDER BY l.created_at ASC, l.leave_id ASC"
        ).fetchall()
        return [dict(r) for r in rows]


def review_leave(leave_id: str, status: str, reviewer_emp_id: str,
                 comment: str, ts: str) -> int:
    """审批：仅 PENDING 可审（乐观锁语义——重复审批返回 0 而非覆盖）。"""
    with tx() as c:
        cur = c.execute(
            "UPDATE leaves SET status=?, reviewer_emp_id=?, review_comment=?, reviewed_at=?"
            " WHERE leave_id=? AND status='PENDING'",
            (status, reviewer_emp_id, comment, ts, leave_id),
        )
        return cur.rowcount


def leave(leave_id: str) -> dict | None:
    with conn() as c:
        r = c.execute("SELECT * FROM leaves WHERE leave_id=?", (leave_id,)).fetchone()
        return dict(r) if r else None


# ---------- OA：站内私信（短信式点对点） ----------


def dm_send(sender: str, receiver: str, body: str, ts: str) -> int:
    with conn() as c:
        cur = c.execute(
            "INSERT INTO dms (sender_emp_id, receiver_emp_id, body, created_at) VALUES (?,?,?,?)",
            (sender, receiver, body, ts),
        )
        return cur.lastrowid


def dm_thread(me: str, other: str, limit: int = 200) -> list[dict]:
    """与某人的双向会话，按时间正序返回最近 limit 条。"""
    with conn() as c:
        rows = c.execute(
            "SELECT * FROM dms WHERE (sender_emp_id=? AND receiver_emp_id=?)"
            " OR (sender_emp_id=? AND receiver_emp_id=?)"
            " ORDER BY id DESC LIMIT ?",
            (me, other, other, me, limit),
        ).fetchall()
        return [dict(r) for r in reversed(rows)]


def dm_inbox(me: str) -> list[dict]:
    """会话列表：每人一行，取最后一条消息与未读数，按最新消息时间倒序。"""
    with conn() as c:
        rows = c.execute(
            "SELECT e.emp_id, e.name, e.role,"
            "  m.body AS last_body, m.created_at AS last_at,"
            "  m.sender_emp_id AS last_sender,"
            "  (SELECT COUNT(*) FROM dms x WHERE x.sender_emp_id=e.emp_id"
            "    AND x.receiver_emp_id=? AND x.read_at IS NULL) AS unread"
            " FROM employees e"
            " LEFT JOIN dms m ON m.id = ("
            "   SELECT MAX(id) FROM dms d"
            "   WHERE (d.sender_emp_id=e.emp_id AND d.receiver_emp_id=?)"
            "      OR (d.receiver_emp_id=e.emp_id AND d.sender_emp_id=?))"
            " WHERE e.emp_id != ?"
            " ORDER BY (m.id IS NULL), m.created_at DESC, e.emp_id",
            (me, me, me, me),
        ).fetchall()
        return [dict(r) for r in rows]


def dm_unread_total(me: str) -> int:
    with conn() as c:
        return c.execute(
            "SELECT COUNT(*) n FROM dms WHERE receiver_emp_id=? AND read_at IS NULL",
            (me,),
        ).fetchone()["n"]


def dm_mark_thread_read(other: str, me: str, ts: str) -> int:
    """打开会话即把对方发给我的未读消息标记已读（幂等，不覆盖首读时间）。"""
    with conn() as c:
        cur = c.execute(
            "UPDATE dms SET read_at=? WHERE sender_emp_id=? AND receiver_emp_id=?"
            " AND read_at IS NULL",
            (ts, other, me),
        )
        return cur.rowcount


# ---------------- 第二期：客户反馈工单（内网为唯一事实源） ----------------

def fb_ingest(fb_id: str, openid_hash: str, category: str,
              body_masked: str, ts: str) -> None:
    """新反馈工单落库（body 必须已是脱敏文本，本函数不做任何原文落盘）。"""
    with conn() as c:
        c.execute(
            "INSERT OR IGNORE INTO feedback_tickets"
            " (fb_id, openid_hash, category, body_masked, status, created_at, updated_at)"
            " VALUES (?,?,?,?, 'SUBMITTED', ?, ?)",
            (fb_id, openid_hash, category, body_masked, ts, ts),
        )


def fb_ticket(fb_id: str) -> dict | None:
    with conn() as c:
        r = c.execute("SELECT * FROM feedback_tickets WHERE fb_id=?", (fb_id,)).fetchone()
        return dict(r) if r else None


def fb_add_reply(fb_id: str, rid: str, sender: str, body_masked: str,
                 verdict: str, ts: str) -> None:
    with conn() as c:
        c.execute(
            "INSERT OR IGNORE INTO feedback_replies"
            " (rid, fb_id, sender, body_masked, rule_verdict, created_at)"
            " VALUES (?,?,?,?,?,?)",
            (rid, fb_id, sender, body_masked, verdict, ts),
        )
        c.execute("UPDATE feedback_tickets SET updated_at=? WHERE fb_id=?", (ts, fb_id))


def fb_set_status(fb_id: str, status: str, ts: str) -> None:
    with conn() as c:
        c.execute("UPDATE feedback_tickets SET status=?, updated_at=? WHERE fb_id=?",
                  (status, ts, fb_id))


def fb_set_ai_reply(fb_id: str, reply: str, ts: str) -> None:
    with conn() as c:
        c.execute("UPDATE feedback_tickets SET ai_reply=?, updated_at=? WHERE fb_id=?",
                  (reply, ts, fb_id))


def fb_takeover(fb_id: str, emp_id: str, ts: str) -> None:
    with conn() as c:
        c.execute(
            "UPDATE feedback_tickets SET status='HUMAN_ANSWERING', assigned_emp=?,"
            " updated_at=? WHERE fb_id=?",
            (emp_id, ts, fb_id),
        )


def fb_close(fb_id: str, emp_id: str, ts: str) -> None:
    with conn() as c:
        c.execute(
            "UPDATE feedback_tickets SET status='CLOSED_HUMAN', assigned_emp=?,"
            " updated_at=? WHERE fb_id=?",
            (emp_id, ts, fb_id),
        )


def fb_rate(fb_id: str, satisfaction: int, ts: str) -> None:
    with conn() as c:
        c.execute("UPDATE feedback_tickets SET satisfaction=?, updated_at=? WHERE fb_id=?",
                  (satisfaction, ts, fb_id))


def fb_list(status: str | None = None, limit: int = 100) -> list[dict]:
    """坐席反馈列表（仅脱敏数据），按更新时间倒序。"""
    with conn() as c:
        if status:
            rows = c.execute(
                "SELECT * FROM feedback_tickets WHERE status=?"
                " ORDER BY updated_at DESC LIMIT ?",
                (status, limit),
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT * FROM feedback_tickets ORDER BY updated_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]


def fb_replies(fb_id: str) -> list[dict]:
    with conn() as c:
        rows = c.execute(
            "SELECT * FROM feedback_replies WHERE fb_id=? ORDER BY created_at, rowid",
            (fb_id,),
        ).fetchall()
        return [dict(r) for r in rows]


def fb_pending_count() -> int:
    """未接管工单数（坐席端角标）：新单/AI 应答中/待人工接管均计入，
    任一坐席接管（或直接回复）后即对全员消失。"""
    with conn() as c:
        return c.execute(
            "SELECT COUNT(*) n FROM feedback_tickets "
            "WHERE status IN ('SUBMITTED','AI_ANSWERING','PENDING_HUMAN')"
        ).fetchone()["n"]


def fb_archive() -> list[dict]:
    """档案库（管理端）：全部工单，含接管坐席姓名与往来回复数。"""
    with conn() as c:
        rows = c.execute(
            "SELECT t.*, COUNT(r.rid) AS reply_count, e.name AS agent_name"
            " FROM feedback_tickets t"
            " LEFT JOIN feedback_replies r ON r.fb_id = t.fb_id"
            " LEFT JOIN employees e ON e.emp_id = t.assigned_emp"
            " GROUP BY t.fb_id ORDER BY t.updated_at DESC LIMIT 500"
        ).fetchall()
        return [dict(r) for r in rows]


def fb_archive_stats() -> list[dict]:
    """档案库汇总：按坐席统计接管单数 / 办结单数。"""
    with conn() as c:
        rows = c.execute(
            "SELECT t.assigned_emp, e.name AS agent_name, COUNT(*) AS total,"
            " SUM(CASE WHEN t.status LIKE 'CLOSED%' THEN 1 ELSE 0 END) AS closed"
            " FROM feedback_tickets t"
            " LEFT JOIN employees e ON e.emp_id = t.assigned_emp"
            " WHERE t.assigned_emp IS NOT NULL"
            " GROUP BY t.assigned_emp ORDER BY total DESC"
        ).fetchall()
        return [dict(r) for r in rows]


def fb_mine(emp_id: str) -> list[dict]:
    """坐席个人工作档案：本坐席接管过的全部工单（工作历史）。"""
    with conn() as c:
        rows = c.execute(
            "SELECT t.*, COUNT(r.rid) AS reply_count"
            " FROM feedback_tickets t"
            " LEFT JOIN feedback_replies r ON r.fb_id = t.fb_id"
            " WHERE t.assigned_emp = ?"
            " GROUP BY t.fb_id ORDER BY t.updated_at DESC LIMIT 500",
            (emp_id,),
        ).fetchall()
        return [dict(r) for r in rows]
