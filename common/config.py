"""全局配置：分区端点、共享密钥、出域白名单。

设计要点：每个区只知道"自己该知道的地址"。外网区在配置层就没有内网地址，
这不是约定，而是让"直连内网"在代码里无址可依。
"""
import os
import sys
from pathlib import Path

# 桌面打包（PyInstaller）适配：
# - 只读资源（web 页面）在 _MEIPASS 临时目录
# - 可写数据（数据库、审计、验收报告）放在 exe 旁边，随目录迁移
if getattr(sys, "frozen", False):
    ROOT = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    APP_DIR = Path(sys.executable).resolve().parent
else:
    ROOT = Path(__file__).resolve().parent.parent
    APP_DIR = ROOT

DATA_DIR = Path(os.getenv("DATA_DIR", str(APP_DIR / "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR = Path(os.getenv("LOG_DIR", str(DATA_DIR / "logs")))
LOG_DIR.mkdir(parents=True, exist_ok=True)

# 应用版本：语义化版本（主.次.修订），发布时同步打 git tag（如 v1.1.0）
APP_VERSION = os.getenv("APP_VERSION", "1.4.5")

HOST = os.getenv("ZONE_HOST", "127.0.0.1")
INNER_PORT = int(os.getenv("INNER_PORT", "8101"))
DMZ_PORT = int(os.getenv("DMZ_PORT", "8102"))
OUTER_PORT = int(os.getenv("OUTER_PORT", "8103"))

# 跨区调用地址与监听地址解耦：ZONE_HOST 可放宽为 0.0.0.0（真机测试需要局域网
# 直连），但区与区之间的服务调用必须走回环——Windows 无法把 0.0.0.0 当目标地址。
_CALL_HOST = os.getenv("ZONE_CALL_HOST", "127.0.0.1")
INNER_URL = os.getenv("INNER_URL", f"http://{_CALL_HOST}:{INNER_PORT}")
DMZ_URL = os.getenv("DMZ_URL", f"http://{_CALL_HOST}:{DMZ_PORT}")
OUTER_URL = os.getenv("OUTER_URL", f"http://{_CALL_HOST}:{OUTER_PORT}")

# 分区间共享密钥（PoC 级：生产应走 KMS/HSM 与证书体系）
SECRET_INNER_DMZ = os.getenv("SECRET_INNER_DMZ", "poc-inner-dmz-2026")
SECRET_DMZ_OUTER = os.getenv("SECRET_DMZ_OUTER", "poc-dmz-outer-2026")
DATA_KEY = os.getenv("DATA_KEY", "poc-data-encryption-key-2026")

# 归档加密用（令牌映射表落盘前加密）
SCHEMA_VERSION = "1.0"
PAYLOAD_TTL_SECONDS = int(os.getenv("PAYLOAD_TTL_SECONDS", "300"))

# 回程/入站载荷长度上限（标准第②项"长度"校验的判定阈值）。
# 取值依据：正常 AgentResponse 序列化后约 1–2KB，给 4 倍余量；
# 单字段上限用于防"一个字段塞 1MB 提示注入"绕过整体阈值。
MAX_RESPONSE_CHARS = int(os.getenv("MAX_RESPONSE_CHARS", "8000"))
MAX_FIELD_CHARS = int(os.getenv("MAX_FIELD_CHARS", "2000"))
# DMZ 入站请求体上限（与回程阈值分开：出域方向是脱敏上下文，通常更短）
MAX_REQUEST_CHARS = int(os.getenv("MAX_REQUEST_CHARS", "16000"))

# DMZ MCP 网关限流（滑动窗口）。标准 C10 要求网关具备"认证/授权/限流/审计"四件套，
# 限流不是性能优化，而是把"凭据泄露后被批量刷取"的影响面限死在窗口内。
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", "60"))
RATE_LIMIT_MAX_CALLS = int(os.getenv("RATE_LIMIT_MAX_CALLS", "30"))
RATE_LIMIT_MAX_PER_ACTOR = int(os.getenv("RATE_LIMIT_MAX_PER_ACTOR", "60"))

# 出域端口白名单：架构约束在配置层固化
ALLOWED_PORTS = {
    "inner": {DMZ_PORT},
    "dmz": {INNER_PORT, OUTER_PORT},
    "outer": {DMZ_PORT},
}

AGENT_IMPL = os.getenv("AGENT_IMPL", "mock")   # mock | http
MODEL_IMPL = os.getenv("MODEL_IMPL", "mock")   # mock | real

# ---------------- 部署模式（任务书三种模式的开关） ----------------
# true  = 受控跨域交换（推荐 PoC 模式，低风险意图可外发脱敏上下文）
# false = 严格物理气隙 / 完全内网模型模式：所有意图强制走内网端点，
#         外呼派发被硬阻断（fail-closed），与内网 Mock/真实算力组合使用
EGRESS_ENABLED = os.getenv("EGRESS_ENABLED", "true").lower() != "false"

# ---------------- 内网算力：牛马仕（Bull Hermes）私有部署端点 ----------------
# 牛马仕是微光工作室自研、唯一可私有化部署到客户内网的智能体产品；
# 内网算力走其 GPU 服务器上的 Qwen3.5-9B-AWQ（vLLM，OpenAI 兼容协议）。
HERMES_BASE_URL = os.getenv("HERMES_BASE_URL", "http://106.55.2.189:8000/v1")
HERMES_API_KEY = os.getenv("HERMES_API_KEY", "eW91ci1zZWNyZXQta2V5LWhlcmUK")
HERMES_MODEL = os.getenv("HERMES_MODEL", "Qwen3.5-9B-AWQ")
HERMES_TIMEOUT = float(os.getenv("HERMES_TIMEOUT", "45"))

# 聚合数据最小样本阈值（防小样本反推）
MIN_AGGREGATE_SAMPLE = int(os.getenv("MIN_AGGREGATE_SAMPLE", "20"))

# ---- 身份与会话 ----
# 会话令牌的签名密钥。生产应轮转并托管于 KMS；PoC 用环境变量。
SESSION_SECRET = os.getenv("SESSION_SECRET", "poc-session-hmac-2026")
SESSION_COOKIE = os.getenv("SESSION_COOKIE", "wb_sid")
SESSION_TTL_SECONDS = int(os.getenv("SESSION_TTL_SECONDS", "28800"))

# 登录失败锁定：同一账号连续失败 N 次后锁定 M 秒（防口令爆破）
LOGIN_MAX_FAIL = int(os.getenv("LOGIN_MAX_FAIL", "5"))
LOGIN_LOCK_SECONDS = int(os.getenv("LOGIN_LOCK_SECONDS", "300"))

# ---- 访问环境限制 ----
# 单会话互踢：同一账号只允许一个活跃会话，新登录强制吊销旧会话（防账号共享）
SINGLE_SESSION = os.getenv("SINGLE_SESSION", "true").lower() != "false"

# 设备绑定：开启后，账号一旦绑定设备 ID，只能从该设备登录。
# 桌面客户端每次请求携带 X-Device-Id；浏览器登录（无设备头）不受影响。
DEVICE_BINDING = os.getenv("DEVICE_BINDING", "false").lower() == "true"

# 登录来源限制：逗号分隔的 CIDR 网段，空表示不限。
# 例：ALLOWED_LOGIN_NETS="127.0.0.0/8,192.168.0.0/16,10.0.0.0/8"
ALLOWED_LOGIN_NETS = [n.strip() for n in os.getenv("ALLOWED_LOGIN_NETS", "").split(",") if n.strip()]

# 服务间凭证：仅用于 DMZ → 内网 MCP Facade 这一条通路。
# 它拿不到业务查询接口——即使泄漏也无法借此读取客户数据。
SERVICE_TOKEN = os.getenv("SERVICE_TOKEN", "poc-dmz-to-inner-service-2026")

# 两个入口与其允许的角色。角色不匹配即拒绝登录，不是登录后再隐藏菜单。
PORTAL_ROLES = {
    "client": {"agent"},
    "admin": {"supervisor", "auditor", "developer"},
}


def db_path(zone: str) -> Path:
    return DATA_DIR / f"{zone}.db"
