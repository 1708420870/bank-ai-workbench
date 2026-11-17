# SSO 与 MFA 对接方案

> 对应审计编号：**R8 / C1 / G1**
> **诚实边界**：本项目**未接入行内 SSO**。本次整改实现了**标准 TOTP（RFC 6238）第二因子**，可在 PoC 现场演示；行内 SSO（OIDC/SAML）为外部依赖，需甲方提供 IdP 元数据。

---

## 1. 现状能力矩阵

| 能力 | 状态 | 实现位置 | 复验 |
|---|---|---|---|
| 账号口令登录 | ✅ | `inner/auth.py:login` | `pytest tests/test_auth.py -q` |
| 口令强度/哈希 | ✅ | `inner/auth.py:hash_password`（PBKDF2） | 同上 |
| 登录失败锁定 | ✅ | `LOGIN_MAX_FAIL` + `locked_until` | `test_auth*` |
| 单会话互踢 | ✅ | `db.revoke_other_sessions` | `test_auth*` |
| 设备绑定 | ✅ | `DEVICE_BINDING` + `device_id` | `test_auth*` |
| 会话滑动续期 | ✅ | `auth.session_of`（8h TTL，剩余<60% 顺延） | 手工验证记录 |
| **TOTP 第二因子（本次新增）** | ✅ | `common/totp.py` + `/auth/mfa/*` | `pytest tests/test_mfa.py -q`（含 RFC 6238 官方向量） |
| **行内 SSO（OIDC/SAML）** | ❌ 未接入 | — | 外部依赖（§4） |
| **短信/硬件令牌 MFA** | ❌ 未接入 | — | 由行内 MFA 提供（§4） |

---

## 2. TOTP 第二因子（可直接演示）

### 2.1 启用流程（两步，防"扫错码被锁在外面"）

```bash
# ① 生成密钥（返回 secret + otpauth:// URI，可生成二维码）
curl -X POST http://127.0.0.1:8101/internal/api/v1/auth/mfa/enable \
     -b cookie.txt
# → {"secret":"JBSWY3DPEHPK3PXP...","uri":"otpauth://totp/...","note":"..."}

# ② 用认证器扫码后，输入当前 6 位码确认（确认后才真正生效）
curl -X POST http://127.0.0.1:8101/internal/api/v1/auth/mfa/confirm \
     -H "Content-Type: application/json" -d '{"otp":"123456"}' -b cookie.txt
# → {"enabled":true,"enabled_at":"..."}
```

**为什么必须两步**：单步"生成即生效"在用户扫错二维码时会直接把自己锁在门外；两步确认保证"能算对码"才算启用成功。

### 2.2 登录时的行为

| 场景 | 返回 |
|---|---|
| 账号未启用 MFA | 正常登录（`otp` 字段被忽略） |
| 已启用但未传 `otp` | `401 {"detail":"请输入动态验证码","code":"MFA_REQUIRED"}` |
| `otp` 错误/过期 | `401 {"detail":"动态验证码错误或已过期","code":"MFA_INVALID"}` |
| `otp` 正确 | 正常登录 |

`code` 字段是给前端用的机器可读标识——**不给 code，前端只能匹配中文提示，一改文案就坏**。

### 2.3 关闭

```bash
curl -X POST http://127.0.0.1:8101/internal/api/v1/auth/mfa/disable \
     -H "Content-Type: application/json" -d '{"password":"<当前口令>"}' -b cookie.txt
```

**必须验口令**：否则"拿到会话"就等于"能关掉第二因子"，MFA 形同虚设。

### 2.4 算法正确性证据

`tests/test_mfa.py` 用 **RFC 6238 附录 B 的 6 组官方向量**断言（8 位 SHA1）：
```
59s → 94287082    1111111109s → 07081804    1111111111s → 14050471
1234567890s → 89005924   2000000000s → 69279037   20000000000s → 65353130
```
这不是"自己算一遍再自己断言"，而是对着标准文档核。

---

## 3. 行内 SSO 对接设计（待甲方 IdP）

### 3.1 协议选择

| 方案 | 适用 | 本项目建议 |
|---|---|---|
| **OIDC（Authorization Code + PKCE）** | 行内有现代 IdP（Azure AD/Keycloak/行内自建） | **首选**：与现有 `auth.py` 会话模型最容易对接，只需把"口令校验"换成"换取 id_token 并验签" |
| SAML 2.0 | 行内为传统 ADFS | 备选：需引入 `python3-saml`，断言解析要考虑 XML 签名包装攻击 |
| CAS | 部分银行历史系统 | 不推荐（能力弱，无标准 MFA 声明） |

### 3.2 对接点（代码级，只有一处）

```python
# inner/auth.py:login() 中"口令校验"这一段替换为：
#   ① 前端跳转 IdP → 回调带 code
#   ② 服务端 code + PKCE verifier 换 id_token
#   ③ 验签（JWKS）+ 校验 iss/aud/exp/nonce
#   ④ 断言 role 映射（行内组 → agent/supervisor/auditor/developer）
#   ⑤ 之后流程完全不变：create_session / 单会话 / 设备绑定 / 审计
```

**关键**：会话模型、RBAC、审计**不需要改**——这正是当前分层的好处：身份来源可换，授权与会话逻辑不动。

### 3.3 角色映射（必须甲方确认）

| 行内身份组 | 本项目角色 | 权限 |
|---|---|---|
| `CB-CS-AGENT` | `agent` | 工单、AI 建议、人工确认（自己工单） |
| `CB-CS-SUP` | `supervisor` | 全部工单、审批、发布、回滚、账号管理 |
| `CB-AUDIT` | `auditor` | 只读审计、规则目录、导出 |
| `CB-TECH` | `developer` | MCP 只读工具、草稿提交、沙箱 |

**不得**用"默认给 supervisor"来简化联调——那会让最小权限在第一天就失效。

---

## 4. 外部依赖清单（未关闭前 C1 不得判"完整符合"）

| 编号 | 依赖项 | 提供方 | 影响 |
|---|---|---|---|
| S1 | IdP 元数据（issuer / authorization_endpoint / token_endpoint / jwks_uri） | 甲方身份平台 | SSO 无法联调 |
| S2 | 客户端注册（client_id / client_secret / 回调地址白名单） | 甲方身份平台 | 无法发起授权码流程 |
| S3 | 行内组 → 本项目角色映射表 | 甲方 HR/身份平台 + 业务 | RBAC 映射无依据 |
| S4 | 行内 MFA 策略（是否强制、哪些角色强制） | 甲方安全 | 无法确定"是否保留 TOTP 作为兜底" |
| S5 | 登出联动（行内单点登出是否要求回调） | 甲方身份平台 | 可能出现"行内已登出、本系统仍在会话" |

**关闭判据**：S1–S5 齐备 + 联调记录（登录→角色正确→登出联动）+ 一次"行内组变更后权限随之变更"的验证。

---

## 5. 建议的过渡策略（PoC 期间）

| 阶段 | 身份方案 | 说明 |
|---|---|---|
| PoC 演示（当前） | 账号口令 + 可选 TOTP | 可离线、可复现、不依赖甲方网络 |
| PoC 验收会 | 同上 + **对 supervisor/auditor 账号强制 TOTP** | 演示"高权限必须双因子" |
| 试点上线 | 行内 SSO（OIDC）+ 行内 MFA | TOTP 仅作为 SSO 不可用时的应急通道，需安全批准 |
| 生产 | 行内 SSO 强制，TOTP 下线 | 单一身份源，避免"两套账号体系" |

**强制 TOTP 的配置方式**（PoC 可用）：
```bash
# 对指定账号启用（管理员在库中置 pending→confirm，或走 API）
curl -X POST .../auth/mfa/enable -b admin_cookie
```
> 生产建议改为"按角色策略自动要求"，而不是逐个账号手工开——手工开一定会漏。
