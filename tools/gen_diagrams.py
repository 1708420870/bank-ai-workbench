"""生成《系统设计说明书》所需的 4+1 视图图集（PNG，供 docx 嵌入）。

图清单：
  1. uml_class.png    —— 逻辑视图：核心对象 UML 类图
  2. seq_main.png     —— 场景视图：12 步主流程时序图
  3. deploy_zones.png —— 物理视图：三区部署图
  4. dev_modules.png  —— 开发视图：模块依赖图
  5. proc_threads.png —— 进程视图：线程与端口拓扑
"""
from __future__ import annotations

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle
from pathlib import Path

plt.rcParams["font.sans-serif"] = ["Microsoft YaHei", "SimHei"]
plt.rcParams["axes.unicode_minus"] = False

OUT = Path(__file__).resolve().parent.parent / "docs" / "assets"
OUT.mkdir(parents=True, exist_ok=True)

C_HEAD = "#1f4e79"   # 类名栏深蓝
C_BOX = "#eaf1f8"    # 类体浅蓝
C_EDGE = "#4472c4"
C_LIFE = "#7f7f7f"
C_ACT = "#ffd966"
C_ZONE_IN = "#e2efda"   # 内网浅绿
C_ZONE_DMZ = "#fff2cc"  # DMZ 浅黄
C_ZONE_OUT = "#fce4ec"  # 外网浅粉
C_NOTE = "#f2f2f2"


def uml_class(ax, x, y, w, h, name, attrs, methods, head=C_HEAD):
    """画一个 UML 类框（三栏：类名/属性/方法）。x,y 为左上角。"""
    nh = 0.052
    na = 0.016 * (len(attrs) + 0.6)
    nm = 0.016 * (len(methods) + 0.6)
    # 属性栏
    ax.add_patch(Rectangle((x, y - nh - na), w, na, fc=C_BOX, ec=C_EDGE, lw=1.2, zorder=3))
    for i, a in enumerate(attrs):
        ax.text(x + 0.008, y - nh - 0.014 * (i + 1), a, fontsize=8.2, va="top", zorder=4,
                family=["Consolas", "Microsoft YaHei"])
    # 方法栏
    ax.add_patch(Rectangle((x, y - nh - na - nm), w, nm, fc="white", ec=C_EDGE, lw=1.2, zorder=3))
    for i, m in enumerate(methods):
        ax.text(x + 0.008, y - nh - na - 0.014 * (i + 1), m, fontsize=8.2, va="top", zorder=4,
                family=["Consolas", "Microsoft YaHei"])
    # 类名栏
    ax.add_patch(Rectangle((x, y - nh), w, nh, fc=head, ec=C_EDGE, lw=1.2, zorder=3))
    ax.text(x + w / 2, y - nh / 2, name, fontsize=10, ha="center", va="center",
            color="white", weight="bold", zorder=4)
    return y - nh - na - nm  # 底边 y


def arrow(ax, p1, p2, style="-|>", color=C_EDGE, lw=1.4, ls="-"):
    ax.add_patch(FancyArrowPatch(p1, p2, arrowstyle=style, mutation_scale=14,
                                 color=color, lw=lw, linestyle=ls, zorder=2))


def label(ax, x, y, text, fontsize=8.5, color="#333333"):
    ax.text(x, y, text, fontsize=fontsize, color=color, ha="center", va="center",
            bbox=dict(fc="white", ec="none", pad=0.8), zorder=5)


# ============ 1. UML 类图（逻辑视图） ============
def draw_class_diagram():
    fig, ax = plt.subplots(figsize=(11.5, 10.0), dpi=150)
    ax.set_xlim(0, 1); ax.set_ylim(-0.05, 1); ax.axis("off")
    ax.set_title("图 4-1  逻辑视图：内网核心对象 UML 类图（职责与依赖）", fontsize=13, weight="bold", pad=14)

    # ---- 第一行：接口层 ----
    uml_class(ax, 0.03, 0.97, 0.28, 1, "InnerApp (app.py)  «Controller»",
              ["- runlog: Logger", "- WEB: Path"],
              ["+ login() / logout()", "+ create_case() / confirm()", "+ restore() / mcp_proxy()"])
    uml_class(ax, 0.40, 0.97, 0.30, 1, "AuthController (auth.py)",
              ["- SESSION_SECRET: str", "- MAX_FAILS = 5 / LOCK = 300s"],
              ["+ login()  失败锁定+防枚举", "+ current_user()  «依赖注入»", "+ require(*roles)  «RBAC»",
               "+ session_of()  单会话互踢"])
    uml_class(ax, 0.76, 0.97, 0.22, 1, "DmzGateway",
              ["- _SEEN  «重放检测»", "- _DLP  «形态级 DLP»"],
              ["+ dispatch()", "+ mcp_call()", "- _deny() fail-closed"],
              head="#8a6d3b")

    # ---- 第二行：编排层 ----
    uml_class(ax, 0.03, 0.55, 0.30, 1, "CaseService (service.py)  «门面»",
              ["- META_FIELDS: set"],
              ["+ handle_case()  «12 步编排»", "- _dispatch()  出域派发", "- _validate_response()",
               "+ restore_for_display()"])
    uml_class(ax, 0.40, 0.55, 0.30, 1, "NiumashiAgent (agent.py)  «编排者»",
              ["+ version = nms-agent-0.9.3", "- connector: ModelConnector"],
              ["+ plan(intent, context)", "  路由决策 + 结果组织"])
    uml_class(ax, 0.76, 0.55, 0.22, 1, "ModelConnector  «策略»",
              ["- _ROUTING: dict"],
              ["+ select(intent)", "+ invoke_local(ep, task)", "  real | mock 可切换"])

    # ---- 第三行：值对象 ----
    uml_class(ax, 0.74, 0.37, 0.24, 1, "Endpoint «frozen dataclass»",
              ["+ endpoint_id: str", "+ egress: bool  «出域»"],
              ["«不可变值对象»"], head="#6a8759")

    # ---- 第四行：支撑层 ----
    uml_class(ax, 0.02, 0.19, 0.24, 1, "PrivacyService (privacy.py)",
              ["- names  «客户名单»"],
              ["+ mask(text, rid)", "+ scan_payload(task)", "+ 复检 / 令牌化"])
    uml_class(ax, 0.28, 0.19, 0.24, 1, "RuleEngine (rules.py)  «否决权»",
              ["- MANDATORY 集合"],
              ["+ evaluate() -> Verdict", "+ build_egress_context()", "+ template_for()"])
    uml_class(ax, 0.54, 0.19, 0.20, 1, "Repository (db.py)",
              ["«对应 MyBatis 映射器»"],
              ["+ tx()  «写事务边界»", "+ conn()  «短连接»", "+ ticket() / save_ticket()"])
    uml_class(ax, 0.76, 0.19, 0.22, 1, "AuditTrail (audit.py)",
              ["- _SCRUB_PATTERNS  «责任链»"],
              ["+ log(zone, event)", "  强制脱敏后落盘", "+ query(rid)"])

    # ---- 关系箭头（避开所有方框） ----
    arrow(ax, (0.31, 0.895), (0.40, 0.895)); label(ax, 0.355, 0.915, "认证/RBAC")
    arrow(ax, (0.165, 0.80), (0.165, 0.55)); label(ax, 0.165, 0.68, "调用")
    arrow(ax, (0.33, 0.475), (0.40, 0.475)); label(ax, 0.365, 0.495, "出域派发 HTTP")
    arrow(ax, (0.18, 0.385), (0.18, 0.19)); label(ax, 0.255, 0.30, "创建")
    arrow(ax, (0.30, 0.44), (0.28, 0.19)); label(ax, 0.265, 0.335, "令牌化/复检")
    arrow(ax, (0.33, 0.465), (0.35, 0.19)); label(ax, 0.36, 0.245, "模型后裁决")
    arrow(ax, (0.70, 0.475), (0.76, 0.475)); label(ax, 0.73, 0.495, "组合 ◆")
    arrow(ax, (0.86, 0.42), (0.86, 0.37)); label(ax, 0.86, 0.393, "返回")

    ax.text(0.5, -0.02, "设计模式标注：CaseService=门面 / NiumashiAgent=编排者(中介者) / ModelConnector=策略 / "
                        "audit._SCRUB=责任链 / Endpoint=不可变值对象\n分层对应：接口层=SpringMVC Controller · "
                        "Repository=MyBatis 映射器 · 审计/日志=横切关注点(AOP)",
            fontsize=8.8, ha="center", color="#555555", style="italic")
    fig.savefig(OUT / "uml_class.png", bbox_inches="tight", facecolor="white")
    plt.close(fig)


# ============ 2. 时序图（场景视图） ============
def draw_sequence():
    fig, ax = plt.subplots(figsize=(12.5, 8.6), dpi=150)
    ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off")
    ax.set_title("图 4-2  场景视图：12 步主流程时序图（以经 DMZ 出域为例）", fontsize=13, weight="bold", pad=14)

    actors = [
        ("坐席\n(浏览器)", 0.045), ("InnerApp\n(路由层)", 0.175), ("CaseService\n(编排层)", 0.315),
        ("Privacy\nService", 0.435), ("Niumashi\nAgent", 0.545), ("DMZ\n网关", 0.645),
        ("Outer\n模型服务", 0.755), ("RuleEngine\n(裁决)", 0.865), ("Audit\n(审计)", 0.955),
    ]
    top = 0.90
    for name, x in actors:
        ax.add_patch(FancyBboxPatch((x - 0.042, top - 0.005), 0.084, 0.052,
                                    boxstyle="round,pad=0.004", fc=C_ACT, ec="#b8860b", lw=1.2, zorder=3))
        ax.text(x, top + 0.021, name, fontsize=8.3, ha="center", va="center", zorder=4)
        ax.plot([x, x], [0.06, top - 0.005], color=C_LIFE, lw=1.0, ls=(0, (4, 3)), zorder=1)

    y = top - 0.055
    def msg(x1, x2, text, dy=0.038, dashed=False, bold=False):
        nonlocal y
        arrow(ax, (x1, y), (x2, y), style="-|>", color="#333333" if not dashed else C_LIFE,
              lw=1.3, ls=":" if dashed else "-")
        label(ax, (x1 + x2) / 2, y + 0.012, text, fontsize=8.0,
              color="#1f4e79" if bold else "#333333")
        y -= dy

    def note(x, text, dy=0.030, color=C_NOTE):
        nonlocal y
        ax.add_patch(FancyBboxPatch((x - 0.10, y - 0.014), 0.20, 0.026,
                                    boxstyle="round,pad=0.003", fc=color, ec="#999999", lw=0.8, zorder=3))
        ax.text(x, y - 0.001, text, fontsize=7.6, ha="center", va="center", zorder=4)
        y -= dy

    x0, x1, x2, x3, x4, x5, x6, x7, x8 = [a[1] for a in actors]

    msg(x0, x1, "① 提交案例 + 附件说明", bold=True)
    msg(x1, x2, "② 权限校验通过，创建工单", bold=True)
    msg(x2, x3, "④ 字段识别 → 令牌化脱敏")
    note(x3, "卡号/手机/证件/金额 → 替换为 ⟨T-CARD-01⟩ 等令牌".replace("⟨", "〔").replace("⟩", "〕"))
    msg(x3, x2, "脱敏文本 + 令牌映射（真实值加密留内网）", dashed=True)
    msg(x2, x4, "⑤⑥ 出域载荷构造 + 内容复检")
    note(x2, "扫描残留 → 直接 BLOCKED，不出域")
    msg(x2, x4, "⑦ agent.plan() 意图规划")
    msg(x4, x5, "⑧ 经 DMZ 出域（低风险意图）")
    msg(x5, x6, "四重白名单 + 复检 + TTL + 重放检测", bold=True)
    msg(x6, x7, "转发脱敏任务（逐跳换签）")
    msg(x7, x6, "结构化建议（schema 校验）", dashed=True)
    msg(x6, x5, "回程校验 + 换回内网签名", dashed=True)
    msg(x4, x2, "候选建议输出", dashed=True)
    msg(x2, x7, "⑩ 规则裁决（模型之后独立运行）", bold=True)
    note(x7, "SHOW_SUGGESTION / HUMAN_HANDOFF / REJECTED", color=C_ZONE_DMZ)
    msg(x7, x2, "裁决结果（规则有否决权）", dashed=True)
    msg(x2, x3, "⑪ 三元匹配复原（会话+员工+请求）".replace("⑪", "(11)"))
    msg(x2, x0, "⑫ RESTORED：可见建议话术".replace("⑫", "(12)"), dashed=True, bold=True)
    msg(x8, x2, "全程每步落审计（元数据、强制脱敏）", dashed=True)

    ax.text(0.5, 0.02, "要点：身份在①终止于内网；跨域载荷过不了两道独立扫描；裁决权永远在内网规则引擎，模型只有建议权。",
            fontsize=8.6, ha="center", color="#555555", style="italic")
    fig.savefig(OUT / "seq_main.png", bbox_inches="tight", facecolor="white")
    plt.close(fig)


# ============ 3. 部署图（物理视图） ============
def draw_deploy():
    fig, ax = plt.subplots(figsize=(11.5, 6.4), dpi=150)
    ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off")
    ax.set_title("图 4-3  物理视图：三区部署拓扑（桌面交付形态与生产拓扑同构）", fontsize=13, weight="bold", pad=14)

    def zone(x, w, title, color, items, port_note):
        ax.add_patch(FancyBboxPatch((x, 0.16), w, 0.66, boxstyle="round,pad=0.008",
                                    fc=color, ec="#666666", lw=1.4, zorder=1))
        ax.text(x + w / 2, 0.775, title, fontsize=11, ha="center", weight="bold", zorder=3)
        yy = 0.66
        for it in items:
            ax.add_patch(FancyBboxPatch((x + 0.03, yy - 0.085), w - 0.06, 0.085,
                                        boxstyle="round,pad=0.003", fc="white", ec=C_EDGE, lw=1.0, zorder=3))
            ax.text(x + w / 2, yy - 0.043, it, fontsize=8.6, ha="center", va="center", zorder=4)
            yy -= 0.10
        ax.text(x + w / 2, 0.115, port_note, fontsize=8.5, ha="center", color="#555555", zorder=3)

    zone(0.02, 0.30, "内网可信域 (Trusted)", C_ZONE_IN,
         ["BankAIWorkbench.exe\n(Uvicorn 线程 + WebView2 壳)", "inner.db  客户/规则/工单/审计\n(原始数据 · 唯一副本)",
          "牛马仕 Agent + ModelConnector\n→ Qwen3.5-9B-AWQ (vLLM)"], "127.0.0.1:8101")
    zone(0.35, 0.28, "DMZ 安全交换区", C_ZONE_DMZ,
         ["交换网关 /dmz/api/v1/dispatch\n四重白名单 + 双道复检", "MCP 受控网关\n工具级授权 + 身份透传",
          "dmz.db  交换审计"], "127.0.0.1:8102")
    zone(0.66, 0.32, "外网 AI 协同域", C_ZONE_OUT,
         ["任务队列 outer.db\n(TTL 过期自动清刷)", "模型适配层\npartner-cloud (Mock / 可插拔)",
          "远端 GPU 算力\n106.55.2.189  vLLM 兼容端点"], "127.0.0.1:8103")

    arrow(ax, (0.32, 0.45), (0.35, 0.45)); label(ax, 0.335, 0.475, "签名载荷")
    arrow(ax, (0.35, 0.41), (0.32, 0.41), ls=":"); label(ax, 0.335, 0.385, "回程校验")
    arrow(ax, (0.63, 0.45), (0.66, 0.45)); label(ax, 0.645, 0.475, "换签转发")
    arrow(ax, (0.66, 0.41), (0.63, 0.41), ls=":"); label(ax, 0.645, 0.385, "回程换签")
    arrow(ax, (0.98, 0.45), (0.985, 0.45)); label(ax, 0.985, 0.43, "")

    ax.text(0.5, 0.045, "安全不变量：外网区代码无内网地址可依（配置层无址可依）；跨区仅 HTTP+签名；端口白名单在配置层固化。",
            fontsize=8.8, ha="center", color="#555555", style="italic")
    fig.savefig(OUT / "deploy_zones.png", bbox_inches="tight", facecolor="white")
    plt.close(fig)


# ============ 4. 模块依赖图（开发视图） ============
def draw_modules():
    fig, ax = plt.subplots(figsize=(11.5, 7.0), dpi=150)
    ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off")
    ax.set_title("图 4-4  开发视图：模块结构与依赖方向（分层 = 包结构，依赖单向向下）", fontsize=13, weight="bold", pad=14)

    layers = [
        ("表现层  Presentation", 0.78, ["web/  login·client·admin (原生HTML/CSS)", "desktop/  launcher·build (PyInstaller+WebView2)"]),
        ("接口层  Interface", 0.60, ["inner/app.py  HTTP+RBAC 路由", "dmz/app.py  交换网关", "outer/app.py  任务队列 API"]),
        ("业务层  Domain", 0.42, ["inner/service.py  12步编排", "inner/agent.py  牛马仕+连接器", "inner/auth.py  认证会话", "inner/privacy.py  令牌化", "inner/rules.py  规则引擎"]),
        ("基础设施层  Infrastructure", 0.20, ["common/config  配置", "common/db(inner/db.py)  仓储", "common/crypto  签名加密", "common/audit  审计", "common/logger  运行日志", "common/schema  Pydantic 契约", "common/egress  出域守卫"]),
    ]
    n_cols = [2, 3, 5, 7]
    for li, (title, y, mods) in enumerate(layers):
        ax.text(0.015, y + 0.075, title, fontsize=10.5, weight="bold", color=C_HEAD)
        ax.add_patch(Rectangle((0.01, y - 0.075), 0.98, 0.135, fc=C_BOX if li % 2 == 0 else "white",
                               ec="#cccccc", lw=0.8, zorder=1))
        w = 0.955 / n_cols[li]
        for mi, m in enumerate(mods):
            x = 0.02 + mi * w
            ax.add_patch(FancyBboxPatch((x + 0.004, y - 0.055), w - 0.014, 0.105,
                                        boxstyle="round,pad=0.003", fc="white", ec=C_EDGE, lw=1.0, zorder=3))
            ax.text(x + w / 2, y - 0.003, m, fontsize=7.7, ha="center", va="center", zorder=4)

    for y in (0.60, 0.42):
        arrow(ax, (0.5, y - 0.078), (0.5, y - 0.132), color="#888888", lw=1.6)
        label(ax, 0.5, y - 0.105, "依赖方向 ↓（上层知下层，下层不知上层）", 8.5)

    ax.text(0.5, 0.045, "映射课程知识：分层与 MVC（软件体系结构）、仓储层对应 MyBatis 映射器、接口层对应 SpringMVC Controller、\n"
                        "审计/日志/出域守卫为 AOP 式横切关注点（独立成模块而非散落在业务代码里）。",
            fontsize=8.6, ha="center", color="#555555", style="italic")
    fig.savefig(OUT / "dev_modules.png", bbox_inches="tight", facecolor="white")
    plt.close(fig)


# ============ 5. 进程视图 ============
def draw_process():
    fig, ax = plt.subplots(figsize=(11.0, 5.6), dpi=150)
    ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off")
    ax.set_title("图 4-5  进程视图：单 exe 多线程拓扑（桌面形态）与生产进程拓扑对照", fontsize=13, weight="bold", pad=14)

    ax.add_patch(FancyBboxPatch((0.03, 0.18), 0.42, 0.66, boxstyle="round,pad=0.008",
                                fc="#eef3fb", ec=C_EDGE, lw=1.4, zorder=1))
    ax.text(0.24, 0.795, "桌面形态：一个进程，三个线程", fontsize=10.5, ha="center", weight="bold")
    procs = [
        ("主线程：pywebview（WebView2 窗口）", 0.66),
        ("线程 zone-8101：Uvicorn 内网服务", 0.52),
        ("线程 zone-8102：Uvicorn DMZ 网关", 0.40),
        ("线程 zone-8103：Uvicorn 外网服务", 0.28),
    ]
    for txt, yy in procs:
        ax.add_patch(FancyBboxPatch((0.05, yy - 0.05), 0.38, 0.10, boxstyle="round,pad=0.003",
                                    fc="white", ec=C_EDGE, lw=1.0, zorder=3))
        ax.text(0.24, yy, txt, fontsize=8.8, ha="center", va="center", zorder=4)
    ax.text(0.24, 0.15, "共享进程不共享状态：三份独立 SQLite + 独立服务边界。\n生产部署改为三容器三网络（docker-compose），边界不变。",
            fontsize=8.4, ha="center", color="#555555", style="italic")

    ax.add_patch(FancyBboxPatch((0.53, 0.18), 0.44, 0.66, boxstyle="round,pad=0.008",
                                fc="#f7f7f7", ec="#888888", lw=1.4, zorder=1))
    ax.text(0.75, 0.795, "生产拓扑（演进路线，边界同构）", fontsize=10.5, ha="center", weight="bold")
    procs2 = [
        ("容器 inner-net：内网 API ×N（负载均衡）", 0.62),
        ("容器 dmz-net：交换网关 ×2（双活）", 0.48),
        ("容器 outer-net：模型网关 ×N（可弹性）", 0.34),
        ("网络策略：仅 dmz 可见两个网络", 0.22),
    ]
    for txt, yy in procs2:
        ax.add_patch(FancyBboxPatch((0.55, yy - 0.05), 0.40, 0.10, boxstyle="round,pad=0.003",
                                    fc="white", ec="#999999", lw=1.0, zorder=3))
        ax.text(0.75, yy, txt, fontsize=8.8, ha="center", va="center", zorder=4)
    ax.text(0.75, 0.15, "进程视图与物理视图解耦：换部署形态不改一行业务代码。",
            fontsize=8.4, ha="center", color="#555555", style="italic")
    fig.savefig(OUT / "proc_threads.png", bbox_inches="tight", facecolor="white")
    plt.close(fig)


if __name__ == "__main__":
    draw_class_diagram()
    draw_sequence()
    draw_deploy()
    draw_modules()
    draw_process()
    for p in sorted(OUT.glob("*.png")):
        print("OK", p.name)
