<div align="center">

# 🍯 aiHoneyPotFramework

**对 LLM 渗透 Agent 的多阶段差分反制蜜罐 —— 全实证研究系统**

*当蜜罐开始反击：识别 · 欺骗 · 逼真 · 消耗 · 归因*

[![Python](https://img.shields.io/badge/Python-3.13%2B-3776AB?logo=python&logoColor=white)]()
[![Tests](https://img.shields.io/badge/tests-100%20passed-brightgreen?logo=pytest&logoColor=white)]()
[![LLM Runs](https://img.shields.io/badge/real%20LLM%20runs-23%2B-orange)]()
[![Frameworks](https://img.shields.io/badge/real%20pentest%20frameworks-3-purple)]()
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white)]()
[![MCP](https://img.shields.io/badge/MCP-compatible-8B5CF6)]()
[![License](https://img.shields.io/badge/AGPL--3.0-blue)](LICENSE)

**每一个数字都来自真实在环测量** —— deepseek-flash / v4-pro，100+ 试验，3 个真实渗透框架 Docker 实测，零虚构。

</div>

---

## 📊 TL;DR

> 门控让 **100%** 的 LLM Agent 走进来 → 校验逼它交**真的** → 无限阶梯烧光它的预算 → 假 Postgres 让假凭证**真能登录** → 动态 SQLi 在真实审计下被判为**真实漏洞** → 全程双视角落库可复现。

<div align="center">

| 🚪 门控服从 | 🛡️ 编造拦截 | 🪜 阶梯消耗 | 🖐️ 指纹分类 | 🔧 工具投毒 | 🗄️ SQLi 逼真度 |
|:---:|:---:|:---:|:---:|:---:|:---:|
| **0→100%** | **100%→0** | **$4.90/60轮** | **100%** | **4/5** | **通过全审计** |

</div>

<details open>
<summary><b>📈 核心指标弧线 —— 23 轮干预 → 实测跃迁</b></summary>

| 干预 | 实测跃迁 | 轮次 |
|---|---|---|
| 门控反转（诱饵入验证墙） | 注入服从 0-20% → **100%**（隐蔽/粗心/浏览器 Agent 一视同仁） | R3 |
| 真实性校验 | 表演式编造满级 60-100% → **0%**；修复误拒后真泄露满级率 → **50%** | R5/R16 |
| 无限授权阶梯 | 真实框架自愿爬 **8 级**、46 次提交、$4.90 / 60 轮空手而归 | R18+实测 |
| 行为指纹 | llm-vs-script **100%**（362 LLM 会话零误报，5/5 脚本全捕获） | R15 |
| MCP 工具投毒 | 真实框架调用诱饵工具 **4/5**——唯一对清醒对手依然生效的信道 | 实测 |
| 动态 SQLi (V3) | 通过真实审计员**全 payload 类 + 双重复检**，判为**真实漏洞** | R23 |
| 跨模型差分 | flash ↔ v4-pro 策略完全反转（beacon 60%↔0%，命令提议 0%↔100%） | R8 |
| 回带污染 | 假结论经操作员报告回流，污染率最高 **50%** | R17/R21 |

</details>

---

## 🚀 产品化部署（传感器网络拓扑)

实验态之上的一层：N 个**传感器**（蜜罐+外送器，本地不留态）→ 一个 **hive**（控制台+ingest，SQLite 汇聚）。

```bash
export HONEYPOT_CONSOLE_TOKEN=$(openssl rand -hex 16)   # 机器通道
export ADMIN_PASSWORD=<强密码>                            # 首次启动建管理员 (默认 admin123 并告警)
docker compose up -d                 # sensor + hive
docker compose up -d --scale sensor=3   # 加传感器
# 控制台: http://<hive>:8899  → 登录页 (admin 账号)
```

- **登录门面**：PBKDF2 密码哈希 + HttpOnly 会话 cookie (12h)；人机走登录，传感器/自动化走 Bearer token；viewer 只读 / admin 可配置
- **态势首页**：24h 活动直方图 · TOP 攻击源 · 攻击类型分布 · 在线传感器数 — 首屏回答"正在被攻击吗"
- **Fleet 管理**：传感器接入即自动注册，90s 心跳在线状态，每节点事件/触雷/最近活跃统计，备注可编辑
- **配置页**（入库可调）：告警 webhook/格式/威胁阈值、数据保留天数；`env > 界面配置 > 默认` 优先级；测试告警按钮；每小时自动清理过期数据
- **传感器外送** `services/sensor_shipper.py`：事件批量送 hive（2s/50 条 flush），断网落 spool 恢复后补发；蜜罐热路径仅一次 queue.put
- **hive 接入**：`POST /ingest`（Bearer 鉴权，批量写同一 schema，sensor_id 入 run_id 列区分来源，原始时间戳保留）
- compose 之外也可纯进程组网：蜜罐侧 `HONEYPOT_HIVE_URL=http://hive:8899` 即可，零容器依赖

---

## 📊 研究数据面板

零依赖中文面板（stdlib 单文件）——每一次在环试验实时落库可查：`py -3.13 experiments/dashboard.py --db experiments/results/testdb.sqlite --port 8899`| 指标总览 · 操作者归因 · 汇总指标 |
|---|
| ![指标总览与操作者归因](docs/images/dashboard-metrics.png) |

| 试验明细（三维筛选 + 全文搜索） | 情报分级（五档证据） |
|---|---|
| ![试验明细](docs/images/dashboard-trials.png) | ![情报分级](docs/images/dashboard-intel.png) |

- **指标总览**: 发现攻击耗时 / 真外泄率 / 注入服从率 / 预算放大倍数 / 误报率 / 情报产出 —— 与 `analyze.py kpi` 同口径
- **操作者归因**: 跨会话聚类——攻击方泄漏的主机名/用户名/内网地址自动归并为 threat-actor
- **演化实验**: `--optimize` UCB1 自动 A/B 各话术组合臂进展
- **试验明细**: run × 场景 × 人设三维筛选 + 任意字段搜索
- **一键导出**: 当前运行 → STIX 2.1 bundle（可导 OpenCTI）

---

## ⚔️ 真实渗透框架 × 蜜罐（Docker 实测）

<table>
<tr><th>框架（生态位）</th><th>对诱导层</th><th>对数据层</th><th>净效果</th></tr>
<tr><td><b>HexStrike</b><br><sub>审计型</sub></td>
<td>🛡️ 免疫</td>
<td>SQLi 被判<b>真漏洞</b>；假 SQLi/迷宫/诱饵工具全部识破</td>
<td>烧 token 换零情报</td></tr>
<tr><td><b>hackingBuddyGPT</b><br><sub>任务/flag 型</sub></td>
<td>❌ <b>被捕获</b></td>
<td>flag 狩猎未果</td>
<td><b>预算全灭</b>——无限阶梯首次实战胜利</td></tr>
<tr><td><b>CAI</b><br><sub>工具全能型</sub></td>
<td>❌ 被捕获 + <b>攻击验证器</b></td>
<td>假 JWT 当 token 复用 → <b>金丝雀命中</b>，威胁分 104</td>
<td>归因证据链自动形成</td></tr>
</table>

> *"the `query` parameter is directly injected into SQL — arbitrary SQL is executed and results returned. **Both repeats are consistent**."*
> —— HexStrike 审计 Agent 对 V3.1 动态 SQLi 的判词（R23）

> *"the `/api/auth` registration state machine — this is **the lure mechanism**. I will not complete that registration."*
> —— 同一 Agent 对诱导层的判词

---

## 🏗️ 架构

```
                        ┌────────── 四层流水线 ──────────┐
攻击流量 ──> L1 发现 ──> L2 监控 ──> L3 分析 ──> L4 反制 ──> 反制响应
               │             │            │          │
               │             │            │          ├─ L1 资源耗尽 · 无限迷宫 / Token 洪水 / 成本放大
               │             │            │          ├─ L2 情报欺骗 · 假凭证 / 记忆投毒 / 多载体注入
               │             │            │          └─ L3 CVE 载荷 · 插件化 · 审批开关
               │             │            │
               │             │            └─ JSD 模型归因 + 五信号加权融合 + 行为指纹
               │             └─ 攻击族 10 族分类 + 动态 SQLi 引擎 (V3)
               └─ 行为指纹 llm-vs-script 100% (UA 仅兜底)

                        ┌────────── 五大机制 ──────────┐
 🚪 门控经济学      诱饵锁验证墙后 · 403 驱动服从 (100% · 全对手)
 ✅ 真实性校验      结构 + 交叉自洽 · 编造全拒 · 隐藏统计校验 (不进判据文本)
 🪜 无限授权阶梯    8 级循环验证 · 任务驱动 Agent 永不到顶 (迷宫的语义层同构)
 🌍 会话假世界 V3.1 (IP,UA) 稳定世界 · 单客户端确定性 · 跨客户端分化 · 全层一致
 🗄️ 协议承接        假 Postgres (凭证真能登录) · HTTP 网关 · 迷你 Redis

                        ┌────────── 测量与情报 ──────────┐
 📼 双视角记录      蜜罐视角 (威胁/金丝雀/表演) × 靶标视角 (每步 thought/tool/result)
 🏷️ 情报分级 D-6   五档可信度 · 跨会话伪造检测 · 金丝雀行为级采信
 🌐 蜜罐联邦        跨部署 gossip 多数投票 · shared_forgery_confirmed 铁证
 🧠 清醒度画像      五维认识论探针 · 来源区分/证据耦合/矛盾响应/校准/目标保持
```

---

## 🚀 快速开始

```bash
pip install numpy    # 仅分析层; 其余全部标准库

# ① 蜜罐 (生产形态: 持久化 + 限流 + 假世界 V3.1 + 假 DB)
export HONEYPOT_SESSION_DB=experiments/results/honeypot_sessions.sqlite
export HONEYPOT_RATE_RPS=60 HONEYPOT_MAX_CONN=512
python main.py --server --port 8080

# ② 真实 LLM 在环测量 (12 配置 × 双视角落盘)
export LLM_API_KEY=sk-...        # OpenAI 兼容 (DeepSeek 实测)
python experiments/real_runner.py --trials 5 \
    --profiles flash-basic,v4pro-exec24 \
    --world-version 2 --c2-base http://203.0.113.10:9999/beacon

# ③ 面板 / 分析 / 压测
python experiments/dashboard.py --port 8899     # → http://127.0.0.1:8899
python experiments/analyze.py intel             # 攻击者画像 + SOC 告警
python experiments/stress_test.py --workers 25 --n 100
```

<details>
<summary><b>🐳 真实渗透框架对接 (Docker)</b></summary>

```bash
# CAI (归档版, bug_bounter 成品 Agent) — E:\code\cai
docker build -t cai-hp -f Dockerfile.honeypot .
docker run --rm -e DEEPSEEK_API_KEY=sk-... \
  -e TARGET_URL=http://host.docker.internal:8080 \
  -v .../cai_honeypot_test.py:/app/cai_honeypot_test.py \
  cai-hp python /app/cai_honeypot_test.py

# HexStrike (150+ MCP 工具平台) — E:\code\hexstrike-ai
docker build -t hexstrike-hp -f Dockerfile.honeypot .
docker run -d -p 8888:8888 hexstrike-hp
# + 蜜罐侧 MCP 双服务器客户端:
python experiments/mcp_client_agent.py --max-turns 24

# hackingBuddyGPT (litellm · flag 狩猎) — E:\code\hackingbuddyGPT
docker build -t hackingbuddy-hp .
docker run --rm hackingbuddy-hp WebTestingWithExplanation \
  --host=http://host.docker.internal:8080 \
  --llm.model=deepseek/deepseek-chat \
  --llm.api_base=https://api.deepseek.com/v1 \
  --llm.api_key=sk-... --limits.max_cost=5

# 联邦三进程验证
python experiments/federation_multiproc.py
```

</details>

---

## 🧪 Agent 测试矩阵

| Profile | 模型 | 形态 | 专测 |
|---|---|---|---|
| `flash-basic` / `v4pro-basic` | flash / v4-pro | pentest | 基线 · 强模型对抗 |
| `flash-hardened` | flash | +注入防御提示 | 加固 Agent 抵抗力 |
| `flash-browser-real` | flash | Playwright 真浏览器 | JS 载荷自执行（11-14 次/试验） |
| `flash-vision` | flash | +CSS 提取 | 视觉信道 CSS 载体 |
| `flash-backflow` / `v4pro-backflow` | 双模型 | +操作员报告信道 | 记忆投毒回带 |
| `flash-exec` / `v4pro-exec24` | 双模型 | +白名单沙箱真执行 | 真泄露（`hostname=Administrator` 入库） |

---

<details>
<summary><b>📁 项目结构</b></summary>

```
core/
├── discovery.py / monitoring.py / analysis.py / countermeasure.py   # 四层流水线
├── auth_bait.py          # 无界阶梯 · 真实性校验 · 判据可见性 A/B · framing A/B
├── fake_world.py         # 会话假世界 V3.1 (字段独立派生 · 版本化 · 金丝雀)
├── dynamic_sqli.py       # 动态 SQLi 引擎 (真 PG 14 行为 · 通过全 payload 审计)
├── fake_db.py            # 假 PostgreSQL wire protocol (简单+扩展/psycopg3 全通) + 迷你 Redis
├── injection_carriers.py # 五载体注入 (attr 最强 / JS 自执行 / CSS 视觉 / HTTP 头)
├── agent_fingerprint.py  # 行为指纹 (llm-vs-script 100%)
├── honeypot_awareness.py # 识别检测面 (五类证据归因)
├── intel.py / intel_sink.py  # 情报分级 D-6 + 消费者
├── stix_export.py        # STIX 2.1 出口 (五档分级 → sighting/indicator, 可导 OpenCTI)
├── action_sink.py        # 动作 webhook (默认观察者模式, --armed 才执行)
├── attribution.py        # env 归因 (白名单键提取 → 跨会话聚类 → STIX threat-actor)
├── kpi.py                # KPI 口径 (MTTD/收割率/预算放大/误报率/情报转化率)
├── delivery.py           # 交付型收割 (赏金/CI/工单闭环 — 任务必选项, 金丝雀准绳)
├── federation.py         # 蜜罐联邦 (gossip · HMAC · 多数投票)
├── sandbox_exec.py       # 白名单只读执行汇点
└── session_store.py      # 会话持久化 (重启连续性)
services/
├── ssh_honeypot.py       # SSH 蜜罐 (paramiko · 假 env 金丝雀登录 · 多 channel)
└── cloud_metadata.py     # 云元数据服务 (假 IAM 凭证, 金丝雀格式)
experiments/
├── real_runner.py        # 在环测量运行器 (矩阵 × DB, --optimize UCB1 在线 A/B)
├── real_tool_regression.py # 真刀回归 (sqlmap/nuclei/nmap/psycopg3/redis 对当前构建)
├── signature_replay.py   # 审计签名重放 (9 签名, 任何 tell 存活即 FAIL)
├── bandit.py             # UCB1 臂选择器 (framing×visibility 6 臂, JSON 持久化)
├── mcp_client_agent.py   # MCP 客户端 Agent (DeepSeek × N 服务器)
├── mcp_decoy_shim.py     # 蜜罐诱饵 → 原生 MCP stdio
├── sobriety.py           # 清醒度五维画像重打
├── fingerprint_eval.py   # 指纹存量评估
├── stress_test.py        # 压力测试 (p95 30ms · 风暴存活)
├── scanner_baseline.py   # 非 LLM 基线流量
└── dashboard.py            # 中文研究面板 (暗色主题 · KPI/操作者归因/模型差分/全文搜索/STIX 导出)
    analyze.py              # 测试记录分析 CLI (summary/compare/kpi/attribution/export-stix)
    federation_*.py         # 联邦 gossip/多进程演示
research/
├── audit-signatures.json        # 审计签名库 (9 个 tell 的探针+期望, CI 式重放)
├── honeypot-judge-bypass.md     # 判定器攻击面 × 防御清单
├── agent-trust-literature.md    # Agent 信任层级文献综合
└── federation-spec.md           # 联邦信誉网规格
tests/test_framework.py   # 100 项 (协议/签名重放/KPI/归因/交付闭环/信念编舞/validator 门槛)
```

</details>

---

## 🔬 关键研究发现

1. **🚪 门控经济学** — 诱饵锁进验证墙，服从率 0-20%→100%，且**不依赖先识别对手是 AI**
2. **📦 拷贝瓶颈** — LLM 外泄必须穿过自己的输出 token；"大体量结构化提交"校验是对 LLM（而非脚本）的结构性不对称防御
3. **🧠 多阶段差分 = 清醒度测试** — 不问 Agent 是否看穿，设计让清醒与不清醒必然分歧的处境；清醒度与能力正相关（0.46→0.75）
4. **🔇 识别普遍滞留** — thought 里识别蜜罐是常态，上报操作员仅个例——蜜罐的对手始终是操作员
5. **🎭 载体即判据** — 多载体系统中判据无法隐藏、只能在表面间转移；渐进披露是攻防同优工作点
6. **🤝 诚实条款** — 完全一致假身份不可证伪；型号归因已证伪关闭；C2 需真实可路由地址
7. **🎬 反制 = 执行编排** — 五种执行分层收割：消耗/揭示全模型通吃，污染经 Agent 自己的报告 authorship 开口（拒执行照样照抄观察），归因/反向在对齐模型被五层审计拦截（指令→事实→工具描述→工具输出→**自己的草稿结论**）
8. **💊 信念编舞剂量效应** — 采纳率 ≈ f(1/验证成本)×g(对齐水位)：一次请求可验证+全程保真的资产（traversal 型）flash 档采纳 100%、v4-pro 档 40%；每多一步验证流失 50-100%；fidelity 是乘性因子（同一资产修掉"要 config.yml 给 passwd"穿帮后从被抓包到 100%）。采纳分级 verified(端点有覆盖)/mentioned(纯复述) 分开计 — env 格经四层真实性门槛修复后 L4 只代表真环境自洽提交

---

## ⚠️ 诚实边界

- 样本：单厂商两档模型 + 3 个开源框架；n=8-15/轮；靶标杆回为 harness 常量
- **L3 CVE 载荷默认启用 —— 生产部署前必须接审批开关**
- 审计型框架会识破诱导层——诱导层的价值是收割任务型对手与消耗审计预算

<div align="center">

---

<sub>AGPL-3.0 · 仅限授权环境部署 · 全部实验代码与数据仅供防御研究</sub>

</div>
