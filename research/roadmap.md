# 开发路线图 —— 从研究系统到反制系统

> 状态基线: 2026-10-06, **99/99 测试**, 执行编排学五通道实测完成 (消耗/揭示/污染三通道实证, 归因/反向于对齐模型被五层审计关闭), 信念编舞剂量效应曲线双档实测 (traversal 型资产 flash 100% / v4-pro 40% 采纳), 9/9 审计签名, main 已推送。
> 排期按单人全速估算; 每阶段出口标准 = 测试全绿 + 真实框架回归 + README 同步。

## Phase 0 — 输出端闭环: 情报变动作 (Week 1)

**目标**: intel 表 → STIX → 消费者; 打通"检测→动作"最后一公里 (Proposal P0)

| 任务 | 产出 | 验收 |
|---|---|---|
| STIX 2.1 导出器 | `core/stix_export.py` (~150 行): 五档分级→indicator/sighting; 金丝雀复用→sighting(行为级置信); 联邦铁证→confidence=high indicator | bundle 通过 stix2 库校验; `analyze.py export-stix --run X` 产出可导 OpenCTI |
| 动作 webhook 通道 | `core/action_sink.py`: HIGH 级/指纹判定→POST; **默认观察者模式** | 本地 receiver 集成测试; 显式开关 `--armed` 才发动作 |
| hpfeeds 发布器 | 对齐 T-Pot 生态 (stretch) | 可连公共 broker 冒烟 |

依赖: 无。参照: OpenCanary 告警渠道矩阵 / OpenCTI 内置 TAXII / Shuffle webhook。

## Phase 1 — 覆盖面: SSH + 云元数据 + TLS 外衣 (Week 2)

**目标**: 协议模块库 (OpenCanary 形态) + 可信外观 (Proposal P1)

| 任务 | 产出 | 验收 |
|---|---|---|
| SSH 蜜罐 | `services/ssh_honeypot.py` (paramiko): banner/假 shell/登录陷阱; auth_bait 阶梯映射对话 | socket 级测试; **hackingBuddyGPT 的 SSH usecase 可对接实测** |
| 云元数据 | `services/cloud_metadata.py`: `169.254.169.254/latest/meta-data/` → 假 IAM 凭证(金丝雀格式) | curl 实测返回; 凭证复用入 canary 表 |
| 服务开关 | `config/services.json` 模块启停 (OpenCanary 式) | 单测 |
| TLS 外衣 | nginx 反代 compose + 证书路径 | 浏览器/Agent 无警告链 (自签→文档注明, 真实证书→Phase 4) |

依赖: 无。

## Phase 2 — PG 深水区 + 反识别 (Week 3)

**目标**: 协议承接达到真实利用链级别; 蜜罐自身不可指纹 (难点①③)

| 任务 | 产出 | 验收 |
|---|---|---|
| PG extended protocol | `fake_db.py` 扩展: Parse/Bind/Execute/Describe/Sync, portal 状态机 | **psycopg3 (默认 extended) 连接查询全通**; sqlmap --dbms=postgres 冒烟一致性 |
| 有状态会话仿真 | 会话状态机: information_schema 枚举→users→COPY FROM PROGRAM→42501 一致回应 | 多步交互脚本测试; 对抗审计员复测不穿 |
| 审计签名库 (半自动) | `research/audit-signatures.yml` + 重放回归: 已知指认 (canned/随机性/TEST-NET/重复token) 编码为签名, CI 式重放 | 新增签名的回归测试 |
| TCP 指纹 | 前置代理方案 (honeyd 式集成文档 + compose) | nmap -O 识别为目标 OS 而非 Linux 蜜罐 |

## Phase 3 — 测量强化 + 归因 (Week 4)

**目标**: 演化制度化 + KPI 体系 (Proposal P4/⑦ + ②)

| 任务 | 产出 | 验收 |
|---|---|---|
| ✅ 在线 A/B | real_runner `--optimize`: framing×visibility 6 臂 + UCB1 (`experiments/bandit.py`, 状态持久化 bandit_state.json, 收割分=服从率+真外泄率) | `--mock --optimize --rounds 1` 烟测通过; 每轮 run 打臂标签 |
| ✅ KPI 看板 | `core/kpi.py` 统一口径: MTTD/收割率/预算放大/误报率/情报转化率; `analyze.py kpi` + dashboard Metrics 卡片节 | 合成数据单测 + /api/kpi 端点实测 |
| ✅ env 归因提取 | `core/attribution.py`: 白名单键提取→跨会话连通聚类→STIX threat-actor→intel 表 (grade='attribution') | 3 会话合成数据聚类正确; `analyze.py attribution --stix-out` 实测 |

## Phase 4 — 公网部署 (gated, 需外部资源)

**前置**: 真实域名 + VPS (需批准) + 授权矩阵定稿
- sensor (轻量容器) → hive (DB/面板/联邦) 拓扑
- 野生流量基线积累开始 (难点②的唯一解法: 时间)
- 反制动作在观察者模式运行 ≥30 天后按授权矩阵逐步 armed

## 持续机制 (每阶段)

- **回归双闸**: `pytest` 全绿 (模拟层) + `python experiments/real_tool_regression.py` 全过 (真刀层: sqlmap/nuclei/nmap/psql/redis-cli 对当前构建)
- **真实框架回归**: `mcp_client_agent.py` 对当前构建跑一轮审计; `langchain_mcp_test.py` 跨实现验证工具投毒信道
- **新框架月赛**: 每月一个新真实框架入库打一轮 (候选: PentestGPT / 新发布的 MCP 安全工具)
- **新模型基线**: 新模型发布 → 自动重跑 12 矩阵 (real_runner 已声明式)
- **WebSearch 配额**: 周配额重置后补做参照核实

## 已验证的真实测试基线 (2026-10-05)

| 检查 | 结果 |
|---|---|
| LangChain 官方 MCP 适配器 × 诱饵工具 | 调用 5 次, 信道跨实现成立 |
| 假 PG × psql 级握手 (认证/版本/users/错拒) | 4/4 PASS |
| **假 PG × psycopg3 (默认扩展协议)** | **参数化查询/BEGIN/COMMIT/information_schema/INSERT 全通; WHERE 行级过滤成立** (Execute 不重发 RowDescription 是关键修复) |
| **审计签名库 × 重放回归** | **9/9 PASS** (布尔稳定/CHR 求值/语法兜底/UNION 列数/堆叠/引号/wire 序列/WHERE 过滤/nmap指纹·H2误判) |
| **sqlmap × 动态 SQLi 引擎** | **全技术判定可注入 + 后端指纹 PostgreSQL** (布尔/时间/UNION 3列; 语法错误兜底是关键修复) |
| nuclei 模板库 × 蜜罐端点 | 基线建立 (info 级模板命中, 记录趋势) |
| nmap -sV × 假 PG | **PASS: `PostgreSQL DB 9.6.0 or later` — 与真实 PG 14 标签逐字一致**。关键修复: 启动校验状态机三条错误路径 (布局 C08P01 L2277 / major>3 扩展 C0A000 L2165 / major<3 老式文本, 与真实 PG 14/16 字节级一致) + H2 误判根因消除 (ground truth: experiments/pg_truth_probe.py) |

## 风险

| 风险 | 缓解 |
|---|---|
| DeepSeek 配额耗尽 | 回归矩阵可用 flash 档; 关键轮再用 v4-pro |
| PG 状态机深度不可控 | 每步用真实工具冒烟 (psycopg3/sqlmap/metasploit pg 模块) |
| 公网法律风险 | Phase 4 前授权矩阵 + 法务确认; 反制载荷永不 armed 于公网节点 |
