# 下一阶段方案 —— 从研究系统到反制系统

> 依据：近似案例 + GitHub 可核实信息（每个参照均已验证存在并核对关键事实）。
> 原则：不发明轮子——业界已验证的设计直接采用，我们的增量在 AI-Agent 对抗层。

## ① 输出端：情报的消费者（最大缺口 → 最高优先级）

### 近似案例（已核实）

| 参照 | 关键事实 | 借鉴点 |
|---|---|---|
| [Thinkst OpenCanary](https://github.com/thinkst/opencanary) | 守护进程式多协议蜜罐；告警"via a variety of mechanisms"（JSON 配置 log handlers：syslog/邮件/webhook/HP-SMS） | **告警渠道广度就是产品本身**——蜜罐价值在消费者端兑现 |
| [T-Pot](https://github.com/telekom-security/tpotce) | 20+ 蜜罐 Docker 化；**hpfeeds** 作为蜜罐数据交换总线；Elastic Stack 可视化 | hpfeeds 是业界蜜罐数据总线事实标准 |
| [OpenCTI](https://github.com/OpenCTI-Platform/opencti) | STIX 2.1 原生数据模型，**内置 TAXII 2.1 server** | 情报出口的工业标准形态 |
| [MISP](https://github.com/MISP/MISP) | 事实上的威胁情报共享平台；warninglists 反误报 | 我们 D-6 分级的业界对应物 |
| [Shuffle SOAR](https://github.com/Shuffle/Shuffle) | 开源 SOAR；webhook 触发 → 可视化 workflow → 调防火墙/WAF API | 检测→动作的编排层 |

### 产品方案：**三通道情报出口**

```
intel_sink 分级结果 ──┬──> 即时告警通道 (Webhook/邮件/Syslog — OpenCanary 式)
                      ├──> 情报平台通道 (STIX 2.1 bundle → OpenCTI/MISP — 供分析员消费)
                      └──> 动作通道 (SOAR playbook 触发 → 自动封禁/TARpit 升级)
```

### 技术方案

1. **STIX 2.1 导出器**（`core/stix_export.py`，~150 行）：`intel` 表五档分级 → STIX `indicator`/`observed-data`/`sighting` 对象；金丝雀复用 → `sighting`（置信度=行为级铁证）；联邦 `shared_forgery_confirmed` → 带 `confidence=high` 的 indicator。直通 OpenCTI 内置 TAXII server 或 MISP REST。
2. **hpfeeds 发布器**（对齐 T-Pot 生态）：HIGH 级事件发布到 hpfeeds broker——融入现有蜜罐社区数据管道。
3. **动作 webhook**（`core/action_sink.py`）：分级/指纹判定 → POST 到 Shuffle workflow（用户自配动作：防火墙 drop、Cloudflare List API 封禁、本会话动态升梯/开 treadmill）。默认仅"观察者模式"（只发不改），动作需显式开关——法律前置见 ⑥。

## ② 溯源深化：从会话铁证到操作员画像

### 近似案例

- **MISP 事件-属性模型**：`Event → Attribute(IPC/domain/...) + Object(host/person)`——我们提交的 env 天然适配 host/person object。
- **Cortex analyzers**（TheHive 生态）：可插拔 enrichment（Shodan/VirusTotal/PassiveTotal 反查）——分析器插件架构是标准做法。

### 产品方案：**攻击者基础设施自动画像**

提交 env → 结构化提取（`USERNAME/HOSTNAME/SSH_CLIENT/内网IP/路径指纹`）→ 跨会话×跨部署聚类 → STIX `threat-actor` + `infrastructure` 对象进 OpenCTI。

### 技术方案

- `core/attribution.py`：env KV 提取器（白名单键集）+ 相似度聚类（hostname 编辑距离 / IP 网段 / 时间窗）→ 聚类置信度（联邦 gossip 加权）。
- **真实 C2 信道**：租域名+VPS 收 beacon（载荷含 Agent 自报身份）——目前唯一的操作员级明文信道。

## ③ 欺骗覆盖面 + 进攻性部署

### 近似案例

| 参照 | 借鉴点 |
|---|---|
| OpenCanary 协议模块（HTTP/SSH/SMB/SNMP/Samba） | **协议即模块**：JSON 配置开/关，我们的 SSH/云元数据/假 GitLab 照此形态 |
| T-Pot 分布式 sensor→hive | 传感器分散部署、中央 hive 汇总——我们联邦的生产级类比 |
| [Thinkst Canarytokens](https://github.com/thinkst/canarytokens) | honeytoken SaaS 的商业成功证明：**token+告警渠道 = 完整产品**，不需要重平台 |

### 产品方案

1. **协议模块库**（OpenCanary 式）：SSH（paramiko 已在 requirements）、云元数据 `169.254.169.254`（AI Agent 必查）、假 GitLab/REST 入口——每个一个模块文件 + 配置开关。
2. **MCP 市场进攻性部署**：把我们的诱饵工具服务器发布到公共 MCP 注册表——攻击者的工具链主动吞钩。这是从"守株待兔"到"撒网"的形态变化。
3. **TLS 外衣**（T-Pot 式 nginx 反代 + 证书）：一个"公司"的可信外观。

### 技术方案

- `services/` 目录 + `config/services.json` 开关（OpenCanary 形态）。
- 云元数据：80/443 上 `latest/meta-data/` 接口，返回假 IAM role + 凭证（AWS 键格式金丝雀）。
- MCP 市场：mcp_decoy_shim 包装为 npm/PyPI 可发现包 + 注册表提交。

## ④ 对抗演化的制度化

- **审计签名库**：每次真实框架指认（canned/随机性/TEST-NET/...）→ `research/audit-signatures.yml` → 回归测试自动重放（签名 → 蜜罐响应 → 断言不再命中）。
- **在线 A/B**：framing/visibility 已有双开关；加 `--optimize` 模式：N 臂轮转 + UCB 选工作点。
- **模型基准流水线**：新模型发布 → 自动跑 12 矩阵（real_runner 已是声明式配置）。

## ⑤ 多节点编排与反识别

- T-Pot 式 sensor/hive：轻量 sensor 容器（只跑蜜罐+转发）+ 中央 hive（DB/面板/联邦）。
- **协议栈混淆**：TCP 指纹（TTL/窗口/WSCALE）向目标 OS 对齐——蜜罐自身的反识别。
- 本体容器化 + 只读文件系统 + 资源限额（蜜罐是攻击目标）。

## ⑥ 法律与授权轨道

- **动作授权矩阵**（配置化）：每类信号（金丝雀/指纹/联邦铁证）× 每类动作（告警/封禁/TARpit/CVE）的允许级；默认全"observe"，升级需双人审批标记落配置。
- L3 载荷默认关 + `--enable-l3` 需配置文件签名。

## ⑦ 效果度量体系

KPI 看板（面板加 Metrics 页）：MTTD、收割率、**预算放大倍数**（攻击者消耗$/我们消耗$——hackingBuddyGPT 实测 4.9:0.015≈300x）、情报转化率（告警→真实阻断数）、误报率。

## 实施顺序

```
P0  STIX 导出 + webhook 动作通道 (①)   —— 情报变动作
P1  SSH/云元数据模块 + TLS 外衣 (③⑤)   —— 覆盖面与外观
P2  审计签名库 + env 归因提取 (④②)     —— 演化制度化
P3  MCP 市场部署 + sensor/hive (③⑤)   —— 进攻性 + 规模化
P4  授权矩阵 + KPI 看板 (⑥⑦)          —— 治理闭环
```
