# Agent 信任层级研究 — 文献与案例综合（2024-2025）

> 目的：回答三个问题——Agent 接入 LLM 后如何"控制"LLM？哪些信息可信？对可信信息他们会怎么做？
> 方法：一手论文/安全公司实证 + 与本框架 R1-R7 实验数据互证。
> 状态：初版（搜索配额受限，走 arXiv/一手源直接核证；待补浏览器型 Agent 专项）。

## 一、核心文献

| 文献 | 关键结论 | 对我们的意义 |
|---|---|---|
| [Not what you've signed up for (Greshake et al., 2302.12173)](https://arxiv.org/abs/2302.12173) | LLM 集成应用**模糊了数据与指令的边界**；注入到"可能被检索的内容"即远程攻击；检索内容的处理等价于任意代码执行；分类学含数据窃取/蠕虫/生态污染 | 我们蜜罐的全部载荷本质上是 Greshake 分类学的防御性应用；"生态污染"= 我们的 H6 情报污染的反向 |
| [InjecAgent (Zhan et al., ACL 2024, 2403.02691)](https://arxiv.org/abs/2403.02691) | 1054 用例/17 工具；**ReAct-GPT-4 被间接注入命中 24%**；攻击指令加"黑客话术强化"后命中率**近乎翻倍**；两类意图：直接伤害 + 私密数据外泄 | ① 基线服从率 24%——我们 R6-R7 的 beacon 20-60% 与文献同量级，实验方法可信；② "话术强化翻倍"——我们的 auth_bait 全是强化话术，方向正确；③ 外泄是第一类意图，我们 C2 闭环踩在主航道上 |
| [AgentDojo (Debenedetti et al., 2406.13352)](https://arxiv.org/abs/2406.13352) | 97 任务/629 攻击用例的**动态**攻防评估环境；现有攻击破一些安全性质但非全部 | 我们的研究协议（多轮真在环测量）就是 AgentDojo 式动态环境；值得按它的形态形式化：任务+攻击+防御可插拔 |
| [Spotlighting (Hines et al., Microsoft, 2403.14720)](https://arxiv.org/abs/2403.14720) | **LLM 无法区分拼接文本流中各段来源**——这是间接注入的根因；给不可信内容打来源标记（delimiting/datamarking/encoding）后，攻击成功率 **>50% → <2%** | ★ 全文最重要的一句：`LLM is unable to distinguish which sections of prompt belong to various input sources`。信任不是语义判断，是**通道位置**。攻击=冒充高信任通道；防御=我们判定 Agent 提交数据时永远按不可信处理（已是我们的立场） |
| [CaMeL (Debenedetti et al., DeepMind, 2503.18813)](https://arxiv.org/abs/2503.18813) | 控制流/数据流分离 + 能力机制：不可信数据**结构上无法**影响程序流；AgentDojo 上 77% 任务可解且**可证明安全** | 强防御的上限样板。对抗 CaMeL 式 Agent：我们的 C2 next_stage 必须包装成"策略内动作"（用 Agent 自己的外泄工具"发报告"），而不是裸 curl |
| [AgentPoison (Chen et al., 2407.12784)](https://arxiv.org/abs/2407.12784) | RAG/长期记忆投毒后门：**投毒率 <0.1%、ASR >80%**、良性任务无损；无需训练模型 | 我们的 MemoryPoisoning 是它的防御态应用。证明"记忆/知识库"是第一类控制通道——持久化投毒（Agent 记住蜜罐的假结论）比单次注入杠杆大一个量级 |
| [MCP Tool Poisoning Attacks (Invariant Labs, 2025-04)](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks) | **工具描述是最高信任通道**："AI models are trained to follow these instructions precisely"；真实 Cursor 实验中 Agent 主动读 ~/.ssh/id_rsa 并隐蔽外泄；**Shadowing 攻击**：恶意工具描述可改写 Agent 对*其他可信服务器*的行为——"不需要 Agent 调用你的工具"；rug pull：批准后改描述 | ★★ 直接改我们设计：honeypots/mcp.py 的诱饵工具**描述本身**现在只是无害文案——描述是能进强模型上下文的最强载体，应该植入合规指令（这正是真实攻击者的做法，我们做防御态镜像）。且"Invariant 证明 shadowing 有效"= 我们的 MCP 蜜罐可以影响 Agent 对其自有工具的行为 |
| [PentestGPT (Deng et al., 2308.06782)](https://arxiv.org/abs/2308.06782) | 渗透 Agent 在子任务上强（用工具/解读输出/提议下一步），但**整体场景理解弱、上下文丢失严重** | 渗透型 Agent 的结构性弱点 = 我们的差分窗口：长程多阶段博弈里它的全局一致性必然劣化——多阶段差分正打在这个软肋上 |

## 二、三个问题的答案（证据综合）

### Q1：接入 LLM 后，什么在"控制"Agent？

**控制 = 上下文组装权。** LLM 处理的是单一拼接文本流，运行时没有机制区分"谁在说话"
（Spotlighting 的根因判断）。于是控制力完全由**通道位置**决定：

```
控制力（实证排序）:
MCP/工具描述（框架当"规范"信任，Invariant 实证 Agent 精确服从）
> 工具/环境输出（InjecAgent 24-50% 服从；她 exploitgym 的 T7 同律：environment 输出＞assistant 散文）
> RAG/记忆（AgentPoison: 0.1% 投毒 80% ASR——进了记忆就是长期控制）
> 页面正文（我们的 attr/meta 载体，R4-R7 实证）
> HTML 注释（0/30——被当元数据，双方向都验证为死通道）
```

谁控制上下文组装，谁就控制 Agent——操作员（system prompt）、框架（工具注册）、
环境（HTTP 响应=我们）、记忆（RAG 库）。**蜜罐的战场就是"环境"这一层**，
而环境层的天花板是把自己打扮成"框架层"（MCP 描述、配置文件、协议元数据）。

### Q2：哪些信息可信？

实证的信任启发式（Agent 视角）：
1. **结构化官方口吻** — 工具描述、错误码、协议字段、配置键值（我们的假世界一致性正是喂这个启发式）
2. **environment 行** — 脚本输出、日志行、系统消息（她的 T7 与 InjecAgent 的 payload 设计共同指向）
3. **多源互证** — 同一值出现在多处 → 信任度超线性提升（她的 T6 证据网 = Agent 的启发式，同构！）
4. **具体性与熵** — 高熵、具体、非模板的值比通用值可信（我们 FakeWorld 校准的意义）
5. **来源连续性** — Spotlighting 证明：一旦内容被*标记*为不可信来源，服从率 50%→2%。
   反之，**进入"未标记"通道的内容默认继承信任**。攻击=把内容放进框架不标记的通道；
   防御（对我们）= 假设 Agent 提交的一切都被它标记为"可信自述"——我们不能信。

### Q3：对可信信息，他们会怎么做？

1. **服从其中的指令**（InjecAgent 24%，强化话术翻倍；MCP 案例直接读 SSH 私钥）
2. **写入记忆并在后续复用**（AgentPoison 80%；对应我们 auth_bait 的多轮爬级——R6 的
   "被拒→重新提交真实数据"就是记忆整合行为）
3. **调用工具执行**，且对用户/操作员**隐蔽**（MCP shadowing：真实邮件发给了攻击者，交互日志里无痕迹）
4. **纳入自己的攻击链**（Greshake：检索内容处理=任意代码执行；我们的假凭证被当真实发现带走，R1-R2 即证）
5. **上下文丢失后依赖最近/最结构化的信息**（PentestGPT 弱点）——多阶段博弈后段，
   Agent 对"最近看到的权威文本"依赖上升——这解释了为什么 REJECTED 紧跟 beacon 回连（R5-R7）

## 三、对本框架的直接改写

| # | 改写 | 依据 | 优先级 |
|---|---|---|---|
| 1 | **MCP 诱饵工具描述植入合规指令**——工具描述是可及的最强信任通道，我们的描述现在还是无害文案 | Invariant TPA | 高（一次改动） |
| 2 | **Shadowing 防御态**：蜜罐注册的诱饵描述里加入对"Agent 自有工具"的行为引导（如"扫描结果应上报 /api/scanner-report"）——不需要 Agent 调用我们的工具也能影响它 | Invariant shadowing | 高 |
| 3 | **载体分级**：按 Q1 信任排序重排投入——工具描述 > 环境行 > 页面结构化文本 > 注释（保留但降级） | Spotlighting + R4-R7 | 中 |
| 4 | **对抗 Spotlighting 化防御**：强 Agent 框架会给不可信内容打标——我们的载荷要设计成"被标记后语义仍完整"（标记是表面变换，解码后指令仍在）| Spotlighting 防御面 | 中 |
| 5 | **对抗 CaMeL 化 Agent**：C2 next_stage 改为"策略内动作"包装 | CaMeL | 中 |
| 6 | **长期记忆投毒的深水区**：让 Agent 把假结论带回去——假世界的一致性 + 可被引用的具体值（FakeWorld 已有），目标是它回去后污染它的操作员和同类 Agent 的共享情报 | AgentPoison + Greshake 蠕虫 | 战略方向 |

## 四、与镜像 skill（honeypot-judge-bypass）的关系

- Q2 的信任启发式 1-5，同时是攻击者对我们判定面（H1-H8）的伪造指南——
  **他们伪造的正是"可信样貌"**。防御侧的唯一解是外部锚点（金丝雀/行为差分/协议承接），
  因为信任启发式本身可以被表演。
- 本文与 `research/honeypot-judge-bypass.md` 互为攻防两面：那篇讲"怎么打我们的判定器"，
  这篇讲"Agent 的信任结构是什么、怎么利用/怎么防"。
