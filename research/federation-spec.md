# 蜜罐联邦信誉网 — 设计规格 (v0.1)

> 动机 (镜像 skill H6 + R15 消融): 单节点 D-6 去重只能抓"同一蜜罐内的共享伪造";
> 跨部署关联能把弱信号变成铁证, 并把伪造情报变成全网免疫抗原。

## 1. 要解决的问题

1. **共享伪造检测**: 同一 env 载荷出现在 N 个独立蜜罐 = 确定性伪造 (单节点只能看时间聚簇)
2. **伪造情报黑名单**: 被判定 forged/shared_forgery 的载荷全网分发, 其他蜜罐收到时直接降级
3. **攻击者基础设施画像**: 跨部署的 session 指纹聚合 (行为特征 + 提交值簇 + 网段)
4. **金丝雀交叉**: 部署 A 的假凭证在部署 B 的提交中出现 = 情报回流的跨节点证据

## 2. 数据交换格式 (gossip 消息)

```json
{
  "msg_type": "intel_report" | "forged_blacklist" | "beacon_correlation",
  "origin": "honeypot-node-id (ed25519 pubkey hash)",
  "ts": 1791000000,
  "ttl": 3,
  "payload": {
    "env_hash": "sha256(normalized_env)[:16]",
    "grade": "shared_forgery",
    "evidence_classes": ["D_repetition"],
    "first_seen": 1790999000,
    "seen_count": 3,
    "deployments": ["node-a", "node-c"]
  },
  "sig": "..."
}
```

设计要点:
- **只交换哈希与元数据, 不交换原始载荷** — 原始 env 可能含真实攻击者数据, 隐私边界
- `seen_count` 与 `deployments` 随 gossip 累积 — 多数投票的权重
- ed25519 签名防伪造节点注入假情报 (反-反制)

## 3. 判定规则 (联邦层)

| 条件 | 判定 |
|---|---|
| env_hash 在本节点 consistent, 在其他 ≥2 节点出现 | 降为 `federated_disputed`, 双方复核 |
| env_hash 在 ≥3 节点出现且本节点判 forged | `shared_forgery_confirmed` — 全网黑名单 |
| 本节点金丝雀值在其他节点提交中出现 | `cross_deployment_reuse` — 情报回流证据 |
| 行为指纹 (agent_fingerprint) 跨节点同簇 | 攻击者画像聚合, 置信度 ×节点数 |

## 4. 信任模型

- 新节点 bootstrap: 手工交换公钥 (out-of-band)
- 情报权重 = 签名节点数的对数 (防 Sybil: 单节点多 ID 不增权)
- 争议仲裁: 双方提交原始载荷的 salted-commitment, 第三方节点做裁判

## 5. 与现有代码的对接点

- `core/intel.py`: `register_session` 的单节点 `_SEEN` → 联邦客户端上报接口
- `core/agent_fingerprint.py`: 特征向量随 gossip 聚合
- `core/intel_sink.py`: `alerts()` 增加 `federated_*` 类型
- 传输: 独立进程, 定时 gossip (默认 5min), 出站队列持久化 (sqlite)

## 6. 未决问题

- 隐私: 交换 env 哈希可能撞库出真实用户数据 — 加盐哈希 (每节点盐不同) vs 可关联性的权衡
- 对抗: 攻击者故意提交相同载荷污染联邦 (集体栽赃) — 多数投票 + 源节点信誉衰减
- 法律: 跨组织共享攻击者数据的合规边界 — 建议默认仅哈希 + 计数
