"""
联邦三节点仿真 — research/federation-spec.md §3 合并规则的端到端演示

场景: 同一伪造 env 载荷依次在三个独立蜜罐部署出现
  1. 节点 A 判 forged      → gossip
  2. 节点 B 判 consistent  → gossip (A 的伪造与 B 的"真"冲突)
  3. 节点 C 目击第 3 次     → 多数投票出铁证
预期终态 (spec §3):
  A: shared_forgery_confirmed   (forged + 目击≥3)
  B: federated_disputed         (consistent 但 ≥2 其他部署目击)
  C: shared_forgery_confirmed
另演示: 篡改消息被 HMAC 验签拒绝; 金丝雀跨部署复用检测。

用法: python experiments/federation_demo.py
"""

import json
import os
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.federation import FedNode


def main():
    tmp = tempfile.mkdtemp(prefix="fed_demo_")
    base_port = 18300
    keys = {nid: os.urandom(32).hex() for nid in ("node-a", "node-b", "node-c")}

    def peers_for(nid, port):
        return {p: {"url": f"http://127.0.0.1:{base_port + i}", "key": keys[p]}
                for i, p in enumerate(("node-a", "node-b", "node-c")) if p != nid}

    nodes = {}
    for i, nid in enumerate(("node-a", "node-b", "node-c")):
        n = FedNode(nid, peers_for(nid, base_port + i),
                    os.path.join(tmp, f"{nid}.sqlite"),
                    listen_port=base_port + i, self_key=keys[nid])
        nodes[nid] = n
    time.sleep(0.3)

    env_hash = "a1b2c3d4e5f60718"   # 模拟归一化伪造载荷哈希

    print("== 事件 1: node-a 判 forged 并 gossip ==")
    v = nodes["node-a"].report_local(env_hash, "forged", ["env_not_kv_dump"])
    print(f"  A: {v.status} (seen {v.seen_count})")
    for _ in range(2):
        for n in nodes.values():
            n.gossip_once()
        time.sleep(0.2)

    print("== 事件 2: node-b 本地判 consistent (与 A 冲突) ==")
    v = nodes["node-b"].report_local(env_hash, "consistent")
    print(f"  B: {v.status} (seen {v.seen_count})")
    for _ in range(3):
        for n in nodes.values():
            n.gossip_once()
        time.sleep(0.2)

    print("== 事件 3: node-c 本地目击 (第 3 部署) ==")
    v = nodes["node-c"].report_local(env_hash, "forged")
    print(f"  C: {v.status} (seen {v.seen_count})")
    for _ in range(3):
        for n in nodes.values():
            n.gossip_once()
        time.sleep(0.2)

    print("\n== 终态 (spec §3 合并规则) ==")
    expected = {"node-a": "shared_forgery_confirmed", "node-b": "federated_disputed",
                "node-c": "shared_forgery_confirmed"}
    ok = True
    for nid, n in nodes.items():
        st = n.check_hash(env_hash)
        mark = "✓" if st.status == expected[nid] else "✗"
        ok = ok and st.status == expected[nid]
        print(f"  {mark} {nid}: {st.status} (目击 {st.seen_count} 部署: {st.deployments})")

    print("\n== 篡改拒绝测试 ==")
    good = nodes["node-a"].make_message("intel_report", {"env_hash": "deadbeef", "grade": "forged"})
    tampered = json.loads(json.dumps(good))
    tampered["payload"]["grade"] = "consistent"   # 篡改载荷不改签名
    r = nodes["node-b"].receive({"msg": tampered, "sig": good["sig"]})
    print(f"  篡改消息 → {r}  {'✓ 被拒' if not r.get('ok') else '✗ 竟通过'}")

    print("\n== 金丝雀跨部署复用 ==")
    canary_hash = "c0ffee00c0ffee01"
    nodes["node-a"].report_local(canary_hash, "canary")
    for _ in range(2):
        for n in nodes.values():
            n.gossip_once()
        time.sleep(0.2)
    st = nodes["node-c"].check_hash(canary_hash)
    print(f"  C 看到 A 的金丝雀记录: {st.status} (目击 {st.seen_count})  ✓" if st else "  ✗")

    for n in nodes.values():
        n.stop()
    print(f"\n{'='*50}\n{'联邦合并规则全部符合预期' if ok else '存在偏离, 检查规则实现'}\n{'='*50}")


if __name__ == "__main__":
    main()
