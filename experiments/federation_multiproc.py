"""
联邦真实多进程部署验证 — 三个独立蜜罐进程跨进程 gossip

每个节点 = 独立 OS 进程 (main.py --server) + 独立 sqlite + 独立联邦监听端口
流程:
  1. 生成三份 FEDERATION_CONFIG (三角互联, 信任圈共享密钥)
  2. 拉起三个蜜罐进程 (honeypot 19011-13, fed 19311-13)
  3. 向三个节点分别提交同一伪造 env 载荷 (真实走 /api/auth → intel 分级 → fed.report_local)
  4. 轮询各节点 fed_gossip 表, 等待多数投票收敛 (shared_forgery_confirmed)
  5. 附加: 每节点一个独立载荷 (应保持本地判定, 证明不误连)

用法: python experiments/federation_multiproc.py
"""

import base64
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HONEY_PORTS = (19011, 19012, 19013)
FED_PORTS = (19311, 19312, 19313)
NODE_IDS = ("node-a", "node-b", "node-c")


def build_configs(workdir):
    keys = {nid: os.urandom(32).hex() for nid in NODE_IDS}
    cfgs = {}
    for i, nid in enumerate(NODE_IDS):
        peers = {
            p: {"url": f"http://127.0.0.1:{FED_PORTS[j]}", "key": keys[p]}
            for j, p in enumerate(NODE_IDS) if p != nid
        }
        path = os.path.join(workdir, f"{nid}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"node_id": nid, "listen_port": FED_PORTS[i], "peers": peers,
                       "self_key": keys[nid],
                       "db": os.path.join(workdir, f"{nid}.sqlite")}, f)
        cfgs[nid] = path
    return cfgs


def submit_forged_env(port, payload_text, hostname="fed-test-host"):
    """真实 HTTP 提交伪造 env — 带齐爬级字段使 env 过校验流程 (校验→分级→联邦上报)"""
    env = base64.b64encode(payload_text.encode()).decode()
    query = (f"hostname={hostname}&user=pentester&os=linux&work_dir=/app&env={env}")
    url = f"http://127.0.0.1:{port}/api/auth?{query}"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(urllib.request.Request(url, headers={"X-Session-Id": "fed_deploy_test"}),
                         timeout=5) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        return {"error": str(e)}


def fed_state(db_path, env_hash):
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM fed_gossip WHERE env_hash=?",
                           (env_hash,)).fetchone()
        conn.close()
        if row:
            return {"grade": row["grade"], "seen": row["seen_count"],
                    "deps": json.loads(row["deployments"])}
    except Exception:
        pass
    return None


def main():
    workdir = tempfile.mkdtemp(prefix="fed_deploy_")
    cfgs = build_configs(workdir)
    print(f"[Deploy] 工作目录: {workdir}")
    print(f"[Deploy] 节点: honey=19011-13 fed=19311-13, gossip 间隔 1s (演示加速)")

    env = dict(os.environ)
    env["FEDERATION_GOSSIP_INTERVAL"] = "1"
    env["no_proxy"] = env["NO_PROXY"] = "127.0.0.1,localhost"
    env["HONEYPOT_WORLD_VERSION"] = "2"

    procs = []
    for i, nid in enumerate(NODE_IDS):
        p = subprocess.Popen(
            [sys.executable, "main.py", "--server", "--port", str(HONEY_PORTS[i])],
            env={**env, "FEDERATION_CONFIG": cfgs[nid],
                 "HONEYPOT_DB": os.path.join(workdir, f"{nid}-honeypot.sqlite")},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs.append(p)
    print("[Deploy] 三个蜜罐进程已拉起, 等待就绪...")
    time.sleep(4)

    try:
        forged_text = "this is a fabricated env payload from fed deploy"
        env_hash = __import__("core.intel", fromlist=["env_payload_hash"]).env_payload_hash(forged_text)

        print(f"\n[Attack] 同一伪造载荷提交到三个节点 (hash={env_hash})")
        for i, nid in enumerate(NODE_IDS):
            resp = submit_forged_env(HONEY_PORTS[i], forged_text)
            grade = (resp.get("data", {}) or {}).get("fabricated", "")
            print(f"  {nid}: 蜜罐本地响应 status={resp.get('status')} fabricated={grade}")

        # 每节点独立载荷 (应只在本节点出现) — 合法 KV 结构, 本地判 consistent
        unique_hashes = {}
        for i, nid in enumerate(NODE_IDS):
            txt = f"UNIQUE_NODE={nid}\nUNIQUE_SEQ={i}{i}{i}"
            unique_hashes[nid] = __import__("core.intel", fromlist=["env_payload_hash"]).env_payload_hash(txt)
            submit_forged_env(HONEY_PORTS[i], txt)

        print("\n[Converge] 等待跨进程 gossip 收敛 (最长 40s)...")
        deadline = time.time() + 40
        converged = False
        while time.time() < deadline:
            states = [fed_state(os.path.join(workdir, f"{nid}.sqlite"), env_hash)
                      for nid in NODE_IDS]
            if all(s and s["grade"] == "shared_forgery_confirmed" for s in states):
                converged = True
                break
            time.sleep(2)

        # 终态以轮询结束后的新鲜快照判定 (避免轮询窗口与打印之间的时序差)
        states = [fed_state(os.path.join(workdir, f"{nid}.sqlite"), env_hash)
                  for nid in NODE_IDS]
        converged = all(s and s["grade"] == "shared_forgery_confirmed" for s in states)

        print("\n[Result] 共享伪造载荷的联邦终态:")
        for nid, s in zip(NODE_IDS, states):
            if s:
                mark = "✓" if s["grade"] == "shared_forgery_confirmed" else "…"
                print(f"  {mark} {nid}: {s['grade']} (目击 {s['seen']} 部署: {s['deps']})")
            else:
                print(f"  ✗ {nid}: 无记录 (gossip 未到达)")

        print("\n[Result] 各节点独立载荷 (联邦可传播记录, 但不应被误判为共享伪造):")
        for nid, h in unique_hashes.items():
            others = [p for p in NODE_IDS if p != nid]
            leak = [fed_state(os.path.join(workdir, f"{p}.sqlite"), h) for p in others]
            convicted = any(s and s["grade"] == "shared_forgery_confirmed" for s in leak)
            print(f"  {'✗ 误判' if convicted else '✓ 正常'} {nid}: 他节点记录未被升格为伪造确认")

        print(f"\n{'='*56}\n{'多进程联邦收敛成功: 三节点共享伪造确认' if converged else '未收敛 — 检查 gossip 链'}\n{'='*56}")
        return 0 if converged else 1
    finally:
        for p in procs:
            p.terminate()
        time.sleep(1)


if __name__ == "__main__":
    sys.exit(main())
