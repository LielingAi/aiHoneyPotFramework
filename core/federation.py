"""
蜜罐联邦信誉网 v1 — 跨部署伪造情报检测 (research/federation-spec.md 的实现)

组件:
- FedNode: 节点身份 (HMAC 对称密钥, ed25519 升级位) + gossip 收发 + 合并规则
- 消息: intel_report / forged_blacklist / beacon_correlation, TTL 限界 + 去重防环
- 持久化: sqlite fed_gossip 表 (哈希 → 部署集合 → 目击计数) + fed_meta (节点密钥)
- 合并规则 (spec §3):
    本地 consistent + ≥2 其他部署目击      → federated_disputed
    目击 ≥3 且本地 forged                   → shared_forgery_confirmed (全网黑名单)
    本地金丝雀值在他部署出现                 → cross_deployment_reuse
- 隐私: 只交换归一化载荷哈希与元数据, 永不交换原始 env (spec §6)

集成: 环境变量 FEDERATION_CONFIG 指向 JSON ({"node_id":..., "listen_port":...,
      "peers": {"peer-id": {"url":..., "key":...}}}) 时自动启用;
      intel.register_session 的共享伪造检测经 report_local 上报。

用法:
  演示:  python experiments/federation_demo.py
  测试:  pytest tests/ -k federation
"""

import hashlib
import hmac
import json
import os
import sqlite3
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional

GOSSIP_TTL = 3
GOSSIP_INTERVAL = float(os.environ.get("FEDERATION_GOSSIP_INTERVAL", "5"))


def _canon(obj: dict) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


@dataclass
class FedVerdict:
    status: str                     # federated_disputed / shared_forgery_confirmed / seen / new
    seen_count: int = 0
    deployments: List[str] = field(default_factory=list)


class FedNode:
    """单个蜜罐节点的联邦成员身份"""

    def __init__(self, node_id: str, peers: Dict[str, dict], db_path: str,
                 listen_host: str = "127.0.0.1", listen_port: int = 0,
                 autostart: bool = True, self_key: str = None):
        """
        Args:
            peers: {peer_id: {"url": "http://host:port", "key": "<hex>"}}
                   key = 该 peer 的签名密钥 (信任圈内共享, out-of-band bootstrap)
            self_key: 本节点签名密钥 (hex); None 时生成并持久化到 db
        """
        self.node_id = node_id
        self.peers = peers
        self.db_path = db_path
        self.self_key = self._load_or_create_key(self_key)
        self._seen_msgs = set()          # (origin, msg_id) 去重防环
        self._outbox: List[dict] = []
        self._lock = threading.Lock()
        self._server: Optional[ThreadingHTTPServer] = None
        self._gossip_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        if listen_port and autostart:
            self.start_server(listen_host, listen_port)

    # ------------------------------------------------------------------
    # 身份与签名 (v1 HMAC; ed25519 升级时替换 _sign/_verify 即可)
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("CREATE TABLE IF NOT EXISTS fed_meta(k TEXT PRIMARY KEY, v TEXT)")
        conn.execute("""CREATE TABLE IF NOT EXISTS fed_gossip(
            env_hash TEXT PRIMARY KEY, deployments TEXT, seen_count INT,
            grade TEXT, first_ts REAL, last_ts REAL)""")
        return conn

    def _load_or_create_key(self, preferred: str = None) -> bytes:
        if preferred:
            key = bytes.fromhex(preferred)
            with self._conn() as c:
                c.execute("INSERT OR REPLACE INTO fed_meta VALUES ('self_key', ?)", (key.hex(),))
            return key
        with self._conn() as c:
            row = c.execute("SELECT v FROM fed_meta WHERE k='self_key'").fetchone()
            if row:
                return bytes.fromhex(row["v"])
            key = os.urandom(32)
            c.execute("INSERT INTO fed_meta VALUES ('self_key', ?)", (key.hex(),))
            return key

    def _sign(self, msg: dict) -> str:
        return hmac.new(self.self_key, _canon(msg), hashlib.sha256).hexdigest()

    def _verify(self, origin: str, msg: dict, sig: str) -> bool:
        peer = self.peers.get(origin)
        if not peer:
            return False
        key = peer["key"]
        key_bytes = bytes.fromhex(key) if isinstance(key, str) and len(key) == 64 else str(key).encode()
        expected = hmac.new(key_bytes, _canon(msg), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig or "")

    # ------------------------------------------------------------------
    # 消息
    # ------------------------------------------------------------------

    def make_message(self, msg_type: str, payload: dict, ttl: int = GOSSIP_TTL) -> dict:
        msg = {"type": msg_type, "origin": self.node_id, "ts": time.time(),
               "ttl": ttl, "msg_id": hashlib.sha256(os.urandom(16)).hexdigest()[:16],
               "payload": payload}
        msg["sig"] = self._sign(msg)
        return msg

    # ------------------------------------------------------------------
    # 核心: 本地上报 / 接收合并 / 查询
    # ------------------------------------------------------------------

    def report_local(self, env_hash: str, grade: str, evidence_classes: List[str] = None):
        """本地情报事件 → 合并 + 入队 gossip (本地判定优先, 联邦可升级但先采信自己)"""
        verdict = self._merge(env_hash, self.node_id, grade, is_local=True)
        msg = self.make_message("intel_report", {
            "env_hash": env_hash, "grade": grade,
            "evidence_classes": evidence_classes or [], "first_seen": time.time(),
        })
        with self._lock:
            self._outbox.append(msg)
        return verdict

    def _merge(self, env_hash: str, origin: str, grade: str,
               is_local: bool = False) -> FedVerdict:
        with self._conn() as c:
            row = c.execute("SELECT * FROM fed_gossip WHERE env_hash=?",
                            (env_hash,)).fetchone()
            now = time.time()
            if row:
                deps = set(json.loads(row["deployments"])) | {origin}
                count = len(deps)
                # 本地判定优先 (self 是最了解自己的节点); gossip 仅在其缺席时建立初值
                local_grade = grade if is_local else row["grade"]
                new_grade = local_grade
                # spec §3 合并规则
                if local_grade == "consistent" and count >= 3:
                    new_grade = "federated_disputed"
                if local_grade in ("forged", "federated_disputed") and count >= 3:
                    new_grade = "shared_forgery_confirmed"
                c.execute("UPDATE fed_gossip SET deployments=?, seen_count=?, grade=?,"
                          " last_ts=? WHERE env_hash=?",
                          (json.dumps(sorted(deps)), count, new_grade, now, env_hash))
            else:
                deps = {origin}
                count = 1
                new_grade = grade
                c.execute("INSERT INTO fed_gossip VALUES (?,?,?,?,?,?)",
                          (env_hash, json.dumps(sorted(deps)), count, grade, now, now))
        return FedVerdict(status=new_grade, seen_count=count, deployments=sorted(deps))

    def receive(self, body: dict) -> dict:
        """HTTP handler 入口: 验签 → 去重 → 合并 → 转 gossip"""
        msg = dict(body.get("msg", {}))
        # 验签对象必须不含 sig 字段本身 (签名时它尚不存在)
        sig = body.get("sig") or msg.pop("sig", "")
        msg.pop("sig", None)
        origin = msg.get("origin", "")
        if not self._verify(origin, msg, sig):
            return {"ok": False, "error": "bad_signature"}
        msg_id = msg.get("msg_id", "")
        with self._lock:
            if (origin, msg_id) in self._seen_msgs:
                return {"ok": True, "dedup": True}
            self._seen_msgs.add((origin, msg_id))
        p = msg.get("payload", {})
        verdict = self._merge(p.get("env_hash", ""), origin, p.get("grade", "unknown"))
        # TTL 转 gossip (除来源外全量转发, seen_msgs 防环)
        if msg.get("ttl", 0) > 0:
            fwd = dict(msg)
            fwd["ttl"] = msg["ttl"] - 1
            with self._lock:
                self._outbox.append(fwd)
        return {"ok": True, "verdict": verdict.status, "seen_count": verdict.seen_count}

    def check_hash(self, env_hash: str) -> Optional[FedVerdict]:
        """提交时查询: 该载荷的联邦判定 (蜜罐侧 grade 之前调用)"""
        with self._conn() as c:
            row = c.execute("SELECT * FROM fed_gossip WHERE env_hash=?",
                            (env_hash,)).fetchone()
        if not row:
            return None
        return FedVerdict(status=row["grade"], seen_count=row["seen_count"],
                          deployments=json.loads(row["deployments"]))

    # ------------------------------------------------------------------
    # 传输
    # ------------------------------------------------------------------

    def start_server(self, host: str, port: int):
        node = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                try:
                    length = int(self.headers.get("Content-Length", 0))
                    body = json.loads(self.rfile.read(length).decode())
                    result = node.receive(body)
                except Exception as e:
                    result = {"ok": False, "error": str(e)}
                data = json.dumps(result).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        self._server = ThreadingHTTPServer((host, port), Handler)
        self.listen_port = self._server.server_address[1]
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        self._gossip_thread = threading.Thread(target=self._gossip_loop, daemon=True)
        self._gossip_thread.start()

    def _gossip_loop(self):
        while not self._stop.is_set():
            self.gossip_once()
            self._stop.wait(GOSSIP_INTERVAL)

    def gossip_once(self):
        with self._lock:
            batch, self._outbox = self._outbox, []
        if not batch:
            return
        # 节点间 gossip 走私网, 必须绕过系统代理 (代理会使成员间消息丢失)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        for peer_id, peer in self.peers.items():
            for msg in batch:
                if msg.get("origin") == peer_id and msg.get("ttl", 0) < GOSSIP_TTL:
                    continue   # 不立刻回环给来源
                try:
                    req = urllib.request.Request(
                        peer["url"].rstrip("/") + "/",
                        data=json.dumps({"msg": msg, "sig": msg.get("sig", "")}).encode(),
                        headers={"Content-Type": "application/json"}, method="POST")
                    opener.open(req, timeout=3)
                except Exception:
                    pass

    def stop(self):
        self._stop.set()
        if self._server:
            self._server.shutdown()

    def stats(self) -> dict:
        with self._conn() as c:
            rows = c.execute("SELECT grade, COUNT(*) n FROM fed_gossip GROUP BY grade").fetchall()
        return {"node": self.node_id, "entries": {r["grade"]: r["n"] for r in rows},
                "peers": list(self.peers)}


# ----------------------------------------------------------------------
# 全局单例 (蜜罐进程内启用: FEDERATION_CONFIG 环境变量指向 JSON)
# ----------------------------------------------------------------------

_NODE: Optional[FedNode] = None


def init_from_env() -> Optional[FedNode]:
    global _NODE
    if _NODE is not None:
        return _NODE
    cfg_path = os.environ.get("FEDERATION_CONFIG")
    if not cfg_path or not os.path.exists(cfg_path):
        return None
    with open(cfg_path, encoding="utf-8") as f:
        cfg = json.load(f)
    db = cfg.get("db", "experiments/results/federation.sqlite")
    _NODE = FedNode(cfg["node_id"], cfg.get("peers", {}), db,
                    listen_port=cfg.get("listen_port", 0),
                    self_key=cfg.get("self_key"))
    return _NODE


def report_local(env_hash: str, grade: str, evidence_classes: List[str] = None):
    """intel.py 挂钩: 共享伪造/分级结果上报联邦 (未启用时 no-op)"""
    node = init_from_env()
    if node:
        try:
            return node.report_local(env_hash, grade, evidence_classes)
        except Exception:
            return None
    return None


def federation_check(env_hash: str) -> Optional[FedVerdict]:
    """main.py 挂钩: 提交前查联邦判定 (覆盖本地 grade)"""
    node = init_from_env()
    if node:
        try:
            return node.check_hash(env_hash)
        except Exception:
            return None
    return None
