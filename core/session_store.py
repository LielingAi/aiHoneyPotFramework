"""
会话持久化 — 内存态补洞

重启后会话/授权状态/世界全部丢失 (内存态)。本模块把会话元数据落 SQLite:
- world 不存储 (由 (sid, version) 确定性再派生), 只存 auth 状态与计数
- 写穿: 会话创建/每次请求/授权变更时同步 (WAL 模式, 蜜罐量级足够)
- 启动时加载: 重启后会话连续性保留 (授权级/爬梯进度不丢)

启用: HONEYPOT_SESSION_DB 环境变量指向 sqlite 路径 (runner/部署时设置)
"""

import json
import os
import sqlite3
import time

from core.fake_world import FakeWorld


class SessionStore:
    def __init__(self, path: str):
        self.path = path
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("""CREATE TABLE IF NOT EXISTS sessions(
            sid TEXT PRIMARY KEY, first_seen REAL, last_seen REAL,
            requests INTEGER, auth TEXT)""")
        self._conn.commit()

    def save(self, sid: str, session: dict):
        auth = session.get("auth", {})
        self._conn.execute(
            "INSERT OR REPLACE INTO sessions VALUES (?,?,?,?,?)",
            (sid, session.get("first_seen", time.time()),
             session.get("last_seen", time.time()),
             session.get("requests", 0), json.dumps(auth, ensure_ascii=False)))
        self._conn.commit()

    def touch(self, sid: str, last_seen: float, requests: int):
        self._conn.execute(
            "UPDATE sessions SET last_seen=?, requests=? WHERE sid=?",
            (last_seen, requests, sid))
        self._conn.commit()

    def save_auth(self, sid: str, auth: dict):
        self._conn.execute("UPDATE sessions SET auth=? WHERE sid=?",
                           (json.dumps(auth, ensure_ascii=False), sid))
        self._conn.commit()

    def load_all(self) -> dict:
        """恢复为 store['sessions'] 兼容结构 (world 按当前版本再派生)"""
        out = {}
        for sid, first, last, reqs, auth_json in self._conn.execute(
                "SELECT * FROM sessions"):
            try:
                auth = json.loads(auth_json) if auth_json else {"level": 0, "data": {}, "attempts": []}
            except Exception:
                auth = {"level": 0, "data": {}, "attempts": []}
            out[sid] = {
                "first_seen": first, "last_seen": last, "requests": reqs,
                "auth": auth,
                "world": FakeWorld(sid),
            }
        return out
