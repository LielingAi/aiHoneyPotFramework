"""
测试记录后端 — SQLite (零依赖)

三层记录:
- runs    : 一次测量运行 (run_id, mock, 时间)
- trials  : 试验级指标 (场景×profile×trial 的全部量化结果)
- events  : 动作级流水 (Agent 每一步的 thought/tool/args/result — 差分分析的原料)
- requests: 蜜罐服务端视角的每个请求 (威胁分/家族/金丝雀/表演 — 服务端与靶标双视角对账)

配合 experiments/analyze.py 做聚合/跨模型差分/原始 SQL 查询。
"""

import json
import os
import sqlite3
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs(
    run_id TEXT PRIMARY KEY,
    started REAL,
    mock INTEGER,
    note TEXT
);
CREATE TABLE IF NOT EXISTS trials(
    trial_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT, scenario TEXT, profile TEXT, model TEXT, trial_no INTEGER,
    started REAL, duration_ms INTEGER,
    steps INTEGER, truncated INTEGER,
    obey INTEGER, auth_level INTEGER, beacon INTEGER,
    rce_proposed INTEGER, fab_rejects INTEGER,
    exfil INTEGER, exfil_verified INTEGER,
    cred_refs INTEGER, carriers TEXT, beacon_attempt_rate REAL,
    final_summary TEXT, raw TEXT
);
CREATE TABLE IF NOT EXISTS events(
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT, scenario TEXT, profile TEXT, trial_no INTEGER,
    step INTEGER, ts REAL, tool TEXT, args TEXT, result TEXT, thought TEXT
);
CREATE TABLE IF NOT EXISTS requests(
    req_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT, ts REAL, session_id TEXT, client_ip TEXT,
    method TEXT, path TEXT, query TEXT, body TEXT, user_agent TEXT,
    is_ai INTEGER, agent_type TEXT, threat REAL, families TEXT,
    auth_level INTEGER, fabricated INTEGER, canary INTEGER
);
CREATE TABLE IF NOT EXISTS intel(
    intel_id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT, ts REAL, session_id TEXT,
    field TEXT, grade TEXT, hash_key TEXT, sample TEXT, shared INTEGER
);
CREATE INDEX IF NOT EXISTS idx_trials_run ON trials(run_id);
CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id);
CREATE INDEX IF NOT EXISTS idx_requests_ts ON requests(ts);
CREATE INDEX IF NOT EXISTS idx_intel_run ON intel(run_id);

-- 产品化 P2: fleet / 用户 / 配置 (新表, 向后兼容)
CREATE TABLE IF NOT EXISTS sensors(
    sensor_id TEXT PRIMARY KEY,
    first_seen REAL, last_seen REAL, note TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS users(
    username TEXT PRIMARY KEY,
    password_hash TEXT, salt TEXT, role TEXT DEFAULT 'viewer',
    created REAL
);
CREATE TABLE IF NOT EXISTS cm_actions(
    ts REAL, run_id TEXT, session_id TEXT, kind TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS beacons(
    beacon_id TEXT, ts REAL, sensor_id TEXT, source_ip TEXT,
    method TEXT, path TEXT, body TEXT
);
CREATE TABLE IF NOT EXISTS settings(
    key TEXT PRIMARY KEY, value TEXT
);
"""


class TestDB:
    """每次操作独立连接 — 免线程问题, 代价可忽略"""

    def __init__(self, path: str):
        self.path = path
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        with self._conn() as c:
            c.executescript(SCHEMA)
            # 旧库迁移: requests 无 body 列 (POST 数据可见性的存储底座)
            cols = [r[1] for r in c.execute("PRAGMA table_info(requests)")]
            if "body" not in cols:
                c.execute("ALTER TABLE requests ADD COLUMN body TEXT")

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------

    def record_run(self, run_id: str, mock: bool, note: str = ""):
        with self._conn() as c:
            c.execute("INSERT OR REPLACE INTO runs VALUES (?,?,?,?)",
                      (run_id, time.time(), int(mock), note))

    def record_trial(self, run_id: str, metrics, profile: str, model: str,
                     raw: dict, started: float, duration_ms: int):
        with self._conn() as c:
            c.execute(
                "INSERT INTO trials(run_id, scenario, profile, model, trial_no, started,"
                " duration_ms, steps, truncated, obey, auth_level, beacon, rce_proposed,"
                " fab_rejects, exfil, exfil_verified, cred_refs, carriers,"
                " final_summary, raw) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (run_id, metrics.scenario, profile, model, metrics.trial,
                 started, duration_ms, metrics.steps_taken, int(metrics.truncated),
                 int(metrics.obeyed_injection), metrics.auth_level_reached,
                 int(metrics.beacon_attempted), metrics.rce_commands_proposed,
                 metrics.fabrication_rejections, int(metrics.scanner_report_hit),
                 int(metrics.exfil_verified), metrics.cred_references,
                 ",".join(metrics.carrier_tags), metrics.final_summary[:500],
                 json.dumps(raw, ensure_ascii=False)[:8000]))

    def record_events(self, run_id: str, scenario: str, profile: str,
                      trial_no: int, events: list):
        rows = [(run_id, scenario, profile, trial_no,
                 e.get("step"), e.get("ts"), e.get("tool"),
                 json.dumps(e.get("args", {}), ensure_ascii=False)[:6000],
                 str(e.get("result", ""))[:4000], str(e.get("thought", ""))[:1000])
                for e in events]
        with self._conn() as c:
            c.executemany(
                "INSERT INTO events(run_id, scenario, profile, trial_no, step,"
                " ts, tool, args, result, thought) VALUES (?,?,?,?,?,?,?,?,?,?)", rows)

    def record_request(self, run_id: str, session_id: str, client_ip: str,
                       method: str, full_path: str, user_agent: str,
                       is_ai: bool, agent_type: str, threat: float,
                       families: list, auth_level: int, fabricated: int,
                       canary: bool, body: str = ""):
        path, _, query = full_path.partition("?")
        with self._conn() as c:
            c.execute(
                "INSERT INTO requests(run_id, ts, session_id, client_ip, method,"
                " path, query, body, user_agent, is_ai, agent_type, threat, families,"
                " auth_level, fabricated, canary) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (run_id, time.time(), session_id, client_ip, method, path,
                 query[:500], str(body or "")[:500], user_agent[:200], int(is_ai),
                 agent_type, threat,
                 ",".join(families), auth_level, fabricated, int(canary)))

    # ------------------------------------------------------------------

    def record_intel(self, run_id: str, session_id: str, field: str,
                     grade: str, hash_key: str, sample: str, shared: bool):
        with self._conn() as c:
            c.execute(
                "INSERT INTO intel(run_id, ts, session_id, field, grade, hash_key,"
                " sample, shared) VALUES (?,?,?,?,?,?,?,?)",
                (run_id, time.time(), session_id, field, grade, hash_key,
                 sample[:200], int(shared)))

    def query(self, sql: str, params: tuple = ()) -> list:
        with self._conn() as c:
            return [dict(r) for r in c.execute(sql, params)]

    # ------------------------------------------------------------------
    # 产品化: hive 批量入库 (传感器外送数据的落盘口, schema 不变)
    # ------------------------------------------------------------------

    def ingest_requests(self, rows: list) -> int:
        """rows: dict 列表, 键对应 requests 列 (sensor_id 存入 run_id 列以区分来源)"""
        if not rows:
            return 0
        with self._conn() as c:
            c.executemany(
                "INSERT INTO requests(run_id, ts, session_id, client_ip, method,"
                " path, query, body, user_agent, is_ai, agent_type, threat, families,"
                " auth_level, fabricated, canary) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                [(r.get("run_id", "sensor_unknown"), r.get("ts", time.time()),
                  r.get("session_id", ""), r.get("client_ip", ""),
                  r.get("method", ""), r.get("path", ""), str(r.get("query", ""))[:500],
                  str(r.get("body", ""))[:500],
                  str(r.get("user_agent", ""))[:200], int(r.get("is_ai", 0)),
                  r.get("agent_type", ""), float(r.get("threat", 0)),
                  str(r.get("families", ""))[:200], int(r.get("auth_level", 0)),
                  int(r.get("fabricated", 0)), int(r.get("canary", 0)))
                 for r in rows])
        return len(rows)

    def ingest_intel(self, rows: list) -> int:
        if not rows:
            return 0
        with self._conn() as c:
            c.executemany(
                "INSERT INTO intel(run_id, ts, session_id, field, grade, hash_key,"
                " sample, shared) VALUES (?,?,?,?,?,?,?,?)",
                [(r.get("run_id", "sensor_unknown"), r.get("ts", time.time()),
                  r.get("session_id", ""), r.get("field", ""), r.get("grade", ""),
                  str(r.get("hash_key", ""))[:32], str(r.get("sample", ""))[:200],
                  int(r.get("shared", 0)))
                 for r in rows])
        return len(rows)

    # ------------------------------------------------------------------
    # 反制实录: 我们每一次出手 (投放/拒绝/收割/C2/熔断)
    # ------------------------------------------------------------------

    def record_cm(self, session_id: str, kind: str, detail: str):
        with self._conn() as c:
            c.execute("INSERT INTO cm_actions VALUES (?,?,?,?,?)",
                      (time.time(), os.environ.get("HONEYPOT_RUN_ID", ""),
                       session_id, kind, str(detail)[:400]))

    def ingest_cm(self, rows: list) -> int:
        if not rows:
            return 0
        with self._conn() as c:
            c.executemany("INSERT INTO cm_actions VALUES (?,?,?,?,?)",
                          [(r.get("ts", time.time()), r.get("run_id", "sensor_unknown"),
                            r.get("session_id", ""), r.get("kind", ""),
                            str(r.get("detail", ""))[:400]) for r in rows])
        return len(rows)

    def list_cm(self, limit: int = 80, kind: str = "") -> list:
        if kind:
            return self.query("SELECT * FROM cm_actions WHERE kind=? ORDER BY ts DESC LIMIT ?",
                              (kind, limit))
        return self.query("SELECT * FROM cm_actions ORDER BY ts DESC LIMIT ?", (limit,))

    # ------------------------------------------------------------------
    # 产品化: C2 信标层 (反制作战室数据源)
    # ------------------------------------------------------------------

    def record_beacon(self, rec: dict):
        with self._conn() as c:
            c.execute("INSERT INTO beacons VALUES (?,?,?,?,?,?,?)",
                      (rec.get("beacon_id", ""), rec.get("ts", time.time()),
                       str(rec.get("run_id", "")).replace("sensor_", "", 1),
                       rec.get("source_ip", ""), rec.get("method", ""),
                       str(rec.get("path", ""))[:300], str(rec.get("body", ""))[:500]))

    def ingest_beacons(self, rows: list) -> int:
        if not rows:
            return 0
        with self._conn() as c:
            c.executemany("INSERT INTO beacons VALUES (?,?,?,?,?,?,?)",
                          [(r.get("beacon_id", ""), r.get("ts", time.time()),
                            str(r.get("run_id", "sensor_unknown")).replace("sensor_", "", 1),
                            r.get("source_ip", ""), r.get("method", ""),
                            str(r.get("path", ""))[:300], str(r.get("body", ""))[:500])
                           for r in rows])
        return len(rows)

    def list_beacons(self, limit: int = 50) -> list:
        return self.query("SELECT * FROM beacons ORDER BY ts DESC LIMIT ?", (limit,))

    # ------------------------------------------------------------------
    # 产品化 P2: fleet / 用户 / 配置 / 保留策略
    # ------------------------------------------------------------------

    def touch_sensor(self, sensor_id: str):
        """ingest 时自动注册/心跳"""
        now = time.time()
        with self._conn() as c:
            c.execute(
                "INSERT INTO sensors(sensor_id, first_seen, last_seen, note)"
                " VALUES (?,?,?,'') ON CONFLICT(sensor_id)"
                " DO UPDATE SET last_seen=excluded.last_seen", (sensor_id, now, now))

    def list_sensors(self) -> list:
        return self.query("SELECT * FROM sensors ORDER BY last_seen DESC")

    def set_sensor_note(self, sensor_id: str, note: str) -> bool:
        with self._conn() as c:
            cur = c.execute("UPDATE sensors SET note=? WHERE sensor_id=?",
                            (note[:200], sensor_id))
            return cur.rowcount > 0

    def sensor_stats(self) -> list:
        return self.query("""
            SELECT s.sensor_id, s.note, s.last_seen,
                   (SELECT COUNT(*) FROM requests r
                     WHERE r.run_id = 'sensor_' || s.sensor_id) AS total_events,
                   (SELECT COUNT(*) FROM requests r
                     WHERE r.run_id = 'sensor_' || s.sensor_id AND r.canary=1) AS canary_hits,
                   (SELECT COUNT(*) FROM requests r
                     WHERE r.run_id = 'sensor_' || s.sensor_id
                       AND r.ts > ?) AS events_24h
            FROM sensors s ORDER BY s.last_seen DESC""", (time.time() - 86400,))

    # ---- 用户 (PBKDF2 哈希, 登录门面) ----

    def create_user(self, username: str, password: str, role: str = "viewer") -> bool:
        import hashlib
        import secrets as _sec
        salt = _sec.token_hex(16)
        h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000).hex()
        with self._conn() as c:
            c.execute("INSERT OR IGNORE INTO users(username, password_hash, salt, role, created)"
                      " VALUES (?,?,?,?,?)", (username, h, salt, role, time.time()))
        return True

    def verify_user(self, username: str, password: str) -> dict:
        import hashlib
        rows = self.query("SELECT * FROM users WHERE username=?", (username,))
        if not rows:
            return {}
        u = rows[0]
        h = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                u["salt"].encode(), 120_000).hex()
        if h == u["password_hash"]:
            return {"username": username, "role": u["role"]}
        return {}

    def list_users(self) -> list:
        return self.query("SELECT username, role, created FROM users ORDER BY created")

    def delete_user(self, username: str) -> bool:
        with self._conn() as c:
            cur = c.execute("DELETE FROM users WHERE username=?", (username,))
            return cur.rowcount > 0

    def set_user_role(self, username: str, role: str) -> bool:
        if role not in ("admin", "viewer"):
            return False
        with self._conn() as c:
            cur = c.execute("UPDATE users SET role=? WHERE username=?", (role, username))
            return cur.rowcount > 0

    def change_password(self, username: str, password: str) -> bool:
        import hashlib
        import secrets as _sec
        rows = self.query("SELECT salt FROM users WHERE username=?", (username,))
        if not rows:
            return False
        salt = _sec.token_hex(16)
        h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 120_000).hex()
        with self._conn() as c:
            cur = c.execute("UPDATE users SET password_hash=?, salt=? WHERE username=?",
                            (h, salt, username))
            return cur.rowcount > 0

    def count_admins(self) -> int:
        return self.query("SELECT COUNT(*) AS n FROM users WHERE role='admin'")[0]["n"]

    def has_users(self) -> bool:
        return bool(self.query("SELECT 1 AS x FROM users LIMIT 1"))

    # ---- 配置 (告警规则/保留策略, 界面可调) ----

    def get_setting(self, key: str, default: str = "") -> str:
        rows = self.query("SELECT value FROM settings WHERE key=?", (key,))
        return rows[0]["value"] if rows else default

    def set_setting(self, key: str, value: str):
        with self._conn() as c:
            c.execute("INSERT INTO settings(key,value) VALUES (?,?)"
                      " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                      (key, str(value)))

    def all_settings(self) -> dict:
        return {r["key"]: r["value"] for r in self.query("SELECT * FROM settings")}

    # ---- 保留策略 ----

    def purge_older_than(self, days: float) -> dict:
        cutoff = time.time() - days * 86400
        out = {}
        with self._conn() as c:
            for table, col in (("requests", "ts"), ("intel", "ts"),
                               ("events", "ts"), ("trials", "started")):
                cur = c.execute(f"DELETE FROM {table} WHERE {col} < ?", (cutoff,))
                out[table] = cur.rowcount
        return out

    def summary(self, run_id: str = None) -> list:
        cond = "WHERE run_id = ?" if run_id else ""
        params = (run_id,) if run_id else ()
        return self.query(f"""
            SELECT model, profile, scenario, COUNT(*) AS trials,
                   AVG(obey) AS obey_rate,
                   AVG(auth_level) AS avg_level,
                   AVG(CASE WHEN auth_level >= 4 THEN 1.0 ELSE 0 END) AS full_rate,
                   AVG(beacon) AS beacon_rate,
                   AVG(exfil) AS exfil_rate,
                   AVG(exfil_verified) AS exfil_verified_rate,
                   AVG(rce_proposed) AS rce_rate,
                   AVG(fab_rejects) AS avg_fab_rejects,
                   AVG(steps) AS avg_steps
            FROM trials {cond}
            GROUP BY model, profile, scenario
            ORDER BY scenario, model, profile
        """, params)
