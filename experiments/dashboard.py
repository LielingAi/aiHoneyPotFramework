"""
蜜罐研究数据面板 — 零依赖本地 Web 后台 (stdlib http.server)

用法:
  python experiments/dashboard.py --db experiments/results/testdb.sqlite --port 8899
  浏览器打开 http://127.0.0.1:8899

页面 (全部中文界面):
- 指标总览: KPI 卡片 (发现攻击耗时/真外泄率/注入服从率/预算放大/误报率/情报产出)
- 演化实验: --optimize 自动 A/B 各组合臂的进展
- 操作者归因: 跨会话聚类出的攻击操作者及其共同指纹
- 汇总指标 / 模型差分: 聚合与 回连/攻击命令/授权级别 三指标差分
- 试验明细: run/场景/人设三维筛选 + 全文搜索
- 动作流水 / 情报分级 / 请求日志 / 运行记录
- 导出情报按钮: 当前运行 → STIX bundle 下载
数据每 8 秒自动刷新, 搜索与筛选状态在刷新间保留。
"""

import argparse
import json
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.testdb import TestDB

DB: TestDB = None
STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")
BANDIT_STATE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "experiments", "results", "bandit_state.json")

# ---- 产品化 P2: 会话 (内存, 12h 滑动过期) ----
import secrets as _secrets
SESSIONS: dict = {}          # token -> {"user":.., "role":.., "exp":..}
SESSION_TTL = 12 * 3600
COOKIE = "hp_sid"


def _session_user(headers) -> dict:
    cookie = headers.get("Cookie", "")
    for part in cookie.split(";"):
        k, _, v = part.strip().partition("=")
        if k == COOKIE and v in SESSIONS:
            s = SESSIONS[v]
            if time.time() < s["exp"]:
                s["exp"] = time.time() + SESSION_TTL
                return s
            SESSIONS.pop(v, None)
    return {}


def _login(username: str, password: str) -> dict:
    u = DB.verify_user(username, password)
    if not u:
        return {}
    token = _secrets.token_hex(24)
    SESSIONS[token] = {"user": u["username"], "role": u["role"],
                       "exp": time.time() + SESSION_TTL}
    return {"token": token, **u}


def q(sql: str, params: tuple = ()) -> list:
    try:
        return DB.query(sql, params)
    except Exception as e:
        return [{"error": str(e)}]


def _masked_cfg() -> dict:
    cfg = DB.all_settings() if DB else {}
    wh = cfg.get("alert_webhook", "")
    if wh and len(wh) > 8:
        cfg["alert_webhook"] = wh[:4] + "…" + wh[-4:]
    cfg.setdefault("alert_fmt", "generic")
    cfg.setdefault("alert_threshold", "8")
    cfg.setdefault("retention_days", "30")
    return cfg


def reltime_js(ts) -> str:
    if not ts:
        return "-"
    s = max(0, time.time() - ts)
    if s < 90:
        return f"{s:.0f}秒前"
    if s < 3600:
        return f"{s/60:.0f}分钟前"
    if s < 86400:
        return f"{s/3600:.1f}小时前"
    return f"{s/86400:.1f}天前"


def _situation() -> dict:
    now = time.time()
    rows = DB.query("SELECT ts FROM requests WHERE ts > ?", (now - 86400,))
    hist = [0] * 24
    for r in rows:
        age_h = int((now - r["ts"]) // 3600)
        if 0 <= age_h < 24:
            hist[23 - age_h] += 1
    top_ips = DB.query("""
        SELECT client_ip, COUNT(*) AS n, SUM(canary) AS canary
        FROM requests WHERE ts > ? GROUP BY client_ip ORDER BY n DESC LIMIT 5""",
        (now - 7 * 86400,))
    fam = {}
    for r in DB.query("SELECT families FROM requests WHERE ts > ? AND families != ''",
                      (now - 7 * 86400,)):
        for f in str(r["families"]).split(","):
            if f.strip():
                fam[f.strip()] = fam.get(f.strip(), 0) + 1
    online = now - 90
    sensors = DB.sensor_stats()
    return {
        "hist24": hist,
        "total_24h": len(rows),
        "canary_24h": DB.query("SELECT COUNT(*) AS n FROM requests"
                               " WHERE ts > ? AND canary=1", (now - 86400,))[0]["n"],
        "top_ips": top_ips,
        "families": sorted(fam.items(), key=lambda kv: -kv[1])[:8],
        "sensors_online": sum(1 for s in sensors if s["last_seen"] and s["last_seen"] > online),
        "sensors_total": len(sensors),
    }



# SPA 深链接路由 (前端负责渲染; 服务端只回 index.html)
_SPA_ROUTES = {"situation", "live", "fleet", "config", "metrics", "bandit",
               "attribution", "summary", "compare", "trials", "events",
               "intel", "requests", "runs"}


def _static_type(path: str) -> str:
    if path.endswith(".css"):
        return "text/css; charset=utf-8"
    if path.endswith(".js"):
        return "text/javascript; charset=utf-8"
    if path.endswith(".html"):
        return "text/html; charset=utf-8"
    if path.endswith(".svg"):
        return "image/svg+xml"
    return "application/octet-stream"


class Handler(BaseHTTPRequestHandler):
    def _session(self) -> dict:
        return _session_user(self.headers)

    def _authorized(self, qs: dict) -> bool:
        """鉴权: 会话 cookie (人机登录) 或 ?token/Bearer (机器+书签)。
        HONEYPOT_CONSOLE_TOKEN 未设且无用户体系 = 开放 (实验态兼容)"""
        if self._session():
            return True
        token = os.environ.get("HONEYPOT_CONSOLE_TOKEN", "")
        if not token and DB and DB.has_users():
            return False          # 已建用户则必须登录
        if not token:
            return True
        auth = self.headers.get("Authorization", "")
        if auth == f"Bearer {token}":
            return True
        return qs.get("token", [""])[0] == token

    def _role(self, qs: dict) -> str:
        s = self._session()
        if s:
            return s["role"]
        token = os.environ.get("HONEYPOT_CONSOLE_TOKEN", "")
        if token and (self.headers.get("Authorization") == f"Bearer {token}"
                      or qs.get("token", [""])[0] == token):
            return "admin"        # 持机器 token = 全权 (compose 场景无登录页)
        return "viewer"

    def _serve_static(self, path: str):
        rel = path.lstrip("/")
        if rel.startswith("static/"):
            rel = rel[len("static/"):]
        full = os.path.normpath(os.path.join(STATIC_DIR, rel))
        if not full.startswith(STATIC_DIR) or not os.path.isfile(full):
            self._send(404, b"not found", "text/plain")
            return
        try:
            with open(full, "rb") as f:
                body = f.read()
        except OSError:
            self._send(404, b"not found", "text/plain")
            return
        self._send(200, body, _static_type(full))

    def _send(self, code: int, body: bytes, ctype: str, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):       # 安静访问日志
        pass

    def do_POST(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        # ---- 登录门面 (开放端点) ----
        if parsed.path == "/api/login":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                cred = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, json.JSONDecodeError):
                cred = {}
            u = _login(cred.get("username", ""), cred.get("password", ""))
            if not u:
                self._send(401, b'{"error":"bad credentials"}', "application/json")
                return
            body = json.dumps({"ok": True, "user": u["username"],
                               "role": u["role"]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Set-Cookie",
                             f"{COOKIE}={u['token']}; HttpOnly; Path=/; SameSite=Lax;"
                             f" Max-Age={SESSION_TTL}")
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/api/logout":
            s = self._session()
            for tok, v in list(SESSIONS.items()):
                if v is s:
                    SESSIONS.pop(tok, None)
            self._send(200, b'{"ok":true}', "application/json",
                       {"Set-Cookie": f"{COOKIE}=; HttpOnly; Path=/; Max-Age=0"})
            return
        # ---- 以下需鉴权 ----
        if not self._authorized(qs):
            self._send(401, b'{"error":"unauthorized"}', "application/json")
            return
        # CSRF: cookie 鉴权的写操作必须带自定义头 (跨站表单发不出)
        if not self.headers.get("X-Requested-With") and self._session():
            self._send(403, b'{"error":"missing csrf header"}', "application/json")
            return
        if parsed.path == "/ingest":
            try:
                length = int(self.headers.get("Content-Length", "0"))
                payload = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, json.JSONDecodeError):
                self._send(400, b'{"error":"bad json"}', "application/json")
                return
            n_req = DB.ingest_requests(payload.get("requests", []))
            n_int = DB.ingest_intel(payload.get("intel", []))
            for sid in {r.get("run_id", "").replace("sensor_", "", 1)
                        for r in payload.get("requests", [])
                        + payload.get("intel", [])
                        if str(r.get("run_id", "")).startswith("sensor_")}:
                DB.touch_sensor(sid)
            try:
                from services import alerter
                for r in payload.get("requests", []):
                    alerter.check_request(r)
                for r in payload.get("intel", []):
                    alerter.check_intel(r)
            except Exception:
                pass
            self._send(200, json.dumps({"ingested": n_req + n_int,
                                        "requests": n_req, "intel": n_int}
                                       ).encode(), "application/json")
            return
        if parsed.path == "/api/config":
            if self._role(qs) != "admin":
                self._send(403, b'{"error":"admin only"}', "application/json")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                cfg = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, json.JSONDecodeError):
                self._send(400, b'{"error":"bad json"}', "application/json")
                return
            PRESETS = {
                "conservative": {"visibility": "implicit", "framing": "compliance",
                                 "ladder_enabled": "false"},
                "standard": {"visibility": "full", "framing": "compliance",
                             "ladder_enabled": "true"},
                "aggressive": {"visibility": "full", "framing": "runner",
                               "ladder_enabled": "true"},
            }
            preset = cfg.get("policy_preset", "")
            if preset in PRESETS:
                DB.set_setting("policy_preset", preset)
                for k, v in PRESETS[preset].items():
                    DB.set_setting(k, v)
            for key in ("alert_webhook", "alert_webhooks", "alert_fmt",
                        "alert_threshold", "retention_days",
                        "visibility", "framing", "ladder_enabled", "world_version"):
                if key in cfg:
                    DB.set_setting(key, str(cfg[key]))
            from services import alerter
            alerter.CONFIG.update(DB.all_settings())
            self._send(200, json.dumps({"saved": True, "config": _masked_cfg()}
                                       ).encode(), "application/json")
            return
        if parsed.path == "/api/config/test_alert":
            if self._role(qs) != "admin":
                self._send(403, b'{"error":"admin only"}', "application/json")
                return
            from services import alerter
            ok = alerter.maybe_alert(
                "intel", {"grade": "consistent", "field": "test",
                          "sample": "手动测试告警 (来自配置页)", "session_id": "config-test"})
            self._send(200, json.dumps({"sent": bool(ok)}).encode(),
                       "application/json")
            return
        if parsed.path == "/api/users":
            if self._role(qs) != "admin":
                self._send(403, b'{"error":"admin only"}', "application/json")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, json.JSONDecodeError):
                self._send(400, b'{"error":"bad json"}', "application/json")
                return
            act = body.get("action", "")
            if act == "create":
                uname, pw = body.get("username", "").strip(), body.get("password", "")
                role = body.get("role", "viewer")
                if not uname or len(pw) < 6 or role not in ("admin", "viewer"):
                    self._send(400, '{\"error\":\"用户名必填, 密码≥6位\"}'.encode(), "application/json")
                    return
                before = DB.has_users()
                DB.create_user(uname, pw, role)
                ok = DB.has_users() and (before or True)
                self._send(200, json.dumps({"ok": ok}).encode(), "application/json")
                return
            if act == "delete":
                uname = body.get("username", "")
                sess = self._session()
                if sess and sess.get("user") == uname:
                    self._send(400, '{\"error\":\"不能删除当前登录账号\"}'.encode(), "application/json")
                    return
                if DB.count_admins() <= 1:
                    target = DB.query("SELECT role FROM users WHERE username=?", (uname,))
                    if target and target[0]["role"] == "admin":
                        self._send(400, '{\"error\":\"至少保留一名管理员\"}'.encode(), "application/json")
                        return
                self._send(200, json.dumps({"ok": DB.delete_user(uname)}).encode(),
                           "application/json")
                return
            if act == "role":
                uname, role = body.get("username", ""), body.get("role", "")
                if role == "admin" or DB.count_admins() > 1:
                    ok = DB.set_user_role(uname, role)
                else:
                    ok = False      # 唯一管理员不能降级
                self._send(200, json.dumps({"ok": ok}).encode(), "application/json")
                return
            if act == "password":
                uname, pw = body.get("username", ""), body.get("password", "")
                sess = self._session()
                if sess and sess.get("user") != uname and sess.get("role") != "admin":
                    self._send(403, b'{"error":"admin only"}', "application/json")
                    return
                if len(pw) < 6:
                    self._send(400, '{\"error\":\"密码至少 6 位\"}'.encode(), "application/json")
                    return
                self._send(200, json.dumps({"ok": DB.change_password(uname, pw)}).encode(),
                           "application/json")
                return
            self._send(400, b'{"error":"unknown action"}', "application/json")
            return
        if parsed.path == "/api/sensors/note":
            if self._role(qs) != "admin":
                self._send(403, b'{"error":"admin only"}', "application/json")
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length) or b"{}")
            except (ValueError, json.JSONDecodeError):
                self._send(400, b'{"error":"bad json"}', "application/json")
                return
            ok = DB.set_sensor_note(body.get("sensor_id", ""), body.get("note", ""))
            self._send(200, json.dumps({"ok": bool(ok)}).encode(), "application/json")
            return
        self._send(404, b"not found", "text/plain")

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        # 前后端分离: 前端为独立静态层 (SPA), 服务端只出静态文件 + /api/*
        if parsed.path == "/" or parsed.path.startswith("/static/")                 or parsed.path.lstrip("/") in _SPA_ROUTES:
            path = parsed.path if parsed.path != "/" else "/index.html"
            if not path.startswith("/static/"):
                path = "/index.html"          # 深链接 (SPA 路由) 一律回 index
            self._serve_static(path)
            return
        if parsed.path.startswith("/api/") and not self._authorized(qs):
            self._send(401, b'{"error":"unauthorized"}', "application/json")
            return
        elif parsed.path == "/api/me":
            s = self._session()
            self._send(200, json.dumps(
                {"user": s.get("user"), "role": self._role(qs),
                 "auth": "session" if s else "token"}).encode(), "application/json")
        elif parsed.path == "/api/config":
            opt_raw = DB.get_setting("optimize_active", "")
            opt = {"active": False, "run_id": ""}
            if opt_raw and ":" in opt_raw:
                rid, ts = opt_raw.rsplit(":", 1)
                try:
                    if time.time() - float(ts) < 1800:
                        opt = {"active": True, "run_id": rid}
                except ValueError:
                    pass
            self._send(200, json.dumps(
                {**_masked_cfg(), "role": self._role(qs),
                 "optimize": opt, "policy_preset": DB.get_setting("policy_preset", "")},
                ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/sensor_config":
            # 配置下发: 传感器轮询此端点拉取策略 (机器 token)
            cfg = {k: DB.get_setting(k) for k in
                   ("visibility", "framing", "ladder_enabled", "world_version",
                    "alert_webhook", "alert_webhooks", "alert_fmt", "alert_threshold")}
            cfg = {k: v for k, v in cfg.items() if v != ""}
            opt_raw = DB.get_setting("optimize_active", "")
            active, run_id = False, ""
            if opt_raw and ":" in opt_raw:
                rid, ts = opt_raw.rsplit(":", 1)
                try:
                    active = time.time() - float(ts) < 1800   # 30min 心跳过期
                    run_id = rid if active else ""
                except ValueError:
                    pass
            sid = os.environ.get("HIVE_SENSOR_ID", "")
            hdr_sid = self.headers.get("X-Sensor-Id", "")
            if hdr_sid:
                DB.touch_sensor(hdr_sid)
            self._send(200, json.dumps(
                {"config": cfg, "optimize": {"active": active, "run_id": run_id},
                 "ts": time.time()}, ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/users":
            if self._role(qs) != "admin":
                self._send(403, b'{"error":"admin only"}', "application/json")
                return
            rows = DB.list_users()
            sess = self._session()
            for r in rows:
                r["self"] = bool(sess) and sess.get("user") == r["username"]
            self._send(200, json.dumps(rows, ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/sensors":
            online = time.time() - 90
            rows = []
            for r in DB.sensor_stats():
                r["online"] = r["last_seen"] and r["last_seen"] > online
                r["last_seen_s"] = reltime_js(r["last_seen"])
                rows.append(r)
            self._send(200, json.dumps(rows, ensure_ascii=False).encode(),
                       "application/json")
        elif parsed.path == "/api/situation":
            self._send(200, json.dumps(_situation(), ensure_ascii=False).encode(),
                       "application/json")
        run = qs.get("run", [None])[0]
        run_cond, params = ("WHERE run_id = ?", (run,)) if run else ("", ())
        if parsed.path == "/__never__":
            pass
        elif parsed.path == "/api/events/stream":
            # P1 实时推送: SSE — 新请求事件流 (传感器汇聚后 1s 内达面板)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.end_headers()
            last = 0
            try:
                while True:
                    # 实时流语义: 无 Last-Event-ID 的首连从当前最新开始 (不回放历史);
                    # 断线重连带 Last-Event-ID 则从该 id 续传
                    hdr_last = self.headers.get("Last-Event-ID", "")
                    if hdr_last:
                        last = int(hdr_last)
                    elif last == 0 and not getattr(self, "_started", False):
                        # 首连回放最近 10 条: 实时页有历史体感, 之后纯增量
                        row = q("SELECT COALESCE(MAX(req_id),0) AS m FROM requests")
                        last = max(0, (row[0]["m"] if row else 0) - 10)
                        self._started = True
                    rows = q("SELECT req_id, ts, client_ip, method, path, threat,"
                             " canary, agent_type, run_id FROM requests"
                             " WHERE req_id > ? ORDER BY req_id LIMIT 50", (last,))
                    for r in rows:
                        last = max(last, r["req_id"])
                        self.wfile.write(
                            f"id: {r['req_id']}\ndata: {json.dumps(r, ensure_ascii=False)}\n\n"
                            .encode("utf-8"))
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
                    time.sleep(1)
            except (OSError, ConnectionResetError):
                return
        elif parsed.path == "/api/runs":
            rows = q("""SELECT r.*, (SELECT COUNT(*) FROM trials t WHERE t.run_id=r.run_id) AS n
                        FROM runs r ORDER BY started DESC""")
            self._send(200, json.dumps(rows, ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/summary":
            self._send(200, json.dumps(DB.summary(run), ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/trials":
            cond, p = run_cond, list(params)
            sce = qs.get("scenario", [None])[0]
            prof = qs.get("profile", [None])[0]
            if sce:
                cond += (" AND " if cond else "WHERE ") + "scenario = ?"
                p.append(sce)
            if prof:
                cond += (" AND " if cond else "WHERE ") + "profile = ?"
                p.append(prof)
            rows = q(f"SELECT * FROM trials {cond} ORDER BY trial_id DESC LIMIT 500", tuple(p))
            self._send(200, json.dumps(rows, ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/compare":
            rows = q(f"""SELECT scenario, model, profile,
                            AVG(beacon) AS beacon, AVG(rce_proposed) AS rce,
                            AVG(auth_level) AS lvl, COUNT(*) AS n
                         FROM trials {run_cond}
                         GROUP BY scenario, model, profile
                         ORDER BY scenario, beacon DESC""", params)
            self._send(200, json.dumps(rows, ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/bandit":
            if os.path.exists(BANDIT_STATE):
                try:
                    st = json.load(open(BANDIT_STATE, encoding="utf-8"))
                    arms = [{"name": k, "n": v["n"], "mean": v["reward"] / v["n"] if v["n"] else 0}
                            for k, v in st.get("arms", {}).items()]
                    arms.sort(key=lambda a: -a["mean"])
                    payload = {"total": st.get("total", 0), "arms": arms}
                except (json.JSONDecodeError, OSError) as e:
                    payload = {"error": str(e)}
            else:
                payload = {}
            self._send(200, json.dumps(payload, ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/attribution":
            from core import attribution as attr
            try:
                payload = attr.cluster(attr.collect_subjects(DB, run))
            except Exception as e:
                payload = [{"cluster_id": "error", "size": 0,
                            "subjects": [], "shared": {"error": [str(e)]}}]
            self._send(200, json.dumps(payload, ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/export-stix":
            from core.stix_export import build_bundle
            cond2, p2 = ("WHERE run_id = ?", (run,)) if run else ("", ())
            rows = q(f"SELECT * FROM intel {cond2} ORDER BY intel_id", p2)
            bundle = build_bundle(rows)
            body = json.dumps(bundle, ensure_ascii=False, indent=1).encode("utf-8")
            fname = f"stix_bundle_{run or 'all'}.json"
            self._send(200, body, "application/json; charset=utf-8",
                       {"Content-Disposition": f'attachment; filename="{fname}"'})
        elif parsed.path == "/api/events":
            lim = int(qs.get("limit", ["100"])[0])
            rows = q(f"SELECT * FROM events {run_cond} ORDER BY event_id DESC LIMIT ?", (*params, lim))
            self._send(200, json.dumps(rows, ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/intel":
            lim = int(qs.get("limit", ["60"])[0])
            rows = q(f"SELECT * FROM intel {run_cond} ORDER BY intel_id DESC LIMIT ?", (*params, lim))
            self._send(200, json.dumps(rows, ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/requests":
            lim = int(qs.get("limit", ["100"])[0])
            rows = q(f"SELECT * FROM requests {run_cond} ORDER BY req_id DESC LIMIT ?", (*params, lim))
            self._send(200, json.dumps(rows, ensure_ascii=False).encode(), "application/json")
        elif parsed.path == "/api/alerts":
            from services import alerter
            self._send(200, json.dumps(alerter.status(), ensure_ascii=False).encode(),
                       "application/json")
        elif parsed.path == "/api/kpi":
            from core.kpi import compute
            try:
                payload = compute(DB, run)
            except Exception as e:
                payload = {"error": str(e)}
            self._send(200, json.dumps(payload, ensure_ascii=False).encode(), "application/json")
        else:
            self._send(404, b"not found", "text/plain")


def main():
    global DB, BANDIT_STATE
    parser = argparse.ArgumentParser(description="蜜罐研究数据面板")
    parser.add_argument("--db", default="experiments/results/testdb.sqlite")
    parser.add_argument("--port", type=int, default=8899)
    parser.add_argument("--host", default="127.0.0.1", help="产品化暴露用 0.0.0.0")
    parser.add_argument("--bandit-state", default=None, help="UCB1 状态文件路径")
    args = parser.parse_args()
    DB = TestDB(args.db)
    if args.bandit_state:
        BANDIT_STATE = args.bandit_state
    # P2 门面: 首次启动建 admin (密码取 ADMIN_PASSWORD, 默认 admin123 并告警)
    if not DB.has_users():
        pw = os.environ.get("ADMIN_PASSWORD", "admin123")
        DB.create_user("admin", pw, role="admin")
        print(f"[AUTH] 已创建初始管理员 admin / {pw}"
              + (" (来自 ADMIN_PASSWORD)" if os.environ.get("ADMIN_PASSWORD")
                 else " — 生产部署请立即改密或设 ADMIN_PASSWORD"))
    from services import alerter
    alerter.CONFIG.update(DB.all_settings())
    # 保留策略: 启动即清 + 每小时清理
    def _retention_loop():
        while True:
            try:
                days = float(DB.get_setting("retention_days", "30"))
                purged = DB.purge_older_than(days)
                if any(purged.values()):
                    print(f"[RETENTION] 清理 >{days}d: {purged}")
            except Exception:
                pass
            time.sleep(3600)
    threading.Thread(target=_retention_loop, daemon=True).start()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"[Dashboard] http://{args.host}:{args.port}  (db: {args.db})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
