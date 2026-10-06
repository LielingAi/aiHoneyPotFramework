# -*- coding: utf-8 -*-
"""前端冒烟测试 — 每个路由必须渲染且无'加载失败' (pytest 门禁)

存在意义: 此前前端改动只靠开发者的 Playwright 抽查, 覆盖率约 60%,
UI 断点全部由 WREN 人肉发现。此测试把全路由扫描固化为门禁。
"""
import json
import threading
import urllib.request

import pytest

pytest.importorskip("playwright.sync_api", reason="playwright 未安装")
from playwright.sync_api import sync_playwright  # noqa: E402

from core.testdb import TestDB  # noqa: E402


@pytest.fixture()
def hive(tmp_path):
    import experiments.dashboard as d
    from http.server import ThreadingHTTPServer
    d.DB = TestDB(str(tmp_path / "ui.sqlite"))
    d.DB.create_user("admin", "admin123", role="admin")
    d.SESSIONS.clear()
    d.DB.ingest_requests([
        {"run_id": "sensor_t1", "path": "/.env", "canary": 1, "client_ip": "6.6.6.6",
         "session_id": "ui-s1", "user_agent": "ua", "is_ai": 1, "agent_type": "llm",
         "threat": 9.0, "families": "info_disclosure", "auth_level": 1,
         "method": "GET", "ts": 1700000000.0},
        {"run_id": "sensor_t1", "path": "/api/bounty/submit", "canary": 1,
         "client_ip": "6.6.6.6", "session_id": "ui-s1", "method": "POST",
         "user_agent": "ua", "is_ai": 1, "agent_type": "llm", "threat": 5.0,
         "families": "", "auth_level": 1, "ts": 1700000001.0},
    ])
    d.DB.ingest_intel([{"run_id": "sensor_t1", "session_id": "ui-s1",
                        "field": "delivery_exfil", "grade": "consistent",
                        "hash_key": "h", "sample": "poc", "ts": 1700000002.0}])
    d.DB.touch_sensor("t1")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), d.Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield port
    srv.shutdown()


def test_all_routes_render(hive):
    """全部目的地与 tab 路由: 不得出现'加载失败', 不得有 pageerror"""
    routes = ["situation", "events/tail", "events/requests", "events/actions",
              "ops", "arsenal", "investigate", "sessions",
              "fleet", "intel/graded", "intel/actors",
              "experiments/trials", "experiments/summary", "experiments/compare",
              "experiments/bandit", "experiments/runs", "config",
              "e/ip/6.6.6.6", "e/session/ui-s1"]
    with sync_playwright() as p:
        b = p.chromium.launch()
        ctx = b.new_context()
        pg = ctx.new_page()
        errors = []
        pg.on("pageerror", lambda e: errors.append(str(e)))
        pg.goto(f"http://127.0.0.1:{hive}/", wait_until="domcontentloaded")
        pg.wait_for_timeout(700)
        pg.fill("#login-user", "admin")
        pg.fill("#login-pass", "admin123")
        pg.click("button[type=submit]")
        pg.wait_for_timeout(1500)
        failures = []
        for route in routes:
            r = ctx.new_page()
            errs = []
            r.on("pageerror", lambda e: errs.append(str(e)))
            r.goto(f"http://127.0.0.1:{hive}/#/{route}", wait_until="domcontentloaded")
            r.wait_for_timeout(1400)
            text = r.evaluate("document.getElementById('content').innerText || ''")
            if "加载失败" in text:
                snippet = text[text.index("加载失败"):text.index("加载失败") + 80]
                failures.append(f"{route}: {snippet}")
            if errs:
                failures.append(f"{route}: JS {errs[0][:80]}")
            r.close()
        ctx.close()
        b.close()
    assert not failures, "前端路由断点:\n" + "\n".join(failures)
