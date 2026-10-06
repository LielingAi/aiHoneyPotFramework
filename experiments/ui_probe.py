# -*- coding: utf-8 -*-
"""新前端逐页探针 — 登录后各页容器/卡片数/JS 错误"""
import sys

from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8899"
PROBES = [
    ("situation", "#content .card", ".hist .bar"),
    ("live", ".feed", None),
    ("fleet", ".table-wrap", None),
    ("config", ".cfgrow", None),
    ("metrics", "#content .card", None),
    ("bandit", ".table-wrap, .empty", None),
    ("attribution", ".table-wrap, .empty", None),
    ("summary", ".table-wrap, .empty", None),
    ("compare", ".table-wrap, .empty", None),
    ("trials", ".table-wrap", None),
    ("events", ".table-wrap", None),
    ("intel", ".table-wrap", None),
    ("requests", ".table-wrap", None),
    ("runs", ".table-wrap", None),
]

with sync_playwright() as p:
    b = p.chromium.launch()
    ctx = b.new_context()
    pg = ctx.new_page()
    errs = []
    pg.on("pageerror", lambda e: errs.append(str(e)))
    pg.goto(BASE + "/", wait_until="domcontentloaded")
    pg.wait_for_timeout(900)
    pg.fill("#login-user", "admin")
    pg.fill("#login-pass", "wren-demo-2026")
    pg.click("button[type=submit]")
    pg.wait_for_timeout(3000)
    ok = 0
    for page_id, sel, extra in PROBES:
        r = ctx.new_page()
        e2 = []
        r.on("pageerror", lambda e: e2.append(str(e)))
        r.goto(f"{BASE}/#/{page_id}", wait_until="domcontentloaded")
        r.wait_for_timeout(2000)
        n = r.evaluate(f"document.querySelectorAll('{sel}').length") if sel else 0
        n2 = r.evaluate(f"document.querySelectorAll('{extra}').length") if extra else "-"
        status = "OK" if (n > 0 or sel.endswith("empty")) else "EMPTY?"
        if status == "OK":
            ok += 1
        print(f"[{status}] /{page_id}: 主容器={n} 附加={n2} err={e2[:1] or None}")
        r.close()
    print(f"\n{ok}/{len(PROBES)} 页渲染正常; 首屏 JS 错误: {errs[:2] or 'none'}")
    pg.goto(BASE + "/#/situation", wait_until="domcontentloaded")
    pg.wait_for_timeout(2500)
    pg.screenshot(path="experiments/results/newui_situation.png", full_page=False)
    ctx.close()
    b.close()
