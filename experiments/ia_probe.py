# -*- coding: utf-8 -*-
"""新 IA 逐目的地探针 — 6 目的地 + tab 组合"""
from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8899"
ROUTES = [
    ("situation", "态势", "#content .card", 6),
    ("events/tail", "事件流·实时", ".feed", 1),
    ("events/requests", "事件流·请求", ".table-wrap", 1),
    ("events/actions", "事件流·动作", ".table-wrap", 1),
    ("fleet", "传感器", ".table-wrap, .empty", 1),
    ("intel/graded", "情报·分级", ".table-wrap, .empty", 1),
    ("intel/actors", "情报·归因", ".table-wrap, .empty", 1),
    ("experiments/trials", "实验·明细", ".table-wrap", 1),
    ("experiments/summary", "实验·汇总", ".table-wrap, .empty", 1),
    ("experiments/compare", "实验·差分", ".table-wrap, .empty", 1),
    ("experiments/bandit", "实验·演化", ".table-wrap, .empty", 1),
    ("experiments/runs", "实验·运行", ".table-wrap, .empty", 1),
    ("config", "配置", ".cfgrow", 4),
]

with sync_playwright() as p:
    b = p.chromium.launch()
    ctx = b.new_context()
    pg = ctx.new_page()
    pg.set_viewport_size({"width": 1680, "height": 1000})
    errs = []
    pg.on("pageerror", lambda e: errs.append(str(e)))
    pg.goto(BASE + "/", wait_until="domcontentloaded")
    pg.wait_for_timeout(900)
    pg.fill("#login-user", "admin")
    pg.fill("#login-pass", "wren-demo-2026")
    pg.click("button[type=submit]")
    pg.wait_for_timeout(3000)
    ok = 0
    for route, label, sel, expect in ROUTES:
        r = ctx.new_page()
        e2 = []
        r.on("pageerror", lambda e: e2.append(str(e)))
        r.goto(f"{BASE}/#/{route}", wait_until="domcontentloaded")
        r.wait_for_timeout(2200)
        n = r.evaluate(f"document.querySelectorAll('{sel}').length")
        status = "OK" if n >= expect else "**FAIL**"
        if status == "OK":
            ok += 1
        print(f"[{status}] {label:14s} /#/{route:22s} 容器={n} (期望≥{expect}) err={e2[:1] or None}")
        r.close()
    print(f"\n{ok}/{len(ROUTES)} 路由正常; 首屏错误 {errs[:1] or 'none'}")
    # 侧栏只应有 6 项
    pg.goto(BASE + "/#/situation", wait_until="domcontentloaded")
    pg.wait_for_timeout(2200)
    nav = pg.evaluate("document.querySelectorAll('.nav-item').length")
    print("侧栏导航项:", nav)
    pg.screenshot(path="experiments/results/ia_situation.png")
    pg.goto(BASE + "/#/events/tail", wait_until="domcontentloaded")
    pg.wait_for_timeout(2000)
    pg.screenshot(path="experiments/results/ia_events.png")
    ctx.close()
    b.close()
