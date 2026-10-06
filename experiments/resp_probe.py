# -*- coding: utf-8 -*-
"""多分辨率适配验证 — 2560 超宽 / 1920 全屏 / 1280 常规 / 768 平板 / 420 手机"""
from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8899"
VIEWPORTS = [
    ("uw2560", 2560, 1400, "超宽 2K+"),
    ("full1920", 1920, 1080, "全屏 1080p"),
    ("std1280", 1280, 800, "常规笔记本"),
    ("pad768", 768, 1024, "平板竖屏"),
    ("phone420", 420, 880, "手机"),
]

with sync_playwright() as p:
    b = p.chromium.launch()
    ctx = b.new_context()
    pg = ctx.new_page()
    pg.set_viewport_size({"width": 1600, "height": 900})
    pg.goto(BASE + "/", wait_until="domcontentloaded")
    pg.wait_for_timeout(800)
    pg.fill("#login-user", "admin")
    pg.fill("#login-pass", "wren-demo-2026")
    pg.click("button[type=submit]")
    pg.wait_for_timeout(2500)

    for tag, w, h, label in VIEWPORTS:
        pg.set_viewport_size({"width": w, "height": h})
        pg.wait_for_timeout(900)
        overflow = pg.evaluate(
            "document.documentElement.scrollWidth > window.innerWidth + 2")
        content_w = pg.evaluate(
            "Math.round(document.querySelector('.content').getBoundingClientRect().width)")
        side_visible = pg.evaluate(
            "getComputedStyle(document.querySelector('.sidebar')).transform")
        pg.screenshot(path=f"experiments/results/resp_{tag}.png")
        print(f"[{label}] {w}x{h}: 横向溢出={overflow} 内容宽={content_w} 侧栏transform={side_visible[:24]}")
    b.close()
