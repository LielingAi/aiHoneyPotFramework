"""
传统扫描器基线流量生成 — 行为指纹 v2 的非 LLM 对照组

模拟 nuclei/dirb 式脚本扫描: 固定间隔、词表路径、无会话一致性、
不构造授权协议、参数为词表值。服务端正常落盘 (HONEYPOT_DB),
之后 fingerprint_eval 可将这些会话标签为 script 做 llm-vs-script 判别。

用法: python experiments/scanner_baseline.py [--sessions 5] [--db path]
"""

import asyncio
import os
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import main as honeypot_main

WORDLIST = [
    "/admin", "/login", "/wp-login.php", "/phpmyadmin", "/backup", "/config",
    "/.env", "/.git/config", "/debug", "/api", "/api/v1", "/api/v2",
    "/status", "/health", "/server-status", "/actuator", "/metrics",
    "/test", "/dev", "/staging", "/old", "/bak", "/tmp", "/xmlrpc.php",
    "/sitemap.xml", "/robots.txt", "/crossdomain.xml", "/.well-known/security.txt",
    "/api/auth", "/api/query", "/api/internal", "/console", "/manager/html",
    "/jmx-console", "/solr", "/jenkins", "/git", "/svn", "/.svn/entries",
    "/database.sql", "/db.sql", "/dump.sql", "/config.json", "/package.json",
]

JUNK_PARAMS = ["id=1' OR '1'='1", "file=../../../../etc/passwd", "redirect=http://evil.example",
               "cmd=whoami", "q=<script>alert(1)</script>", "user=admin&password=admin"]


def run_scanner(target: str, sessions: int = 5):
    import random
    random.seed(42)
    for s in range(sessions):
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        headers = {
            "User-Agent": random.choice([
                "Mozilla/5.0 (compatible; Nuclei/3.1.0)",
                "dirb/2.22",
                "python-requests/2.31.0",
            ]),
            "X-Session-Id": f"scanner_{int(time.time())}_{s}",
        }
        for path in WORDLIST:
            url = target + path
            if random.random() < 0.15:
                url += "?" + random.choice(JUNK_PARAMS)
            try:
                req = urllib.request.Request(url, headers=headers)
                opener.open(req, timeout=2).read()
            except Exception:
                pass
            time.sleep(0.05 + random.random() * 0.04)   # 脚本式均匀间隔


async def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=18110)
    parser.add_argument("--sessions", type=int, default=5)
    parser.add_argument("--db", default="experiments/results/testdb.sqlite")
    args = parser.parse_args()

    os.environ["HONEYPOT_DB"] = args.db
    os.environ["HONEYPOT_RUN_ID"] = f"scanner_baseline_{int(time.time())}"
    os.environ["HONEYPOT_BEACON_BASE"] = "http://127.0.0.1:9999/beacon"

    # runs 表登记 (fingerprint_eval 按 run_id 取标签)
    from core.testdb import TestDB
    TestDB(args.db).record_run(os.environ["HONEYPOT_RUN_ID"], False,
                               note="profiles=scanner_baseline")

    server = asyncio.create_task(honeypot_main.run_http_server(args.port))
    await asyncio.sleep(1)
    print(f"[Scanner] 生成 {args.sessions} 组脚本扫描流量 → {os.environ['HONEYPOT_RUN_ID']}")
    await asyncio.to_thread(run_scanner, f"http://127.0.0.1:{args.port}", args.sessions)
    server.cancel()
    try:
        await server
    except Exception:
        pass
    print("[Scanner] 完成 — 用 fingerprint_eval.py 评估 (标签: script)")


if __name__ == "__main__":
    asyncio.run(main())
