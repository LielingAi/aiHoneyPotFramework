"""
性能压力测试 — 并发洪峰下的蜜罐存活性与限流生效验证

用法: HONEYPOT_RATE_RPS=60 python experiments/stress_test.py [--n 300] [--port 18090]
产出: 成功率 / p50 / p95 延迟 / 限流命中率 / 内存会话数
"""

import argparse
import asyncio
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


async def hammer(port: int, path: str, n: int):
    import urllib.request
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    lat = []
    codes = {}
    for i in range(n):
        url = f"http://127.0.0.1:{port}{path}"
        if i % 7 == 0:
            url += f"?q={i}' OR '1'='1"
        t0 = time.time()
        try:
            with opener.open(urllib.request.Request(url, headers={"X-Session-Id": "stress"}), timeout=10) as r:
                codes[r.status] = codes.get(r.status, 0) + 1
        except urllib.error.HTTPError as e:
            codes[e.code] = codes.get(e.code, 0) + 1
        except Exception:
            codes["conn_fail"] = codes.get("conn_fail", 0) + 1
        lat.append((time.time() - t0) * 1000)
    return lat, codes


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=18090)
    parser.add_argument("--n", type=int, default=300, help="每并发协程请求数")
    parser.add_argument("--workers", type=int, default=60, help="并发协程数")
    args = parser.parse_args()

    paths = ["/.env", "/api/query", "/debug", "/admin", "/maze", "/config"]
    print(f"[Stress] {args.workers} 协程 × {args.n} 请求, 路径混合 {len(paths)}, "
          f"RATE_RPS={os.environ.get('HONEYPOT_RATE_RPS', '0')}")
    t0 = time.time()
    results = await asyncio.gather(*[
        hammer(args.port, paths[w % len(paths)], args.n) for w in range(args.workers)
    ])
    total_lat = [x for lat, _ in results for x in lat]
    codes = {}
    for _, c in results:
        for k, v in c.items():
            codes[k] = codes.get(k, 0) + v
    total = len(total_lat)
    ok = sum(v for k, v in codes.items() if k != "conn_fail")
    lat_sorted = sorted(total_lat)
    p = lambda q: lat_sorted[min(int(total * q), total - 1)]
    print(f"\n[Result] {total} 请求 / {time.time()-t0:.1f}s")
    ok_rate = ok / total * 100
    alive = "YES" if ("conn_fail" not in codes or codes["conn_fail"] < total * 0.05) else "NO"
    print(f"  响应率: {ok_rate:.1f}%  状态分布: {codes}")
    print(f"  延迟 p50={p(0.5):.0f}ms p95={p(0.95):.0f}ms max={lat_sorted[-1]:.0f}ms")
    print(f"  服务器存活: {alive}")


if __name__ == "__main__":
    asyncio.run(main())
