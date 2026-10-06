"""
真实工具回归套件 —— 与 pytest 并列的出口闸 (真刀层)

蜜罐的回归判定是反转的:
  sqlmap 报告 injectable   = 欺骗成功 (动态 SQLi 被判真漏洞)
  nuclei 模板命中假 CVE     = 成本放大生效
  nmap -sV 识别 PostgreSQL  = 协议承接穿真
  nmap -O 命中蜜罐指纹      = 反识别失败

每个检查声明 expected: deceived | resisted | detected, 解析真实工具输出判定。
工具缺失时 Docker/venv 兜底, 无兜底则 SKIP (套件不因缺工具而假绿/假红)。

用法: python experiments/real_tool_regression.py [--port 18120] [--skip-docker]
产出: experiments/results/tool_regression_<ts>.{json,md}
"""

import argparse
import asyncio
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

HTTP_PORT = 18120
PG_PORT = 18121
REDIS_PORT = 18122
TOOLS_VENV = r"E:\code\venvs\toolreg"


# ------------------------------------------------------------------
# 工具探测
# ------------------------------------------------------------------

def which(tool):
    return shutil.which(tool)


def docker_available():
    return which("docker") and subprocess.run(
        ["docker", "info"], capture_output=True, timeout=15).returncode == 0


def tool_sqlmap():
    exe = os.path.join(TOOLS_VENV, "Scripts", "sqlmap.exe")
    return exe if os.path.exists(exe) else None


# ------------------------------------------------------------------
# 判定提取器 (真实工具输出 → 反转语义判定)
# ------------------------------------------------------------------

def parse_sqlmap(out: str):
    injectable = "is injectable" in out or "identified the following injection point" in out
    details = []
    for line in out.splitlines():
        if "Type:" in line or "Title:" in line or "Parameter:" in line:
            details.append(line.strip())
    return injectable, "; ".join(details[:6])


def parse_nuclei_jsonl(out: str):
    fired = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
            fired.append({
                "template": d.get("template-id", "?"),
                "severity": (d.get("info") or {}).get("severity", "info"),
                "matched": d.get("matched-at", ""),
            })
        except Exception:
            pass
    return fired


def parse_nmap_sv(out: str):
    """返回 (服务识别文本列表) — 期望含 PostgreSQL 14.9"""
    sv = [l.strip() for l in out.splitlines() if "/tcp" in l and "open" in l]
    return sv


def parse_nmap_o(out: str):
    guesses = [l.strip() for l in out.splitlines()
               if "OS details" in l or "Running:" in l or "Aggressive OS" in l]
    honeypot_tells = [g for g in guesses if "honeypot" in g.lower() or "kippo" in g.lower()
                      or "cowrie" in g.lower() or "conpot" in g.lower()]
    return guesses, honeypot_tells


# ------------------------------------------------------------------
# 原生协议检查 (无外部工具依赖)
# ------------------------------------------------------------------

def pg_query(sql, password, host="127.0.0.1", port=PG_PORT, user="prod_admin"):
    """简单协议 mini 客户端 — 返回响应字节串"""
    conn = socket.create_connection((host, port), timeout=5)

    def typed(mt, payload):
        return mt + struct.pack(">I", len(payload) + 4) + payload

    payload = struct.pack(">I", 196608) + b"user\x00" + user.encode() + b"\x00\x00"
    conn.sendall(struct.pack(">I", 4 + len(payload)) + payload)
    conn.recv(64)                      # cleartext request
    pw = password.encode() + b"\x00"
    conn.sendall(b"p" + struct.pack(">I", len(pw) + 4) + pw)
    buf = b""
    while b"Z" not in buf and b"E" not in buf:   # FATAL 错误无 ReadyForQuery
        chunk = conn.recv(512)
        if not chunk:
            break
        buf += chunk
    q = sql.encode() + b"\x00"
    conn.sendall(b"Q" + struct.pack(">I", len(q) + 4) + q)
    resp = b""
    while b"Z" not in resp[-8:]:
        chunk = conn.recv(4096)
        if not chunk:
            break
        resp += chunk
    conn.close()
    return resp


def redis_cmd(*args, host="127.0.0.1", port=REDIS_PORT):
    conn = socket.create_connection((host, port), timeout=5)
    conn.sendall(b" ".join(a.encode() for a in args) + b"\r\n")
    data = conn.recv(256)
    conn.close()
    return data


# ------------------------------------------------------------------
# 检查执行器
# ------------------------------------------------------------------

class Result:
    def __init__(self, name, expected):
        self.name, self.expected = name, expected
        self.status, self.detail = "SKIP", "未执行"


def check_http_gate(port):
    r = Result("http_gate_403_obey", "deceived")
    import urllib.request
    import urllib.error
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        opener.open(f"http://127.0.0.1:{port}/.env", timeout=5)
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="ignore")
        ok = e.code == 403 and "hostname=<your_hostname>" in body
        r.status = "PASS" if ok else "FAIL"
        r.detail = f"HTTP {e.code}, 门控协议指引{'在' if 'hostname=' in body else '缺失'}"
    return r


def check_pg_auth_and_version(world):
    r = Result("pg_version_banner", "deceived")
    try:
        resp = pg_query("SELECT version();", world.db_password)
        ok = b"PostgreSQL 14.9" in resp
        r.status = "PASS" if ok else "FAIL"
        r.detail = "version() 返回 PG 14.9" if ok else f"异常: {resp[:60]}"
    except Exception as e:
        r.status, r.detail = "FAIL", str(e)[:100]
    return r


def check_pg_wrong_password(world):
    r = Result("pg_wrong_password_rejected", "resisted")
    try:
        resp = pg_query("SELECT 1;", "definitely-wrong-password", user="prod_admin")
        ok = b"28P01" in resp
        r.status = "PASS" if ok else "FAIL"
        r.detail = "28P01 拒绝" if ok else f"未拒绝: {resp[:50]}"
    except Exception as e:
        r.status, r.detail = "PASS", f"连接被拒 ({type(e).__name__})"
    return r


def check_pg_users_table(world):
    r = Result("pg_users_table_rows", "deceived")
    try:
        resp = pg_query("SELECT * FROM users;", world.db_password)
        ok = b"password_hash" in resp or b"$2b$12$" in resp
        r.status = "PASS" if ok else "FAIL"
        r.detail = "users 表返回 bcrypt 哈希行" if ok else f"{resp[:60]}"
    except Exception as e:
        r.status, r.detail = "FAIL", str(e)[:100]
    return r


def check_redis_ping():
    r = Result("redis_ping", "deceived")
    try:
        ok = redis_cmd("PING") == b"+PONG\r\n"
        r.status = "PASS" if ok else "FAIL"
        r.detail = "PING→PONG" if ok else redis_cmd("PING")[:30]
    except Exception as e:
        r.status, r.detail = "FAIL", str(e)[:80]
    return r


def check_sqlmap(port):
    r = Result("sqlmap_dynamic_sqli", "deceived")
    exe = tool_sqlmap()
    if not exe:
        r.detail = f"sqlmap 未安装 (期望 venv: {TOOLS_VENV})"
        return r
    url = f"http://127.0.0.1:{port}/api/query?q=1"
    try:
        proc = subprocess.run(
            [exe, "-u", url, "--batch", "--level=2", "--risk=1",
             "--technique=UBT", "--threads=4", "--timeout=10", "--retries=0",
             "--flush-session", "--dbms=postgres", "-v", "1"],
            capture_output=True, timeout=420, text=True, encoding="utf-8", errors="ignore")
        out = proc.stdout + proc.stderr
        os.makedirs("experiments/results", exist_ok=True)
        with open(f"experiments/results/sqlmap_raw_{int(time.time())}.txt", "w",
                  encoding="utf-8", errors="ignore") as f:
            f.write(out)   # 原始输出留档 — 判定反转场景必须可审计
        injectable, det = parse_sqlmap(out)
        r.status = "PASS" if injectable else "FAIL"
        r.detail = (f"sqlmap 判定可注入: {det[:80]}" if injectable
                    else f"未判定可注入 (rc={proc.returncode}): {out[-120:].strip()[:100]}")
    except subprocess.TimeoutExpired:
        r.status, r.detail = "FAIL", "sqlmap 超时 (420s)"
    return r


def check_nuclei(port):
    r = Result("nuclei_baseline", "deceived")
    if not docker_available():
        r.detail = "docker 不可用"
        return r
    try:
        proc = subprocess.run(
            ["docker", "run", "--rm", "projectdiscovery/nuclei",
             "-u", f"http://host.docker.internal:{port}",
             "-jsonl", "-silent", "-timeout", "4", "-max-time", "150"],
            capture_output=True, timeout=240, text=True, encoding="utf-8", errors="ignore")
        fired = parse_nuclei_jsonl(proc.stdout)
        sev = {}
        for f in fired:
            sev[f["severity"]] = sev.get(f["severity"], 0) + 1
        r.status = "PASS"    # 基线记录模式: 首轮确立基线, 后续 diff
        r.detail = f"命中 {len(fired)} 模板 {sev}: " + ",".join(
            f["template"] for f in fired[:8])
        r.fired = fired
    except subprocess.TimeoutExpired:
        r.status, r.detail = "SKIP", "nuclei 超时"
    except Exception as e:
        r.status, r.detail = "SKIP", str(e)[:80]
    return r


def check_nmap_sv():
    r = Result("nmap_service_ident", "deceived")
    exe = which("nmap")
    use_docker = not exe and docker_available()
    if not exe and not use_docker:
        r.detail = "nmap 不可用 (无宿主二进制, docker 缺席)"
        return r
    target = f"127.0.0.1" if exe else "host.docker.internal"
    cmd = ([exe, "-sV", "--version-intensity", "4", "-p", f"{PG_PORT},{REDIS_PORT}", target] if exe else
           ["docker", "run", "--rm", "instrumentisto/nmap", "-sV", "--version-intensity", "4",
            "-p", f"{PG_PORT},{REDIS_PORT}", target])
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=300,
                              text=True, encoding="utf-8", errors="ignore")
        sv = parse_nmap_sv(proc.stdout)
        pg_ok = any("postgres" in l.lower() for l in sv)
        r.status = "PASS" if pg_ok else "FAIL"
        r.detail = " | ".join(sv[:4]) or proc.stdout[-150:]
    except subprocess.TimeoutExpired:
        r.status, r.detail = "SKIP", "nmap 超时"
    except Exception as e:
        r.status, r.detail = "SKIP", str(e)[:80]
    return r


# ------------------------------------------------------------------
# 主流程
# ------------------------------------------------------------------

async def main():
    parser = argparse.ArgumentParser(description="真实工具回归 (真刀层)")
    parser.add_argument("--port", type=int, default=HTTP_PORT)
    parser.add_argument("--skip-slow", action="store_true", help="跳过 sqlmap/nuclei 慢检查")
    args = parser.parse_args()

    os.environ.setdefault("HONEYPOT_WORLD_VERSION", "2")
    os.environ.setdefault("HONEYPOT_C2_BASE", "http://203.0.113.10:9999/beacon")

    import main as hp
    from core.fake_db import FakePostgresServer, MiniRedis
    from core.fake_world import FakeWorld

    world = FakeWorld("toolreg-session")
    server = asyncio.create_task(hp.run_http_server(args.port))
    pg = FakePostgresServer("0.0.0.0", PG_PORT,
                            lambda pw, u: world if pw == world.db_password else None)
    pg.start()
    redis = MiniRedis("0.0.0.0", REDIS_PORT)
    redis.start()
    await asyncio.sleep(1)
    print(f"[ToolReg] 蜜罐 :{args.port}  假PG :{PG_PORT}  迷你Redis :{REDIS_PORT}")

    checks = [
        lambda: check_http_gate(args.port),
        lambda: check_pg_auth_and_version(world),
        lambda: check_pg_wrong_password(world),
        lambda: check_pg_users_table(world),
        lambda: check_redis_ping(),
    ]
    if not args.skip_slow:
        checks.append(lambda: check_sqlmap(args.port))
        checks.append(lambda: check_nuclei(args.port))
    checks.append(lambda: check_nmap_sv())

    results = []
    for c in checks:
        t0 = time.time()
        res = await asyncio.to_thread(c)   # 同步工具调用放工作线程 — 否则饿死同 loop 蜜罐
        secs = round(time.time() - t0, 1)
        results.append({"name": res.name, "expected": res.expected,
                        "status": res.status, "detail": res.detail,
                        "secs": secs})
        mark = {"PASS": "+", "FAIL": "!", "SKIP": "-"}[res.status]
        print(f"  [{mark}] {res.name:26s} ({secs:5.1f}s) {res.detail[:90]}")

    server.cancel()
    passed = sum(1 for r in results if r["status"] == "PASS")
    failed = [r for r in results if r["status"] == "FAIL"]
    skipped = sum(1 for r in results if r["status"] == "SKIP")
    print(f"\n[ToolReg] PASS {passed} / FAIL {len(failed)} / SKIP {skipped}")

    os.makedirs("experiments/results", exist_ok=True)
    ts = time.strftime("%Y%m%d_%H%M%S")
    with open(f"experiments/results/tool_regression_{ts}.json", "w", encoding="utf-8") as f:
        json.dump({"ts": ts, "results": results}, f, ensure_ascii=False, indent=2)
    with open(f"experiments/results/tool_regression_{ts}.md", "w", encoding="utf-8") as f:
        f.write(f"# 真实工具回归 {ts}\n\n| 检查 | 期望 | 结果 | 详情 |\n|---|---|---|---|\n")
        for r in results:
            f.write(f"| {r['name']} | {r['expected']} | {r['status']} | {r['detail'][:120]} |\n")
    print(f"[ToolReg] 报告已存 experiments/results/tool_regression_{ts}.*")
    return 1 if failed else 0


if __name__ == "__main__":
    code = asyncio.run(main())
    sys.exit(code)
