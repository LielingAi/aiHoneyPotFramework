"""审计签名重放 — research/audit-signatures.json 的机器可执行版

每个签名 = 审计方识破蜜罐的 tell + 探针 + 期望。本脚本载入签名库,
对 SQLi 引擎 (纯函数, 进程内直调) 和假 PG (raw socket wire 重放) 逐项重放,
任何一项 FAIL = 对应 tell 仍然存活, 不得宣称对抗当前工具链。

用法: py -3.13 experiments/signature_replay.py
"""

import json
import os
import random
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.dynamic_sqli import sqli_response
from core.fake_db import FakePostgresServer
from core.fake_world import FakeWorld

SIGNATURES_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "research", "audit-signatures.json")


# ------------------------------------------------------------------
# 执行器
# ------------------------------------------------------------------
def r_bool_stability(sig):
    """TRUE 分支 = 输入前缀纯函数: resp(base AND a=a) == resp(base), 且 != resp(base AND a=b)"""
    rng = random.Random(20261005)
    rounds = sig["params"].get("rounds", 3)
    checks = []
    for _ in range(rounds):
        base = f"u{rng.randrange(10**6):06x}"
        a = rng.randrange(1000, 9999)
        t_body, t_status, _ = sqli_response(f"{base} AND {a}={a}", _WORLD)
        p_body, p_status, _ = sqli_response(base, _WORLD)
        f_body, f_status, _ = sqli_response(f"{base} AND {a}={a + 1}", _WORLD)
        checks.append(t_status == "200" and t_body == p_body
                      and f_status == "200" and '"rows_returned": 0' in f_body
                      and f_body != t_body)
    ok = all(checks)
    return ok, f"{rounds} 轮 base×(TRUE/裸查询/FALSE) 三元组, 等式成立: {sum(checks)}/{rounds}"


def r_chr_eval(sig):
    probe = sig["params"]["probe"]
    body, status, _ = sqli_response(probe, _WORLD)
    ok = status == "200" and '"qk"' in body and "CHR(" not in body
    return ok, f"probe={probe!r} status={status} 常量行求值={'qk' in body} 字面泄露={'CHR(' in body}"


def r_syntax_probe(sig):
    parts = []
    for p in sig["params"]["probes"]:
        body, status, _ = sqli_response(p, _WORLD)
        good = status == "500" and "syntax error at or near" in body
        parts.append(f"{p!r}->{status}{'+PGerr' if good else '+BAD'}")
    return all("+PGerr" in p for p in parts), " | ".join(parts)


def r_union_colcount(sig):
    bad, good = sig["params"]["bad_probe"], sig["params"]["good_probe"]
    b_body, b_status, _ = sqli_response(bad, _WORLD)
    g_body, g_status, _ = sqli_response(good, _WORLD)
    ok = (b_status == "500" and "same number of columns" in b_body
          and g_status == "200" and '["1", "2", "3"]' in g_body)
    return ok, f"bad->{b_status} good->{g_status} 常量回显={'[\"1\", \"2\", \"3\"]' in g_body}"


def r_stacked(sig):
    probe = sig["params"]["probe"]
    body, status, _ = sqli_response(probe, _WORLD)
    ok = status == "500" and "cannot insert multiple commands into a prepared statement" in body
    return ok, f"probe={probe!r} status={status} 拒绝语={'multiple commands' in body}"


def r_quote(sig):
    probe = sig["params"]["probe"]
    body, status, _ = sqli_response(probe, _WORLD)
    ok = status == "500" and "unterminated quoted string at or near" in body and probe[:-1] in body
    return ok, f"probe={probe!r} status={status} 片段回显={probe[:-1] in body}"


# ------------------------------------------------------------------
# 假 PG wire 重放
# ------------------------------------------------------------------
def _recv_msg(sock):
    head = b""
    while len(head) < 5:
        chunk = sock.recv(5 - len(head))
        if not chunk:
            return None, None
        head += chunk
    mt = head[:1]
    ln = struct.unpack(">I", head[1:])[0]
    body = b""
    while len(body) < ln - 4:
        chunk = sock.recv(ln - 4 - len(body))
        if not chunk:
            return None, None
        body += chunk
    return mt, body


def _pg_handshake(sock, world):
    startup = (struct.pack(">I", 196608)
               + b"user\x00prod_admin\x00database\x00nexus_prod\x00\x00")
    sock.sendall(struct.pack(">I", len(startup) + 4) + startup)
    mt, _ = _recv_msg(sock)
    if mt != b"R":
        raise RuntimeError(f"期望认证请求, 收到 {mt}")
    pw = world.db_password.encode()
    sock.sendall(b"p" + struct.pack(">I", 4 + len(pw) + 1) + pw + b"\x00")
    mt, _ = _recv_msg(sock)
    if mt != b"R":
        raise RuntimeError(f"期望认证通过, 收到 {mt}")
    while True:                       # ParameterStatus×N → ReadyForQuery
        mt, _ = _recv_msg(sock)
        if mt == b"Z":
            return
        if mt is None:
            raise RuntimeError("握手中断")


def _pg_start():
    world = FakeWorld("sigwire")
    srv = FakePostgresServer("127.0.0.1", 0,
                             lambda pw, u: world if pw == world.db_password else None)
    srv.start()
    port = srv._sock.getsockname()[1]
    sock = socket.create_connection(("127.0.0.1", port), timeout=8)
    _pg_handshake(sock, world)
    return srv, sock


def _pg_simple_query(sock, sql):
    """简单 Q 协议 — 返回 (messages, n_datarows, command_tag)"""
    payload = sql.encode() + b"\x00"
    sock.sendall(b"Q" + struct.pack(">I", 4 + len(payload)) + payload)
    msgs, rows, tag = [], 0, ""
    while True:
        mt, body = _recv_msg(sock)
        if mt is None:
            break
        msgs.append(mt)
        if mt == b"D":
            rows += 1
        if mt == b"C":
            tag = body.rstrip(b"\x00").decode(errors="ignore")
        if mt == b"Z":
            break
    return msgs, rows, tag


def r_pg_wire(sig):
    """扩展协议 Parse/Bind/Describe(portal)/Execute/Sync 字节级重放"""
    srv, sock = _pg_start()
    try:
        q = sig["params"]["query"].encode()
        param = sig["params"]["param"].encode()
        msgs = [b"P" + struct.pack(">I", 4 + 1 + len(q) + 1 + 2) + b"\x00" + q + b"\x00"
                + struct.pack(">H", 0),
                b"B" + struct.pack(">I", 4 + 1 + 1 + 2 + 2 + 4 + len(param) + 2)
                + b"\x00" + b"\x00" + struct.pack(">H", 0) + struct.pack(">H", 1)
                + struct.pack(">I", len(param)) + param + struct.pack(">H", 0),
                b"D" + struct.pack(">I", 4 + 1 + 1) + b"P" + b"\x00",
                b"E" + struct.pack(">I", 4 + 1 + 4) + b"\x00" + struct.pack(">I", 0),
                b"S" + struct.pack(">I", 4)]
        sock.sendall(b"".join(msgs))
        got = []
        exec_types, exec_rows, done = [], 0, False
        while True:
            mt, _ = _recv_msg(sock)
            if mt is None:
                return False, "连接中断"
            got.append(mt)
            if not done and mt in (b"1", b"2"):
                continue
            if not done and mt == b"T":          # Describe 的 RowDescription
                continue
            if not done:                          # Execute 应答流
                if mt == b"C":
                    done = True
                    continue
                exec_types.append(mt)
                if mt == b"D":
                    exec_rows += 1
                continue
            if done and mt == b"Z":
                break
        seq = b"".join(got).decode()
        dup_t = b"T" in exec_types               # Execute 里混进 RowDescription = 原死因
        ok = (not dup_t and exec_rows >= 1 and got[0] == b"1" and got[1] == b"2"
              and got[2] == b"T" and got[-1] == b"Z")
        return ok, f"序列={seq} Execute内T={dup_t} 数据行={exec_rows}"
    finally:
        sock.close()
        srv.stop() if hasattr(srv, "stop") else None


def r_pg_where(sig):
    srv, sock = _pg_start()
    try:
        _, all_rows, _ = _pg_simple_query(sock, "SELECT * FROM users")
        _, hit_rows, _ = _pg_simple_query(
            sock, f"SELECT * FROM users WHERE username = '{sig['params']['hit']}'")
        _, miss_rows, _ = _pg_simple_query(
            sock, f"SELECT * FROM users WHERE username = '{sig['params']['miss']}'")
        ok = all_rows == 8 and hit_rows == 1 and miss_rows == 0
        return ok, f"全表={all_rows} 命中={hit_rows} 未命中={miss_rows}"
    finally:
        sock.close()
        srv.stop() if hasattr(srv, "stop") else None


def _raw_probe(port, payload, read_to=3.0):
    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.settimeout(read_to)
    s.sendall(payload)
    out = b""
    try:
        while True:
            d = s.recv(4096)
            if not d:
                break
            out += d
    except (socket.timeout, ConnectionResetError):
        pass
    s.close()
    return out


def r_pg_startup_errors(sig):
    """nmap 指纹/H2 误判签名 — 四类畸形 startup 应答必须与真 PG14 字节级一致"""
    import struct as st
    srv, _ = _pg_start()
    port = srv._sock.getsockname()[1]
    try:
        smbprogneg = (bytes([0, 0, 0, 0xA4]) + b"\xffSMB\x72" + b"\x00" * 36
                      + b"\x40\x06\x00\x00\x01\x00\x00\x81\x00"
                      + b"\x02PC NETWORK PROGRAM 1.0\x00\x02MICROSOFT NETWORKS 1.03\x00"
                      + b"\x02MICROSOFT NETWORKS 3.0\x00\x02LANMAN1.0\x00"
                      + b"\x02LM1.2X002\x00\x02Samba\x00\x02NT LANMAN 1.0\x00"
                      + b"\x02NT LM 0.12\x00")
        real_smb = (b"E\x00\x00\x00\x8bSFATAL\x00VFATAL\x00C0A000\x00Munsupported frontend "
                    b"protocol 65363.19778: server supports 3.0 to 3.0\x00Fpostmaster.c\x00"
                    b"L2165\x00RProcessStartupPacket\x00\x00")
        proto20 = st.pack(">I", 20) + st.pack(">II", 131072, 0) + b"\x00" * 8
        real_20 = b"EFATAL:  unsupported frontend protocol 2.0: server supports 3.0 to 3.0\n\x00"
        bad_layout = st.pack(">I", 16) + st.pack(">I", 196608) + b"GARBAGE!!"
        real_layout = (b"E\x00\x00\x00\x85SFATAL\x00VFATAL\x00C08P01\x00Minvalid startup "
                       b"packet layout: expected terminator as last byte\x00Fpostmaster.c\x00"
                       b"L2277\x00RProcessStartupPacket\x00\x00")
        bare_garbage = b"\xffSMB\x72\x00\x00\x00\x00\x08\x01\x40"   # 无长度前缀
        h2_tell = b"\x52\x00\x00\x00\x08\x00\x00\x00\x03"           # 明文认证请求 (H2 同形)
        checks = []
        r = _raw_probe(port, smbprogneg)
        checks.append(("SMBProgNeg→C0A000", r == real_smb))
        r = _raw_probe(port, proto20)
        checks.append(("协议2.0→老式文本", r == real_20))
        r = _raw_probe(port, bad_layout)
        checks.append(("布局非法→C08P01", r == real_layout))
        r = _raw_probe(port, bare_garbage)
        checks.append(("裸乱码→静默", r == b""))
        auth_leak = False
        for p in (smbprogneg, proto20, bad_layout, bare_garbage):
            if h2_tell in _raw_probe(port, p):
                auth_leak = True
        checks.append(("无认证请求泄露(H2根因)", not auth_leak))
        ok = all(c for _, c in checks)
        return ok, " | ".join(f"{n}:{'OK' if c else 'XX'}" for n, c in checks)
    finally:
        srv._sock.close()


EXECUTORS = {
    "bool_stability": r_bool_stability,
    "chr_eval": r_chr_eval,
    "syntax_probe": r_syntax_probe,
    "union_colcount": r_union_colcount,
    "stacked": r_stacked,
    "quote": r_quote,
    "pg_wire": r_pg_wire,
    "pg_where": r_pg_where,
    "pg_startup_errors": r_pg_startup_errors,
}

_WORLD = FakeWorld("sig")


# ------------------------------------------------------------------
# 主流程
# ------------------------------------------------------------------
def main():
    lib = json.load(open(SIGNATURES_PATH, encoding="utf-8"))
    results = []
    for sig in lib["signatures"]:
        t0 = time.time()
        try:
            ok, detail = EXECUTORS[sig["replay"]](sig)
        except Exception as e:
            ok, detail = False, f"执行器异常: {type(e).__name__}: {e}"
        results.append({"id": sig["id"], "severity": sig["severity"],
                        "status": "PASS" if ok else "FAIL",
                        "detail": detail, "secs": round(time.time() - t0, 2)})
        print(f"[{'PASS' if ok else 'FAIL'}] {sig['id']:<22} {detail}")
    n_fail = sum(1 for r in results if r["status"] == "FAIL")
    os.makedirs("experiments/results", exist_ok=True)
    out = os.path.join("experiments/results", f"signature_replay_{time.strftime('%Y%m%d_%H%M%S')}.json")
    json.dump({"ts": time.strftime("%Y%m%d_%H%M%S"), "results": results},
              open(out, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"\n{len(results) - n_fail}/{len(results)} 签名存活对抗, 结果已存 {out}")
    return 1 if n_fail else 0


if __name__ == "__main__":
    sys.exit(main())
