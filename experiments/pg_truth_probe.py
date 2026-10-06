# -*- coding: utf-8 -*-
"""ground truth 采集: 真实 PG (docker 55432) 对各类畸形 startup 的精确响应"""
import socket
import struct
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 55432


def probe(payload, read_to=3.0):
    s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
    s.settimeout(read_to)
    s.sendall(payload)
    out = b""
    try:
        while True:
            d = s.recv(4096)
            if not d:
                break
            out += d
            if len(out) > 65536:
                break
    except (socket.timeout, ConnectionResetError):
        pass
    s.close()
    return out


cases = [
    ("SMB_garbage", b"\xffSMB\x72\x00\x00\x00\x00\x08\x01\x40"),
    ("SSLRequest", struct.pack(">II", 8, 80877103)),
    ("proto196608_bad_layout", struct.pack(">I", 16) + struct.pack(">I", 196608) + b"GARBAGE!!"),
    ("len_too_short", struct.pack(">I", 4)),
    ("proto_2_0", struct.pack(">I", 20) + struct.pack(">II", 131072, 0) + b"\x00" * 8),
    ("valid_startup", struct.pack(">I", 25) + struct.pack(">I", 196608)
     + b"user\x00postgres\x00\x00"),
]
for name, p in cases:
    r = probe(p)
    print(f"--- {name} port={PORT}")
    print(f"    resp({len(r)}B): {r[:160]!r}")
