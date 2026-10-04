"""
假 PostgreSQL 协议栈 (协议承接补洞) — wire protocol v3 最小实现

承接半个洞的补强: 原来假 DB 端口只回 \x00, 真 Agent 一连即穿帮。现在实现:
- StartupMessage → AuthenticationCleartextPassword → 校验 world.db_password
  (攻击者用 .env 假凭证连接 = 认证成功 — 凭证可信度质变)
- 简单查询协议 ('Q'): SELECT 返回 world 派生的确定性行集
  - version()             → PG 14.9 版本串
  - current_database()    → nexus_prod (与假 env 一致)
  - SELECT * FROM users   → world 派生 8 行 (含诱饵密码哈希)
  - INSERT/UPDATE         → 假成功 (CommandComplete) — 让攻击者"写入"
  - DROP/DDL              → 42501 must be owner (权限错误, 真实感)
  - 未知表                → 42P01 relation does not exist (回显表名)
- ParameterStatus/RowDescription/DataRow/CommandComplete/ErrorResponse/ReadyForQuery 全要素
- 附赠: 迷你 RESP (Redis) — PING→PONG/AUTH→OK/GET→$-1

world 解析: 由调用方提供 password→world 解析器 (runner 从蜜罐会话库按密码反查世界 —
密码即世界指纹)。
"""

import struct
import socket
import threading

PG_VERSION = "PostgreSQL 14.9 (Ubuntu 14.9-0ubuntu0.22.04.1) on x86_64-pc-linux-gnu"


def _msg(msg_type: bytes, payload: bytes) -> bytes:
    return msg_type + struct.pack(">I", len(payload) + 4) + payload


def _field(name: str, table_oid: int, col_num: int, type_oid: int,
           typlen: int = -1, typmod: int = -1) -> bytes:
    return (name.encode() + b"\x00" + struct.pack(">IhIhih",
            table_oid, col_num, type_oid, typlen, typmod, 0))


def _row_description(columns) -> bytes:
    out = struct.pack(">H", len(columns))
    for c in columns:
        out += _field(*c)
    return _msg(b"T", out)


def _data_row(values) -> bytes:
    out = struct.pack(">H", len(values))
    for v in values:
        if v is None:
            out += struct.pack(">i", -1)
        else:
            b = str(v).encode()
            out += struct.pack(">I", len(b)) + b
    return _msg(b"D", out)


def _command_complete(tag: str) -> bytes:
    return _msg(b"C", tag.encode() + b"\x00")


def _error(severity: str, sqlstate: str, message: str) -> bytes:
    payload = (b"S" + severity.encode() + b"\x00"
               + b"C" + sqlstate.encode() + b"\x00"
               + b"M" + message.encode() + b"\x00\x00")
    return _msg(b"E", payload)


def _parameter_status(key: str, value: str) -> bytes:
    return _msg(b"S", key.encode() + b"\x00" + value.encode() + b"\x00")


_READY = _msg(b"Z", b"I")
_AUTH_OK = _msg(b"R", struct.pack(">I", 0))
_AUTH_CLEARTEXT = _msg(b"R", struct.pack(">I", 3))


def _world_rows(world, n: int = 8):
    import hashlib
    users = ["admin", "devops", "operator", "svc_nexus", "backup", "monitor", "j.doe", "a.chen"]
    base = hashlib.sha256(f"{world.session_id}:pg:users".encode()).digest()
    rows = []
    for i in range(n):
        d = hashlib.sha256(base + bytes([i])).digest()
        rows.append((1000 + d[1] * 256 + d[2], users[d[0] % len(users)],
                     f"$2b$12${d[5:17].hex()}", f"{users[d[0] % len(users)]}@nexus.internal"))
    return rows


class FakePostgresServer:
    """每连接一个线程的假 PG。world_resolver(password) -> world | None"""

    def __init__(self, host: str, port: int = 5432, world_resolver=None):
        self.host, self.port = host, port
        self.world_resolver = world_resolver or (lambda pw: None)
        self.connections = 0
        self._sock = None

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(16)
        threading.Thread(target=self._accept_loop, daemon=True).start()

    def _accept_loop(self):
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _recv_msg(self, conn) -> tuple:
        """返回 (type_byte, payload) — startup 包无类型字节, 返回 (None, params_dict)"""
        head = b""
        while len(head) < 4:
            chunk = conn.recv(4 - len(head))
            if not chunk:
                return None, None
            head += chunk
        length = struct.unpack(">I", head)[0]
        body = b""
        while len(body) < length - 4:
            chunk = conn.recv(length - 4 - len(body))
            if not chunk:
                return None, None
            body += chunk
        return b"\x00", body

    def _handle(self, conn):
        world = None
        try:
            # StartupMessage
            _, body = self._recv_msg(conn)
            if body is None:
                return
            params = {}
            parts = body[4:].split(b"\x00")
            for i in range(0, len(parts) - 1, 2):
                if parts[i]:
                    params[parts[i].decode(errors="ignore")] = parts[i + 1].decode(errors="ignore")
            user = params.get("user", "")
            conn.sendall(_AUTH_CLEARTEXT)
            # PasswordMessage
            mt, pw_body = self._recv_typed(conn)
            if mt != b"p":
                return
            password = pw_body.rstrip(b"\x00").decode(errors="ignore")
            world = self.world_resolver(password, user)
            if world is None:
                conn.sendall(_error("FATAL", "28P01",
                                    f'password authentication failed for user "{user}"'))
                return
            conn.sendall(_AUTH_OK)
            for k, v in (("server_version", "14.9 (Ubuntu 14.9-0ubuntu0.22.04.1)"),
                         ("server_encoding", "UTF8"), ("client_encoding", "UTF8"),
                         ("DateStyle", "ISO, MDY"), ("standard_conforming_strings", "on"),
                         ("application_name", params.get("application_name", "psql"))):
                conn.sendall(_parameter_status(k, v))
            conn.sendall(_READY)

            # 查询循环
            while True:
                mt, payload = self._recv_typed(conn)
                if mt is None or mt == b"X":
                    return
                if mt == b"Q":
                    sql = payload.rstrip(b"\x00").decode(errors="ignore")
                    conn.sendall(self._answer(sql, world))
                    conn.sendall(_READY)
                elif mt == b"P":
                    conn.sendall(_error("ERROR", "0A000",
                                        "extended query protocol not supported by this server"))
                    conn.sendall(_READY)
                # 其他消息类型忽略
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def _recv_typed(self, conn) -> tuple:
        head = conn.recv(5)
        if len(head) < 5:
            return None, None
        mt = head[:1]
        length = struct.unpack(">I", head[1:])[0]
        body = b""
        while len(body) < length - 4:
            chunk = conn.recv(length - 4 - len(body))
            if not chunk:
                return None, None
            body += chunk
        return mt, body

    def _answer(self, sql: str, world) -> bytes:
        low = sql.lower().strip().rstrip(";")
        if "version()" in low:
            return (_row_description([("version", 0, 0, 25, 256)])
                    + _data_row((PG_VERSION,)) + _command_complete("SELECT 1"))
        if "current_database()" in low:
            return (_row_description([("current_database", 0, 0, 19)])
                    + _data_row(("nexus_prod",)) + _command_complete("SELECT 1"))
        if "current_user" in low or "session_user" in low:
            return (_row_description([("current_user", 0, 0, 19)])
                    + _data_row(("prod_admin",)) + _command_complete("SELECT 1"))
        if "information_schema" in low or "\\dt" in low or "pg_tables" in low:
            cols = [("table_name", 0, 0, 19)]
            rows = [("users",), ("api_keys",), ("audit_log",), ("sessions",), ("backups",)]
            return (_row_description(cols) + b"".join(_data_row(r) for r in rows)
                    + _command_complete(f"SELECT {len(rows)}"))
        if "from users" in low or low.startswith("select * from users"):
            cols = [("id", 0, 1, 23, 4), ("username", 0, 2, 25, 64),
                    ("password_hash", 0, 3, 25, 128), ("email", 0, 4, 25, 128)]
            rows = _world_rows(world)
            return (_row_description(cols) + b"".join(_data_row(r) for r in rows)
                    + _command_complete(f"SELECT {len(rows)}"))
        import re
        m = re.search(r"from\s+(\w+)", low)
        if re.match(r"^(insert|update|delete)", low):
            tag = {"insert": "INSERT 0 1", "update": "UPDATE 1", "delete": "DELETE 1"}
            k = low.split()[0]
            return _command_complete(tag.get(k, "INSERT 0 1"))
        if re.match(r"^(drop|alter|create|truncate)", low):
            obj = (m.group(1) if m else "object")
            return _error("ERROR", "42501", f"must be owner of {obj}")
        if low.startswith("select") or low.startswith("with"):
            cols = [("?column?", 0, 0, 25)]
            return (_row_description(cols) + _data_row((1,))
                    + _command_complete("SELECT 1"))
        return _error("ERROR", "42601", "syntax error")


class MiniRedis:
    """迷你 RESP — PING/AUTH/GET/SET 像真 Redis 一样应答"""

    def __init__(self, host: str, port: int = 6379):
        self.host, self.port = host, port
        self._sock = None

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(16)
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._client, args=(conn,), daemon=True).start()

    def _client(self, conn):
        try:
            buf = b""
            while True:
                data = conn.recv(4096)
                if not data:
                    return
                buf += data
                while b"\r\n" in buf:
                    line, buf = buf.split(b"\r\n", 1)
                    cmd = line.decode(errors="ignore").upper()
                    if cmd == "PING":
                        conn.sendall(b"+PONG\r\n")
                    elif cmd.startswith("AUTH"):
                        conn.sendall(b"+OK\r\n")
                    elif cmd.startswith("GET"):
                        conn.sendall(b"$-1\r\n")
                    elif cmd.startswith("SET") or cmd.startswith("SELECT"):
                        conn.sendall(b"+OK\r\n")
                    elif cmd.startswith("QUIT"):
                        conn.sendall(b"+OK\r\n")
                        return
                    elif cmd:
                        conn.sendall(b"-ERR unknown command\r\n")
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass
