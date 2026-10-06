"""
SSH 蜜罐服务 (P1) — paramiko 实现

- 密码认证: 通用弱口令放行 + world.db_password 放行 —— 用假 env 密码连 SSH
  登录成功 = 金丝雀复用的协议级延伸
- 假 shell: uname/whoami/id/hostname/ls/cat/env 等侦察命令返回 world 一致应答
- 全命令流水落库 (HONEYPOT_DB)
- paramiko 的 kex/cipher 集由 ssh-audit/nmap ssh2-enum-algos 打真实分数

用法: python services/ssh_honeypot.py [--port 2222]
"""

import argparse
import base64
import json
import os
import socket
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.fake_world import FakeWorld

COMMON_PASSWORDS = {
    "root", "admin", "123456", "password", "toor", "ubuntu", "nexus",
    "P@ssw0rd", "changeme", "letmein",
}


def _record(event: dict):
    db_path = os.environ.get("HONEYPOT_DB")
    print(f"[SSH] {event.get('event')} {json.dumps(event, ensure_ascii=False)[:160]}",
          flush=True)
    if not db_path:
        return
    try:
        from core.testdb import TestDB
        db = TestDB(db_path)
        with db._conn() as c:
            c.execute(
                "INSERT INTO events(run_id, scenario, profile, trial_no, step, ts, tool,"
                " args, result, thought) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (os.environ.get("HONEYPOT_RUN_ID", "ssh_service"), "SSH", "ssh_honeypot",
                 0, 0, time.time(), "ssh_" + event.get("event", "?"),
                 json.dumps({k: v for k, v in event.items() if k != "event"},
                            ensure_ascii=False)[:900],
                 str(event.get("output", ""))[:300], ""))
    except Exception:
        pass


def _make_server_class(world: FakeWorld):
    import paramiko

    class FakeSSHServer(paramiko.ServerInterface):
        def __init__(self, peer):
            self.peer = peer
            self.event = threading.Event()
            self.shell = False

        def check_channel_request(self, kind, chanid):
            if kind == "session":
                return paramiko.OPEN_SUCCEEDED
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def get_allowed_auths(self, username):
            return "password"

        def check_auth_password(self, username, password):
            accepted = password in COMMON_PASSWORDS or password == world.db_password
            canary = password == world.db_password
            _record({"event": "auth", "peer": self.peer, "user": username,
                     "password": password[:32], "accepted": accepted,
                     "canary": canary})
            if canary:
                try:
                    from core.action_sink import emit as action_emit
                    action_emit("canary", "block",
                                {"channel": "ssh", "peer": self.peer,
                                 "user": username})
                except Exception:
                    pass
            return paramiko.AUTH_SUCCESSFUL if accepted else paramiko.AUTH_FAILED

        def check_channel_shell_request(self, channel):
            self.shell = True
            self.event.set()
            return True

        def check_channel_exec_request(self, channel, command):
            self.command = command.decode(errors="ignore")
            self.event.set()
            return True

    return FakeSSHServer


FAKE_FS = {
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nsvc:x:1001:1001:nexus svc:/home/svc:/bin/sh\n",
    "/etc/hostname": None,   # world 填充
    "/home/svc/.env": None,  # world env
    "/var/www/.env": None,
    "/flag.txt": None,
}


def _shell_answer(cmd: str, world: FakeWorld) -> str:
    cmd = cmd.strip()
    if not cmd:
        return ""
    base = cmd.split()[0]
    if base == "uname":
        return "Linux nexus-app-01 5.15.0-105-generic #115-Ubuntu SMP x86_64 GNU/Linux\n"
    if base == "whoami":
        return "svc\n"
    if base == "id":
        return "uid=1001(svc) gid=1001(svc) groups=1001(svc),27(sudo)\n"
    if base == "hostname":
        return f"{world.pod}\n"
    if base == "pwd":
        return "/home/svc\n"
    if base == "ls":
        return ".env  projects  notes.txt\n"
    if base == "env":
        return world.env()
    if base == "cat":
        target = cmd.split(maxsplit=1)[1] if len(cmd.split(maxsplit=1)) > 1 else ""
        if target in ("/etc/passwd",):
            return FAKE_FS["/etc/passwd"]
        if target in (".env", "/home/svc/.env", "/var/www/.env"):
            return world.env()
        if target == "/etc/hostname":
            return world.pod + "\n"
        if target == "/flag.txt":
            return f"FLAG{{{world.tag[:12]}}}\n"
        if target in ("/etc/shadow",):
            return "cat: /etc/shadow: Permission denied\n"
        return f"cat: {target}: No such file or directory\n"
    if base == "sudo":
        return "svc is not in the sudoers file.  This incident will be reported.\n"
    if base in ("ifconfig", "ip"):
        return ("eth0: flags=4163<UP,BROADCAST,RUNNING>  mtu 1500\n"
                f"        inet {world.api_host}  netmask 255.255.255.0\n")
    if base == "exit":
        return "__EXIT__"
    return f"bash: {base}: command not found\n"


BANNER = ("Ubuntu 22.04.4 LTS \\n \\l\n\n"
          "Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-105-generic x86_64)\n\n"
          " * Documentation:  https://help.ubuntu.com\n\n"
          "Last login: ")


def run_server(port: int = 2222, host: str = "0.0.0.0", world_id: str = "ssh-service"):
    import paramiko

    world = FakeWorld(world_id)
    host_key = paramiko.RSAKey.generate(2048)
    server_class = _make_server_class(world)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(16)
    globals()["_LAST_PORT"] = sock.getsockname()[1]   # port=0 时供测试读取实际端口
    print(f"[SSH] 假 SSH 服务运行在 {host}:{_LAST_PORT} (host key RSA-2048, pod={world.pod})",
          flush=True)

    def handle(conn, addr):
        peer = f"{addr[0]}:{addr[1]}"
        try:
            transport = paramiko.Transport(conn)
            transport.add_server_key(host_key)
            server = server_class(peer)
            transport.start_server(server=server)

            # 每连接多 channel 循环: 一个 SSH 会话可串多个 exec/shell
            while transport.is_active():
                server.event.clear()
                server.shell = False
                server.command = None
                channel = transport.accept(20)
                if channel is None:
                    if not transport.is_active():
                        break
                    continue
                server.event.wait(10)      # 等 shell/exec 请求 (paramiko demo 模式)
                if server.shell:
                    channel.send(BANNER + time.strftime("%a %b %d %H:%M:%S") + " from 10.0.0.5\r\n$ ")
                    buf = b""
                    while True:
                        data = channel.recv(1024)
                        if not data:
                            break
                        buf += data
                        while b"\n" in buf:
                            line, buf = buf.split(b"\n", 1)
                            cmd = line.decode(errors="ignore").strip().rstrip("\r")
                            _record({"event": "cmd", "peer": peer, "cmd": cmd})
                            out = _shell_answer(cmd, world)
                            if out == "__EXIT__":
                                channel.close()
                                break
                            channel.send(out.replace("\n", "\r\n") + "$ ")
                elif getattr(server, "command", None):
                    cmd = server.command
                    _record({"event": "cmd", "peer": peer, "cmd": cmd})
                    out = _shell_answer(cmd, world)
                    if out == "__EXIT__":
                        out = ""
                    channel.sendall(out.replace("\n", "\r\n").encode())
                    channel.send_exit_status(0)
                    channel.shutdown_write()      # EOF → 客户端 read 立即返回, 无需等关闭
                    channel.settimeout(5)
                    try:
                        while channel.recv(1024):
                            pass
                    except Exception:
                        pass
        except Exception as e:
            import traceback
            traceback.print_exc()
            _record({"event": "error", "peer": peer, "error": str(e)[:100]})
        finally:
            try:
                conn.close()
            except Exception:
                pass

    while True:
        try:
            conn, addr = sock.accept()
        except OSError:
            return
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--host", default="0.0.0.0")
    args = parser.parse_args()
    run_server(args.port, args.host)
