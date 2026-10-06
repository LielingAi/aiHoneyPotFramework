"""传感器外送器 — 产品化 P0: 传感器事件批量送达 hive

传感器上只跑蜜罐进程 + 本 shipper; 事件 (requests/intel) 经内存队列异步外送:
  - 批量: 每 2s 或满 50 条 flush 一次
  - 可靠: 送达失败落 spool 目录 (jsonl), 下次 flush 优先补发 (断网续传)
  - 零依赖: stdlib urllib; 与主进程解耦 (后台线程, 蜜罐热路径只做一次 queue.put)

配置 (环境变量):
  HONEYPOT_HIVE_URL   如 http://hive:8899 (不设 = 不外送, 纯实验态)
  HONEYPOT_HIVE_TOKEN 与 hive 端 HONEYPOT_CONSOLE_TOKEN 一致
  HONEYPOT_SENSOR_ID  传感器身份, 入 run_id 列区分来源 (默认 hostname)
  HONEYPOT_SPOOL_DIR  spool 目录 (默认 ./spool)
"""

import json
import os
import queue
import socket
import threading
import time
import urllib.request

FLUSH_INTERVAL = 2.0
FLUSH_SIZE = 50
MAX_BATCH = 200
TIMEOUT = 10


class SensorShipper:
    def __init__(self, hive_url: str = None, token: str = None,
                 sensor_id: str = None, spool_dir: str = None):
        self.hive_url = (hive_url or os.environ.get("HONEYPOT_HIVE_URL", "")).rstrip("/")
        self.token = token or os.environ.get("HONEYPOT_HIVE_TOKEN", "")
        self.sensor_id = sensor_id or os.environ.get(
            "HONEYPOT_SENSOR_ID") or socket.gethostname()
        self.spool_dir = spool_dir or os.environ.get("HONEYPOT_SPOOL_DIR", "spool")
        self._q: "queue.Queue[dict]" = queue.Queue()
        self._stop = threading.Event()
        self._thread: threading.Thread = None
        self.shipped = 0
        self.spool_pending = 0

    # ------------------------------------------------------------------
    def start(self):
        if not self.hive_url:
            return False
        os.makedirs(self.spool_dir, exist_ok=True)
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return True

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)
        self._flush()          # 收尾: 队列剩余尽力送出

    def enqueue(self, kind: str, record: dict):
        """蜜罐热路径调用 — 非阻塞, 一次 put"""
        if not self.hive_url:
            return
        record = dict(record)
        record["run_id"] = f"sensor_{self.sensor_id}"
        record.setdefault("ts", time.time())
        record["_kind"] = kind
        try:
            self._q.put_nowait(record)
        except queue.Full:
            pass                   # 极端背压下丢弃外送 (本地落库不受影响)

    # ------------------------------------------------------------------
    def _loop(self):
        while not self._stop.is_set():
            time.sleep(FLUSH_INTERVAL)
            self._flush()

    def _spool_files(self):
        import glob
        return sorted(glob.glob(os.path.join(self.spool_dir, "*.jsonl")))

    def _flush(self):
        batch = []
        while len(batch) < MAX_BATCH:
            try:
                batch.append(self._q.get_nowait())
            except queue.Empty:
                break
        # spool 补发优先 (断网续传: 旧事件先送达, 顺序即优先级)
        for f in self._spool_files():
            if len(batch) >= MAX_BATCH:
                break
            try:
                with open(f, encoding="utf-8") as fh:
                    for line in fh:
                        if len(batch) >= MAX_BATCH:
                            break
                        batch.append(json.loads(line))
                os.remove(f)
            except (OSError, json.JSONDecodeError):
                continue
        if not batch:
            return
        if self._post(batch):
            self.shipped += len(batch)
        else:
            self._spool(batch)
        self.spool_pending = sum(
            sum(1 for _ in open(f, encoding="utf-8"))
            for f in self._spool_files()) if self._spool_files() else 0

    def _post(self, batch: list) -> bool:
        reqs = [r for r in batch if r.get("_kind") == "request"]
        intel = [r for r in batch if r.get("_kind") == "intel"]
        beacons = [r for r in batch if r.get("_kind") == "beacon"]
        cm = [r for r in batch if r.get("_kind") == "cm_action"]
        body = json.dumps({"requests": reqs, "intel": intel,
                           "beacons": beacons, "cm_actions": cm}).encode("utf-8")
        req = urllib.request.Request(
            f"{self.hive_url}/ingest", data=body,
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self.token}"})
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(req, timeout=TIMEOUT) as r:
                return r.status == 200
        except Exception:
            return False

    def _spool(self, batch: list):
        try:
            path = os.path.join(self.spool_dir, f"spool-{int(time.time()*1000)}.jsonl")
            with open(path, "w", encoding="utf-8") as f:
                for r in batch:
                    f.write(json.dumps(r, ensure_ascii=False) + "\n")
        except OSError:
            pass


_shipper: SensorShipper = None


def init_from_env() -> bool:
    """main.py 启动时调用: 配置了 HIVE_URL 则启用外送"""
    global _shipper
    if not os.environ.get("HONEYPOT_HIVE_URL"):
        return False
    _shipper = SensorShipper()
    return _shipper.start()


def get_shipper() -> SensorShipper:
    return _shipper


def enqueue(kind: str, record: dict):
    if _shipper:
        _shipper.enqueue(kind, record)
