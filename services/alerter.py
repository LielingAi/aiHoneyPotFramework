"""告警渠道 — 产品化 P1: 金丝雀触雷/铁证情报/高威胁的实时外推

触发 (任一满足):
  - requests.canary = 1                        (金丝雀被触碰 — 假凭证真的被用了)
  - intel.grade in (consistent, attribution)   (铁证/操作者归因情报入库)
  - threat >= HONEYPOT_ALERT_THRESHOLD (默认 8)

配置 (环境变量):
  HONEYPOT_ALERT_WEBHOOK   webhook URL (未设 = 静默, 不影响主流程)
  HONEYPOT_ALERT_FMT       generic (默认, {text:...}) | dingtalk ({msgtype,text})
  HONEYPOT_ALERT_THRESHOLD 威胁阈值 (默认 8)

去抖: 同 (session_id, path) 60 秒内只告警一次 — 扫描器风暴不会炸渠道。
出口仅 stdlib urllib; 发送失败静默 (告警永远不能打断蜜罐)。
"""

import json
import os
import threading
import time
import urllib.request

_DEDUP: dict = {}
_DEDUP_WINDOW = 60.0
_lock = threading.Lock()

# 产品化 P2: 配置页可调 — 优先级 env > DB 配置 (dashboard 启动/保存时载入) > 默认
CONFIG: dict = {}

TRIGGER_GRADES = ("consistent", "attribution")


def _cfg(env_name: str, key: str, default: str) -> str:
    return os.environ.get(env_name) or CONFIG.get(key) or default


def _webhook() -> str:
    return _cfg("HONEYPOT_ALERT_WEBHOOK", "alert_webhook", "")


def _fmt() -> str:
    return _cfg("HONEYPOT_ALERT_FMT", "alert_fmt", "generic")


def _threshold() -> float:
    try:
        return float(_cfg("HONEYPOT_ALERT_THRESHOLD", "alert_threshold", "8"))
    except ValueError:
        return 8.0


def _deduped(key: str) -> bool:
    now = time.time()
    with _lock:
        for k in [k for k, ts in _DEDUP.items() if now - ts > _DEDUP_WINDOW]:
            _DEDUP.pop(k, None)
        if key in _DEDUP:
            return False
        _DEDUP[key] = now
        return True


def build_text(kind: str, record: dict) -> str:
    if kind == "canary":
        return (f"🚨 金丝雀触雷 [{record.get('run_id','')}] "
                f"{record.get('method','')} {record.get('path','')} "
                f"来自 {record.get('client_ip','?')} — 假凭证真的被使用了")
    if kind == "intel":
        return (f"🚨 铁证情报 [{record.get('grade','')}] "
                f"{record.get('field','')}: {str(record.get('sample',''))[:120]}")
    return (f"⚠️ 高威胁 (threat={record.get('threat',0)}) "
            f"{record.get('method','')} {record.get('path','')} "
            f"来自 {record.get('client_ip','?')} agent={record.get('agent_type','')}")


def maybe_alert(kind: str, record: dict) -> bool:
    """评估并发送。返回是否发出 (去抖后仍失败也返回 False)。"""
    if not _webhook():
        return False
    key = f"{kind}:{record.get('session_id','')}:{record.get('path', record.get('field',''))}"
    if not _deduped(key):
        return False
    text = build_text(kind, record)
    if _fmt() == "dingtalk":
        payload = {"msgtype": "text", "text": {"content": text}}
    else:
        payload = {"text": text, "kind": kind,
                   "ts": time.time(), "record": record}
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        _webhook(), data=body,
        headers={"Content-Type": "application/json"})
    try:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(req, timeout=5) as r:
            return r.status in (200, 204)
    except Exception:
        return False


def check_request(record: dict):
    """requests 类记录: canary 触雷 或 高威胁 → 告警"""
    if record.get("canary"):
        maybe_alert("canary", record)
    try:
        if float(record.get("threat", 0)) >= _threshold():
            maybe_alert("threat", record)
    except (TypeError, ValueError):
        pass


def check_intel(record: dict):
    if record.get("grade") in TRIGGER_GRADES:
        maybe_alert("intel", record)


def status() -> dict:
    return {"webhook": bool(_webhook()), "fmt": _fmt(), "threshold": _threshold()}
