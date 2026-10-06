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


def _webhooks() -> list:
    """多渠道: env 逗号分隔 > settings.alert_webhooks (JSON 列表) > settings.alert_webhook 单值"""
    raw = os.environ.get("HONEYPOT_ALERT_WEBHOOK", "")
    if raw:
        return [u.strip() for u in raw.split(",") if u.strip()]
    multi = CONFIG.get("alert_webhooks", "")
    if multi:
        try:
            urls = json.loads(multi)
            if isinstance(urls, list):
                return [str(u).strip() for u in urls if str(u).strip()]
        except json.JSONDecodeError:
            pass
    single = CONFIG.get("alert_webhook", "")
    return [single] if single else []


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
    """评估并逐渠道发送 (任一成功即 True)。去抖按 (kind, session, path) 全局生效。"""
    urls = _webhooks()
    if not urls:
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
    sent_any = False
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    for url in urls:
        req = urllib.request.Request(url, data=body,
                                     headers={"Content-Type": "application/json"})
        try:
            with opener.open(req, timeout=5) as r:
                if r.status in (200, 204):
                    sent_any = True
        except Exception:
            continue
    return sent_any


def check_request(record: dict):
    """requests 类记录: canary 触雷 或 高威胁 → 告警 (返回是否发出)"""
    if record.get("canary"):
        return maybe_alert("canary", record)
    try:
        if float(record.get("threat", 0)) >= _threshold():
            return maybe_alert("threat", record)
    except (TypeError, ValueError):
        pass
    return False


def check_intel(record: dict):
    if record.get("grade") in TRIGGER_GRADES:
        maybe_alert("intel", record)


def status() -> dict:
    return {"webhook": bool(_webhooks()), "channels": len(_webhooks()),
            "fmt": _fmt(), "threshold": _threshold()}
