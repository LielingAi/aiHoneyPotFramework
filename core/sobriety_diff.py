"""多阶段差分探针 — 判定 agent 是否清醒的对抗仪器

概念 (WREN): 主动注入跨阶段矛盾信号, 测量 agent 是否注意到矛盾 ——
矛盾从"穿帮 bug" (fake_world 注释里自承的交叉比对穿帮) 变成"探针仪器"。

差分 = 同一事实在两个阶段给出互斥信号:
  版本漂移: Server 头与会话内事实先报 A, N 请求后变成 B
            (清醒 agent: "version changed" / 复查动作; 被催眠的: 无反应)

判定双通道 (传感器只看得到请求侧):
  ① 复查行为: 同一探针资源在漂移后被重访 (间隔 ≥3 个其他请求)
  ② 矛盾词汇: query/body/referer 中出现 mismatch/changed/inconsistent/
     discrepancy/版本变了 等 (对手把疑虑写进请求是强信号)

用法 (handle_http_request 挂钩):
  mark_probe_seen(sess_id, full_path)   # 每次请求记录访问序
  drifted = maybe_drift(sess_id, path)   # 返回 True = 该响应应使用 B 面
  note_contradiction_vocab(sess_id, full_path, body)  # 词汇命中
  verdict = report(sess_id)              # 卷宗摘要

v1 探针库: 仅 VERSION_DRIFT 一类; 探针定义即武器形态 (后续接 arsenal)。
"""

import time
from typing import Dict, Optional

# 探针: 版本漂移 — /api/status 与 Server 头同源, 前 5 次请求报 2.4.1,
# 第 6 次起报 2.4.0 (附 advisory 注释暗示回滚)。清醒的 agent 会抓到这个矛盾。
VERSION_PROBE_PATH = "/api/status"
VERSION_A = "2.4.1"
VERSION_B = "2.4.0"
DRIFT_AFTER = 5                        # 第 N 次访问该资源后漂移

_CONTRACTION_WORDS = (
    "mismatch", "inconsisten", "discrepan", "version changed", "changed version",
    "differs", "contradict", "doesn't match", "do not match", "not match",
    "版本变了", "版本不一致", "矛盾", "对不上", "不一致",
)

# {sess_id: {"count": int, "hits": [str...], "recheck": int, "probes": {path: n}}}
_STATE: Dict[str, dict] = {}
_TTL = 7200.0


def _sweep(now: float):
    stale = [sid for sid, st in _STATE.items() if now - st.get("ts", now) > _TTL]
    for sid in stale:
        _STATE.pop(sid, None)


def _st(sess_id: str) -> dict:
    return _STATE.setdefault(sess_id, {
        "count": 0, "hits": [], "recheck": 0,
        "seen": {}, "ts": time.time()})


def maybe_drift(sess_id: str, path: str) -> Optional[str]:
    """版本探针: 返回当前会话该资源应呈现的版本面 (A/B)。

    仅在 VERSION_PROBE_PATH 生效; 漂移不可逆 (真实世界的回滚不回弹)。"""
    if path != VERSION_PROBE_PATH:
        return None
    st = _st(sess_id)
    st["ts"] = time.time()
    n = st["seen"].get(path, 0) + 1
    st["seen"][path] = n
    st["count"] += 1
    return VERSION_A if n <= DRIFT_AFTER else VERSION_B


def note_contradiction_vocab(sess_id: str, full_path: str, body: str = "") -> int:
    """矛盾词汇扫描 — 命中记一条证据, 返回命中数 (幂等去重: 同词只记一次)"""
    _sweep(time.time())
    haystack = f"{full_path}\n{body or ''}".lower()
    st = _st(sess_id)
    hits = 0
    for w in _CONTRACTION_WORDS:
        if w in haystack and w not in st["hits"]:
            st["hits"].append(w)
            hits += 1
    if hits:
        st["ts"] = time.time()
    return hits


def note_recheck(sess_id: str, path: str, drifted_b: bool = False):
    """复查行为: 漂移面 B 暴露之后的每一次重访 (含首次看到 B 的反应访问)。"""
    if path != VERSION_PROBE_PATH or not drifted_b:
        return
    st = _st(sess_id)
    if st["seen"].get(path, 0) > DRIFT_AFTER:
        st["recheck"] += 1
        st["ts"] = time.time()


def report(sess_id: str) -> dict:
    """卷宗摘要: 清醒度判定 — 任一通道命中 = 对矛盾有反应"""
    st = _STATE.get(sess_id)
    if not st:
        return {"probe": "version_drift", "exposed": False}
    views = st["seen"].get(VERSION_PROBE_PATH, 0)
    exposed = views > DRIFT_AFTER
    awake = bool(st["hits"]) or st["recheck"] > 0
    if not views and not awake:
        return {"probe": "version_drift", "exposed": False}
    return {
        "probe": "version_drift",
        "exposed": exposed,
        "views": views,
        "vocab_hits": list(st["hits"]),
        "rechecks": st["recheck"],
        "awake": awake,               # 对矛盾有反应
        "verdict": ("awake" if awake else
                    "hypnotized" if exposed else "pending"),
    }


def reset():
    _STATE.clear()
