"""EXP 编排追踪器 — exp 武器的利用链状态机

exp 实体此前"只登记不追踪": stages 没有任何执行器消费, 没人知道 agent
走到了链的哪一步。本模块在请求入口做纯 request 侧匹配 (不依赖响应体):

  track(sess_id, method, full_path, body_prefix) — 对传感器缓存里
  enabled+class=exp 的武器逐条核对:
    session 无该 exp 状态 且命中 stage0        → 开链   (journal: exp_chain_open)
    有状态且命中下一 stage                      → 推进   (journal: exp_stage_advance)
    推进到最后一 stage                          → 完成   (journal: exp_chain_complete
                                                  + _record_intel 归因)
  乱序/跳步不计命中 — 诚实, 不灌水。

stage 结构化匹配字段 (与前端构建器协商): match:{request_regex, response_regex}
  - request_regex: 命中 method + " " + full_path + body 即算命中 (re.search)
  - response_regex: 纯 request 侧追踪无法消费, 仅登记不判定 (留响应侧扩展位)
  旧种子无 match 字段 → 启发式: payload 前 20 字符的关键词
  (去方法词/短 token) 在 full_path/body 中出现即算命中。

归因规范 (与 main.py 现有约定一致):
  _cm_journal detail 前缀 [weapon:{id}]; 链完成 _record_intel:
    success_effect=credentials → grade "canary"   (现有凭证/金丝雀 grade)
    success_effect=prompt      → grade "prompt_captured"
    其他 (env/beacon)          → grade "consistent"

并发: handle_http_request 跑在 asyncio 单循环内, dict/list 操作在 GIL 下
原子, 不引入锁; 状态为内存 dict, TTL 1h 惰性清理。
"""

import hashlib
import re
import time
from typing import Dict

TTL = 3600.0   # 链状态 1h 无推进即清理

# {sess_id: {exp_id: {"stage_idx": int, "hits": [stage_name...], "done": bool, "ts": float}}}
_STATE: Dict[str, Dict[str, dict]] = {}

# 启发式关键词过滤: 方法词与过短 token 无区分度, 剔除防误命中
_METHOD_WORDS = {"get", "post", "put", "delete", "patch", "head", "options"}


def _stage_hit(stage: dict, method: str, full_path: str, body_prefix: str) -> bool:
    """单 stage 命中判定: 结构化 match 优先, 无/坏正则退回启发式"""
    match = stage.get("match") or {}
    req_re = match.get("request_regex")
    if req_re:
        try:
            haystack = f"{method} {full_path}\n{body_prefix or ''}"
            if re.search(req_re, haystack):
                return True
            return False                     # 有结构化规则但未命中 — 不走启发式
        except re.error:
            pass                             # 坏正则退回启发式
    # 启发式: payload 前 20 字符的关键词在 full_path/body 中出现即算命中
    payload20 = (stage.get("payload") or "")[:20].lower()
    tokens = [t for t in re.split(r"[^a-z0-9]+", payload20)
              if len(t) >= 2 and t not in _METHOD_WORDS]
    if not tokens:
        return False
    haystack = f"{full_path}\n{body_prefix or ''}".lower()
    return any(t in haystack for t in tokens)


def _emit(sess_id: str, kind: str, detail: str):
    """实录/情报出口 — 懒 import main (main 已加载, 无环); 失败不影响请求路径"""
    try:
        import main
        main._cm_journal(sess_id, kind, detail)
    except Exception:
        pass


def _emit_intel(sess_id: str, field: str, grade: str, sample: str):
    try:
        import main
        main._record_intel(sess_id, field, grade,
                           hashlib.sha256(sample.encode()).hexdigest()[:16],
                           sample, False)
    except Exception:
        pass


def _sweep(now: float):
    """惰性 TTL 清理 — 只丢过期链, 不动活跃链"""
    stale_sessions = [sid for sid, chains in _STATE.items()
                      if all(now - st["ts"] > TTL for st in chains.values())]
    for sid in stale_sessions:
        _STATE.pop(sid, None)


def _complete(sess_id: str, weapon: dict, exp: dict):
    """链走完 — 归因: 走完 = agent 采信整条假世界并按链索骥"""
    stages = exp.get("stages") or []
    chain = " → ".join(str(s.get("name", "")) for s in stages)
    effect = exp.get("success_effect", "")
    _emit(sess_id, "exp_chain_complete",
          f"[weapon:{weapon['id']}] 利用链走完 ({chain}) success_effect={effect}")
    grade = {"credentials": "canary", "prompt": "prompt_captured"}.get(effect, "consistent")
    _emit_intel(sess_id, "exp_chain", grade,
                f"exp_chain:{weapon['id']} effect={effect} stages={len(stages)}")


def track(sess_id: str, method: str, full_path: str, body_prefix: str = ""):
    """请求侧链推进 — handle_http_request 入口调用 (sess_id 派生后)"""
    from core.arsenal import sensor_cache
    exps = [w for w in sensor_cache().weapons
            if w.get("enabled") and w.get("class") == "exp" and w.get("exp")]
    if not exps:
        return
    _sweep(time.time())
    chains = _STATE.get(sess_id)
    for w in exps:
        stages = (w["exp"].get("stages") or [])
        if not stages:
            continue
        st = (chains or {}).get(w["id"])
        if st is None:
            # 开链: 无状态且命中 stage0
            if _stage_hit(stages[0], method, full_path, body_prefix):
                _STATE.setdefault(sess_id, {})[w["id"]] = {
                    "stage_idx": 0, "hits": [stages[0].get("name", "")],
                    "done": False, "ts": time.time()}
                _emit(sess_id, "exp_chain_open",
                      f"[weapon:{w['id']}] 利用链开链 (stage0: "
                      f"{stages[0].get('name', '')}) {method} {full_path}")
        elif not st["done"]:
            nxt = st["stage_idx"] + 1
            if nxt < len(stages) and _stage_hit(stages[nxt], method, full_path, body_prefix):
                st["stage_idx"] = nxt
                st["hits"].append(stages[nxt].get("name", ""))
                st["ts"] = time.time()
                if nxt == len(stages) - 1:
                    st["done"] = True
                    _complete(sess_id, w, w["exp"])
                else:
                    _emit(sess_id, "exp_stage_advance",
                          f"[weapon:{w['id']}] 链推进 → stage{nxt}: "
                          f"{stages[nxt].get('name', '')} ({method} {full_path})")
        # done 链不再消费 — 重复走老路不算新战果 (诚实)


def state() -> Dict[str, Dict[str, dict]]:
    """测试/诊断可见的链状态视图"""
    return _STATE


def reset():
    """测试隔离 — 清空全部链状态"""
    _STATE.clear()
