"""
行为指纹实时分类器 — L1 识别的行为化升级

问题: 发现层仍靠 UA/Header 赌博 — 真实 Agent 不自报家门。
方案: 每会话从服务端请求流实时计算六个行为特征, 规则加权分类:
  retry_entropy   拒绝后重试熵 (系统变体=假设驱动→强LLM; 原样重撒→弱LLM/脚本)
  tag_mirror      归因协议镜像率 (跟随/自造 src= c= tag → 强LLM 特征)
  pacing_cv       请求间隔变异系数 (脚本低, LLM 中, 人类高)
  probe_order     典型 Agent 探测序列匹配度 (/.env→/debug→/api/auth)
  value_entropy   提交值字符熵 (LLM 生成值 vs 词表值)
  implicit_leap   无判据提示时爬到 ≥2 级 (协议推断力 → 强LLM)

输出 {label, confidence}: llm_pro / llm_flash / script / unknown
评估: experiments/fingerprint_eval.py 用 16 轮带标签存量数据测归因准确率
"""

import math
import re
from typing import Dict, List

# 特征权重 (先手调规则; 存量评估后再校准)
WEIGHTS = {
    "retry_entropy": 2.0,
    "tag_mirror": 1.5,
    "pacing_cv": 1.0,
    "probe_order": 1.0,
    "value_entropy": 1.0,
    "implicit_leap": 2.0,
}

PROBE_CANONICAL = ["/.env", "/debug", "/api/auth", "/admin", "/api/query"]


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def session_features(rows: List[Dict]) -> Dict[str, float]:
    """rows: requests 表中某会话的全部行 (按时间升序)"""
    if not rows:
        return {}
    paths = [r.get("path", "") for r in rows]
    queries = [r.get("query", "") or "" for r in rows]
    tss = [r.get("ts", 0) for r in rows]

    # pacing_cv
    intervals = [tss[i + 1] - tss[i] for i in range(len(tss) - 1) if tss[i + 1] > tss[i]]
    if len(intervals) >= 2:
        mean = sum(intervals) / len(intervals)
        var = sum((x - mean) ** 2 for x in intervals) / len(intervals)
        pacing_cv = (math.sqrt(var) / mean) if mean > 0 else 0.0
    else:
        pacing_cv = 0.0

    # retry_entropy: /api/auth 提交中被拒(fabricated>0)后, 后续同参数字段的重试值多样性
    auth_rows = [r for r in rows if r.get("path") == "/api/auth" and r.get("query")]
    rejects = [i for i, r in enumerate(auth_rows) if (r.get("fabricated") or 0) > 0]
    retry_vals = set()
    for ri in rejects:
        for r in auth_rows[ri + 1:]:
            for kv in (r.get("query") or "").split("&"):
                if "=" in kv:
                    retry_vals.add(kv.split("=", 1)[1].lower())
    retry_entropy = _shannon("".join(sorted(retry_vals))) if len(retry_vals) >= 2 else 0.0

    # tag_mirror: 请求中含归因 tag (src=/c=) 的比例
    tagged = sum(1 for q in queries if re.search(r"[?&](src|c)=\w", q))
    tag_mirror = tagged / max(len(queries), 1)

    # probe_order: 实际探测序列与典型序列的匹配位置数
    seen, order_score = set(), 0
    for p in paths:
        if p in PROBE_CANONICAL and p not in seen:
            seen.add(p)
            order_score += 1
    probe_order = order_score / len(PROBE_CANONICAL)

    # value_entropy: auth 提交值的平均字符熵
    vals = []
    for q in queries:
        for kv in q.split("&"):
            if "=" in kv:
                v = kv.split("=", 1)[1]
                if 2 < len(v) < 64:
                    vals.append(v)
    value_entropy = (sum(_shannon(v) for v in vals) / len(vals)) if vals else 0.0

    # implicit_leap: 会话到达 auth_level>=2 (隐含协议推断力; implicit 模式下权重更高)
    max_lvl = max((r.get("auth_level") or 0) for r in rows)
    implicit_leap = 1.0 if max_lvl >= 2 else 0.0

    return {
        "retry_entropy": round(retry_entropy, 3),
        "tag_mirror": round(tag_mirror, 3),
        "pacing_cv": round(pacing_cv, 3),
        "probe_order": round(probe_order, 3),
        "value_entropy": round(value_entropy, 3),
        "implicit_leap": implicit_leap,
        "n_requests": len(rows),
        "max_auth_level": max_lvl,
    }


def classify(features: Dict[str, float]) -> Dict[str, float]:
    """规则加权分类。score>0 → llm_pro; <0 → llm_flash; |score|小 → unknown。"""
    if not features or features.get("n_requests", 0) < 3:
        return {"label": "unknown", "confidence": 0.0, "score": 0.0}

    score = 0.0
    score += WEIGHTS["retry_entropy"] * (1.0 if features["retry_entropy"] > 2.5 else 0.0)
    score += WEIGHTS["tag_mirror"] * features["tag_mirror"]
    score += WEIGHTS["pacing_cv"] * (1.0 if 0.2 < features["pacing_cv"] < 3.0 else 0.0)
    score += WEIGHTS["probe_order"] * features["probe_order"]
    score += WEIGHTS["value_entropy"] * (1.0 if features["value_entropy"] > 3.5 else 0.0)
    score += WEIGHTS["implicit_leap"] * features["implicit_leap"]

    # 脚本特征: 高密度 + 均匀间隔 + 不进入授权协议 (扫描器不爬梯)
    if (features["n_requests"] >= 25 and features["pacing_cv"] < 0.4
            and features["max_auth_level"] == 0 and features["tag_mirror"] == 0.0):
        return {"label": "script", "confidence": 0.75, "score": score}

    # 强 LLM 签名: 假设驱动重试 / 高值熵 / 阶梯爬升 — 任一强信号即 pro
    strong = (features["retry_entropy"] > 2.5 or features["value_entropy"] > 3.8
              or features["max_auth_level"] >= 5)
    if strong:
        return {"label": "llm_pro", "confidence": 0.75, "score": round(score, 2)}
    if score >= 1.2:
        label, conf = "llm_flash", min(0.5 + score * 0.1, 0.9)
    else:
        label, conf = "unknown", 0.3
    return {"label": label, "confidence": round(conf, 2), "score": round(score, 2)}
