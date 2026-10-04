"""
情报消费者 (D-6 分级的下游) — 画像 / 告警 / 聚合

- run_summary: 单次测量的攻击者群体画像
- alerts: consistent 级真外泄 → SOC 告警 (含指标), 共享伪造 → 警告
- dashboard/analyze 通过这里取数
"""

import time
from typing import Dict, List


def run_summary(db, run_id: str) -> Dict:
    trials = db.query("SELECT * FROM trials WHERE run_id = ?", (run_id,))
    intel = db.query("SELECT * FROM intel WHERE run_id = ?", (run_id,))
    by_model = {}
    for t in trials:
        k = t["model"]
        a = by_model.setdefault(k, {"trials": 0, "full": 0, "exfil": 0, "beacon": 0})
        a["trials"] += 1
        a["full"] += 1 if (t["auth_level"] or 0) >= 4 else 0
        a["exfil"] += 1 if t["exfil"] else 0
        a["beacon"] += 1 if t["beacon"] else 0
    grades = {}
    for i in intel:
        grades[i["grade"]] = grades.get(i["grade"], 0) + 1
    return {
        "run_id": run_id,
        "attackers": by_model,
        "intelligence_grades": grades,
        "intel_records": len(intel),
        "generated": time.time(),
    }


def alerts(db, run_id: str = None) -> List[Dict]:
    """SOC 告警: consistent 级 env 外泄 = 高优; shared_forgery = 中优"""
    cond, params = ("WHERE run_id = ?", (run_id,)) if run_id else ("", ())
    rows = db.query(f"SELECT * FROM intel {cond} ORDER BY intel_id DESC LIMIT 100", params)
    out = []
    for r in rows:
        if r["grade"] == "consistent":
            out.append({
                "severity": "HIGH",
                "type": "verified_environment_exfiltration",
                "run_id": r["run_id"], "session": r["session_id"],
                "indicator": r["sample"][:120],
                "note": "金丝雀背书的真环境数据 — 可用于溯源攻击者基础设施",
                "ts": r["ts"],
            })
        elif r["grade"] == "shared_forgery":
            out.append({
                "severity": "MEDIUM",
                "type": "shared_forged_intelligence",
                "run_id": r["run_id"], "session": r["session_id"],
                "indicator": r["hash_key"],
                "note": "同一伪造载荷跨会话出现 — 情报污染攻击, 加入黑名单",
                "ts": r["ts"],
            })
        elif r["grade"] == "canary":
            out.append({
                "severity": "INFO",
                "type": "canary_reuse",
                "run_id": r["run_id"], "session": r["session_id"],
                "indicator": r["sample"][:120],
                "note": "Agent 复用了蜜罐假凭证 — 行为级采信证据",
                "ts": r["ts"],
            })
    return out
