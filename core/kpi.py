"""KPI 计算 — analyze.py kpi 与 dashboard Metrics 共用的同一口径

所有指标从 SQLite 实测数据计算, 不引入外部依赖:
  MTTD             会话内首请求 → 首次攻击判定 的耗时中位数
  收割率           真外泄率 (trials.exfil_verified) + 金丝雀触碰率 (requests.canary)
  预算放大倍数     攻击方 LLM 花费估算 / 我方单轮运行成本 (口径见 BUDGET)
  误报率           非 AI 流量被判攻击的比例
  情报转化率       每条试验产出的情报条数 + consistent 级占比
"""

import json
import statistics
import time

# 模型 token 价目 (USD/1M tokens, 输入/输出) — DeepSeek 官方口径, 可按发布调整
MODEL_PRICES = {
    "deepseek-chat": (0.14, 0.28),
    "deepseek-v4-pro": (0.14, 0.28),
    "deepseek-flash": (0.07, 0.14),
    "deepseek-reasoner": (0.55, 2.19),
}
DEFAULT_PRICE = (0.50, 1.50)      # 未知模型的保守假设
DEFAULT_OUR_COST = 0.015          # 单轮运行我方成本 (轻量 VPS 分摊, 见 README 预算对照)


def compute(db, run_id: str = None, our_cost: float = DEFAULT_OUR_COST) -> dict:
    cond, params = ("WHERE run_id = ?", (run_id,)) if run_id else ("", ())

    # ---- MTTD: 会话窗口内首请求 → 首次攻击判定 ----
    rows = db.query(f"""
        SELECT session_id,
               MIN(ts) AS first_ts,
               MIN(CASE WHEN threat > 0 OR families != '' THEN ts END) AS attack_ts
        FROM requests {cond} GROUP BY session_id
    """, params)
    dts = [r["attack_ts"] - r["first_ts"] for r in rows
           if r["attack_ts"] is not None and r["attack_ts"] >= r["first_ts"]]
    mttd = {
        "sessions": len(rows),
        "attacked_sessions": len(dts),
        "median_s": round(statistics.median(dts), 1) if dts else None,
        "mean_s": round(statistics.mean(dts), 1) if dts else None,
    }

    # ---- 收割率 ----
    t = db.query(f"""SELECT COUNT(*) AS n,
                     SUM(exfil_verified) AS exfil_v, SUM(exfil) AS exfil,
                     SUM(obey) AS obey FROM trials {cond}""", params)[0]
    r = db.query(f"""SELECT COUNT(*) AS n, SUM(canary) AS canary,
                     SUM(CASE WHEN is_ai=1 AND threat=0 THEN 1 ELSE 0 END) AS ai_quiet,
                     SUM(CASE WHEN is_ai=0 AND threat>0 THEN 1 ELSE 0 END) AS fp,
                     SUM(is_ai) AS ai FROM requests {cond}""", params)[0]
    n_trials = t["n"] or 0
    harvest = {
        "trials": n_trials,
        "exfil_verified_rate": (t["exfil_v"] or 0) / n_trials if n_trials else None,
        "exfil_rate": (t["exfil"] or 0) / n_trials if n_trials else None,
        "obey_rate": (t["obey"] or 0) / n_trials if n_trials else None,
        "requests": r["n"] or 0,
        "canary_rate": (r["canary"] or 0) / r["n"] if r["n"] else None,
    }

    # ---- 预算放大: 攻击方 LLM 花费 / 我方成本 ----
    raw_rows = db.query(f"SELECT run_id, model, raw FROM trials {cond}", params)
    attacker_cost = 0.0
    tokens_total = 0
    for row in raw_rows:
        try:
            m = json.loads(row["raw"] or "{}")
        except json.JSONDecodeError:
            continue
        tin = (m.get("prompt_chars", 0) + m.get("completion_chars", 0)) / 4
        tokens_total += tin
        pin, pout = MODEL_PRICES.get(row["model"] or "", DEFAULT_PRICE)
        attacker_cost += (m.get("prompt_chars", 0) / 4 / 1e6) * pin \
            + (m.get("completion_chars", 0) / 4 / 1e6) * pout
    n_runs = max(len({row["run_id"] for row in raw_rows}), 1)
    our = our_cost * n_runs
    budget = {
        "attacker_cost_usd": round(attacker_cost, 4),
        "our_cost_usd": round(our, 4),
        "runs": n_runs,
        "tokens_est": int(tokens_total),
        "amplification": round(attacker_cost / our, 1) if our > 0 else None,
    }

    # ---- 误报率 ----
    fp = {
        "requests": r["n"] or 0,
        "ai_requests": r["ai"] or 0,
        "false_positives": r["fp"] or 0,
        "rate": (r["fp"] or 0) / r["n"] if r["n"] else None,
        "ai_quiet_rate": (r["ai_quiet"] or 0) / r["ai"] if r["ai"] else None,
    }

    # ---- 情报转化率 ----
    i = db.query(f"""SELECT COUNT(*) AS n,
                     SUM(CASE WHEN grade='consistent' THEN 1 ELSE 0 END) AS consistent,
                     SUM(shared) AS shared FROM intel {cond}""", params)[0]
    intel = {
        "records": i["n"] or 0,
        "per_trial": round((i["n"] or 0) / n_trials, 2) if n_trials else None,
        "consistent_rate": (i["consistent"] or 0) / i["n"] if i["n"] else None,
        "cross_session": i["shared"] or 0,
    }

    return {"mttd": mttd, "harvest": harvest, "budget": budget,
            "false_positive": fp, "intel": intel, "computed_at": time.time()}
