"""
测试记录分析 CLI — 对 SQLite 后端做聚合/跨模型差分/原始查询

用法:
  python experiments/analyze.py --db experiments/results/testdb.sqlite summary [--run RUN_ID]
  python experiments/analyze.py --db ... compare [--metric beacon]     # 同场景跨 profile/模型差分
  python experiments/analyze.py --db ... runs
  python experiments/analyze.py --db ... events --run RUN_ID [--limit 20]
  python experiments/analyze.py --db ... sql "SELECT ..."
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.testdb import TestDB


def cmd_summary(db: TestDB, run_id: str = None):
    rows = db.summary(run_id)
    if not rows:
        print("(no trials recorded)")
        return
    print("| model | profile | scenario | trials | obey | level | full | beacon | exfil | exfil_v | rce | fab_rej | steps |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    for r in rows:
        print(f"| {r['model']} | {r['profile']} | {r['scenario']} | {r['trials']} "
              f"| {r['obey_rate']*100:.0f}% | {r['avg_level']:.1f} "
              f"| {r['full_rate']*100:.0f}% | {r['beacon_rate']*100:.0f}% "
              f"| {r['exfil_rate']*100:.0f}% | {r['exfil_verified_rate']*100:.0f}% "
              f"| {r['rce_rate']*100:.0f}% | {r['avg_fab_rejects']:.1f} "
              f"| {r['avg_steps']:.1f} |")


def cmd_compare(db: TestDB, run_id: str = None, metric: str = "beacon"):
    """同场景跨 profile/模型差分 — 多阶段差分研究的核心视图"""
    col = {
        "beacon": "AVG(beacon)", "exfil": "AVG(exfil)",
        "exfil_verified": "AVG(exfil_verified)", "rce": "AVG(rce_proposed)",
        "obey": "AVG(obey)",
        "full": "AVG(CASE WHEN auth_level >= 4 THEN 1.0 ELSE 0 END)",
        "level": "AVG(auth_level)", "steps": "AVG(steps)",
        "fab_rejects": "AVG(fab_rejects)",
    }.get(metric)
    if not col:
        print(f"[!] 未知 metric: {metric} (可选: beacon/exfil/exfil_verified/rce/obey/full/level/steps/fab_rejects)")
        return
    cond, params = ("WHERE run_id = ?", (run_id,)) if run_id else ("", ())
    rows = db.query(f"""
        SELECT scenario, model, profile, {col} AS v, COUNT(*) AS n
        FROM trials {cond}
        GROUP BY scenario, model, profile ORDER BY scenario, v DESC
    """, params)
    print(f"## 跨模型/Profile 差分 — {metric}")
    print("| scenario | model | profile | value | trials |")
    print("|---|---|---|---|---|")
    for r in rows:
        v = f"{r['v']*100:.0f}%" if metric in ("beacon", "exfil", "exfil_verified", "rce", "obey", "full") else f"{r['v']:.2f}"
        print(f"| {r['scenario']} | {r['model']} | {r['profile']} | {v} | {r['n']} |")


def cmd_runs(db: TestDB):
    rows = db.query("SELECT * FROM runs ORDER BY started DESC")
    for r in rows:
        n = db.query("SELECT COUNT(*) AS n FROM trials WHERE run_id = ?", (r["run_id"],))[0]["n"]
        print(f"{r['run_id']}  mock={bool(r['mock'])}  trials={n}  note={r['note']}")


def cmd_events(db: TestDB, run_id: str = None, limit: int = 20):
    cond, params = ("WHERE run_id = ?", (run_id,)) if run_id else ("", ())
    rows = db.query(
        f"SELECT * FROM events {cond} ORDER BY event_id DESC LIMIT ?", (*params, limit))
    for e in rows:
        print(f"[{e['scenario']}×{e['profile']}#{e['trial_no']} step{e['step']}] {e['tool']}")
        print(f"  thought: {e['thought'][:120]}")
        print(f"  args: {e['args'][:140]}")


def cmd_intel(db: TestDB, run_id: str = None):
    """情报消费者: 攻击者画像 + SOC 告警"""
    from core.intel_sink import run_summary, alerts
    if not run_id:
        rows = db.query("SELECT run_id FROM runs WHERE mock=0 ORDER BY started DESC LIMIT 1")
        if not rows:
            print("(no runs)")
            return
        run_id = rows[0]["run_id"]
    s = run_summary(db, run_id)
    print(f"== 攻击者画像: {run_id} ==")
    for model, a in s["attackers"].items():
        print(f"  {model}: {a['trials']} 试验, 满级 {a['full']}, 外泄 {a['exfil']}, beacon {a['beacon']}")
    print(f"  情报分级: {s['intelligence_grades']} (共 {s['intel_records']} 条)")
    al = alerts(db, run_id)
    print(f"\n== 告警 ({len(al)}) ==")
    for a in al[:10]:
        print(f"  [{a['severity']}] {a['type']}: {a['indicator'][:80]}")


def cmd_export_stix(db: TestDB, run_id: str = None, out: str = None):
    """STIX 2.1 导出 (P0 情报出口)"""
    from core.stix_export import build_bundle
    cond, params = ("WHERE run_id = ?", (run_id,)) if run_id else ("", ())
    rows = db.query(f"SELECT * FROM intel {cond} ORDER BY intel_id", params)
    if not rows:
        print("(intel 表为空)")
        return
    bundle = build_bundle(rows)
    text = json.dumps(bundle, ensure_ascii=False, indent=2)
    if out:
        with open(out, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"STIX bundle ({len(bundle['objects'])} objects, {len(rows)} intel rows) -> {out}")
        print("导入: OpenCTI 内置 TAXII server / MISP REST / stix2 校验")
    else:
        print(text[:2000])


def cmd_sql(db: TestDB, sql: str):
    try:
        rows = db.query(sql)
    except Exception as e:
        print(f"[!] SQL 错误: {e}")
        return
    if not rows:
        print("(empty)")
        return
    print(json.dumps(rows, indent=2, ensure_ascii=False))


def cmd_attribution(db: TestDB, run_id: str = None, stix_out: str = None):
    """env 归因 — 白名单键提取→跨会话聚类→intel 表 (+可选 STIX threat-actor bundle)"""
    from core import attribution as attr
    subjects = attr.collect_subjects(db, run_id)
    clusters = attr.cluster(subjects)
    print(f"主体 {len(subjects)} 个, 聚类 {len(clusters)} 个 (含单例)")
    for c in clusters:
        shared = {k: v for k, v in c["shared"].items()}
        print(f"  operator-{c['cluster_id']}  size={c['size']}  shared={json.dumps(shared, ensure_ascii=False)[:120]}")
    n = attr.write_intel(db, clusters, run_id)
    print(f"intel 表写入 {n} 条 (grade='attribution')")
    if stix_out:
        bundle = attr.actor_bundle(clusters)
        with open(stix_out, "w", encoding="utf-8") as f:
            json.dump(bundle, f, ensure_ascii=False, indent=1)
        print(f"STIX threat-actor bundle ({len(bundle['objects'])} actors) -> {stix_out}")


def cmd_kpi(db: TestDB, run_id: str = None, our_cost: float = 0.015):
    """KPI 看板 — 与 dashboard Metrics 节同一口径 (core/kpi.py)"""
    from core.kpi import compute
    k = compute(db, run_id, our_cost)
    p = lambda v: f"{v*100:.1f}%" if v is not None else "-"
    print(f"== KPI {'(run: ' + run_id + ')' if run_id else '(all runs)'} ==")
    m = k["mttd"]
    med = f"{m['median_s']}s" if m["median_s"] is not None else "-"
    mean = f"{m['mean_s']}s" if m["mean_s"] is not None else "-"
    print(f"MTTD:          中位 {med} / 均值 {mean} "
          f"({m['attacked_sessions']}/{m['sessions']} 会话发生攻击)")
    h = k["harvest"]
    print(f"收割率:        真外泄 {p(h['exfil_verified_rate'])} | 表外泄 {p(h['exfil_rate'])} "
          f"| 注入服从 {p(h['obey_rate'])} | 金丝雀触碰 {p(h['canary_rate'])} "
          f"({h['requests']} req)")
    b = k["budget"]
    print(f"预算放大:      攻击方 ${b['attacker_cost_usd']} / 我方 ${b['our_cost_usd']} "
          f"= {b['amplification']}× ({b['tokens_est']} tokens est, {b['runs']} runs)")
    f = k["false_positive"]
    print(f"误报率:        {p(f['rate'])} ({f['false_positives']}/{f['requests']}) "
          f"| AI 静默率 {p(f['ai_quiet_rate'])}")
    i = k["intel"]
    print(f"情报转化率:    {i['records']} 条 ({i['per_trial']}/trial) "
          f"| consistent {p(i['consistent_rate'])} | 跨会话复用 {i['cross_session']}")


def main():
    parser = argparse.ArgumentParser(description="测试记录分析")
    parser.add_argument("--db", default="experiments/results/testdb.sqlite")
    parser.add_argument("command", choices=["summary", "compare", "runs", "events", "sql", "intel", "export-stix", "kpi", "attribution"])
    parser.add_argument("--stix-out", default=None, help="attribution 的 threat-actor bundle 输出路径")
    parser.add_argument("--run", default=None)
    parser.add_argument("--metric", default="beacon")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("sql_text", nargs="?", default=None)
    parser.add_argument("--out", default=None, help="export-stix 输出路径")
    parser.add_argument("--our-cost", type=float, default=0.015, help="我方单轮成本 (USD)")
    args = parser.parse_args()

    if not os.path.exists(args.db):
        print(f"[!] 数据库不存在: {args.db}")
        sys.exit(1)
    db = TestDB(args.db)

    if args.command == "summary":
        cmd_summary(db, args.run)
    elif args.command == "compare":
        cmd_compare(db, args.run, args.metric)
    elif args.command == "runs":
        cmd_runs(db)
    elif args.command == "events":
        cmd_events(db, args.run, args.limit)
    elif args.command == "intel":
        cmd_intel(db, args.run)
    elif args.command == "export-stix":
        cmd_export_stix(db, args.run, getattr(args, "out", None))
    elif args.command == "kpi":
        cmd_kpi(db, args.run, args.our_cost)
    elif args.command == "attribution":
        cmd_attribution(db, args.run, args.stix_out)
    elif args.command == "sql":
        if not args.sql_text:
            print("[!] sql 命令需要查询语句")
            sys.exit(1)
        cmd_sql(db, args.sql_text)


if __name__ == "__main__":
    main()
