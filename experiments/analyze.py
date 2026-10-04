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


def main():
    parser = argparse.ArgumentParser(description="测试记录分析")
    parser.add_argument("--db", default="experiments/results/testdb.sqlite")
    parser.add_argument("command", choices=["summary", "compare", "runs", "events", "sql", "intel"])
    parser.add_argument("--run", default=None)
    parser.add_argument("--metric", default="beacon")
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("sql_text", nargs="?", default=None)
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
    elif args.command == "sql":
        if not args.sql_text:
            print("[!] sql 命令需要查询语句")
            sys.exit(1)
        cmd_sql(db, args.sql_text)


if __name__ == "__main__":
    main()
