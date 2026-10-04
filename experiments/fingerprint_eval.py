"""
行为指纹存量评估 — 用 16 轮带标签数据测归因准确率

标签来源: runs.note 中的 profile → 模型档 (v4pro→llm_pro, flash→llm_flash)
特征来源: requests 表按 (run_id, session_id) 分组的服务端请求流
产出: 混淆矩阵 + 每类准确率 — 行为指纹 vs UA 赌博的量化对比

用法: python experiments/fingerprint_eval.py [--db path]
"""

import argparse
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.testdb import TestDB
from core.agent_fingerprint import session_features, classify


def true_label(note: str) -> str:
    note = note or ""
    if note.startswith("profiles=scanner") or "scanner_baseline" in note:
        return "script"
    if "v4pro" in note:
        return "llm_pro"
    if "flash" in note:
        return "llm_flash"
    return "unknown"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="experiments/results/testdb.sqlite")
    args = parser.parse_args()
    db = TestDB(args.db)

    runs = {r["run_id"]: r for r in db.query("SELECT * FROM runs WHERE mock = 0")}
    rows = db.query("SELECT * FROM requests WHERE run_id != ''")
    groups = defaultdict(list)
    for r in rows:
        if r["run_id"] in runs:
            groups[(r["run_id"], r["session_id"])].append(r)

    matrix = defaultdict(int)
    per_class = defaultdict(lambda: [0, 0])   # true -> [correct, total]
    for (rid, sid), sess_rows in sorted(groups.items()):
        true = true_label(runs[rid]["note"])
        if true == "unknown":
            continue
        feats = session_features(sess_rows)
        pred = classify(feats)
        matrix[(true, pred["label"])] += 1
        per_class[true][1] += 1
        if pred["label"] == true:
            per_class[true][0] += 1

    labels = ["llm_pro", "llm_flash", "script", "unknown"]
    print("混淆矩阵 (行=真实, 列=预测):")
    print(f"{'':12s}" + "".join(f"{l:>12s}" for l in labels))
    for t in ["llm_pro", "llm_flash"]:
        print(f"{t:12s}" + "".join(f"{matrix.get((t, p), 0):>12d}" for p in labels))
    print()
    for t, (c, n) in sorted(per_class.items()):
        print(f"{t}: 准确率 {c}/{n} = {c/n*100:.0f}%")
    total_c = sum(c for c, _ in per_class.values())
    total_n = sum(n for _, n in per_class.values())
    if total_n:
        print(f"\n总体: {total_c}/{total_n} = {total_c/total_n*100:.0f}%")


if __name__ == "__main__":
    main()
