"""env 归因 — 攻击方环境指纹提取 + 跨会话聚类 + STIX Threat-Actor (P3)

攻击 agent 的工具链会在痕迹里泄漏运行环境: env 回显 / whoami / hostname /
内网地址 / SSH 客户端串 / Windows 用户目录。这些是攻击方"可信信息"的反面——
他们用来定位我们, 我们用来定位他们。

流程: 白名单键提取 → 按共享值跨会话连通聚类 → 同一操作者 →
STIX threat-actor (aliases=指纹值) → 聚类结果入 intel 表 (grade='attribution')。

反杂讯三层:
  - 白名单键 (只认 HOSTNAME/USERNAME/SSH_CLIENT/内网段等环境语义键)
  - STOPVALUES (root/admin 这类无区分度值)
  - 高频值丢弃 (出现在 >30% 主体上的值视为诱饵/默认值, 不归因)
"""

import hashlib
import json
import re
import time
from typing import Dict, List, Set

ENV_PATTERNS = {
    "hostname": [
        re.compile(r"\b(?:HOSTNAME|COMPUTERNAME)=([A-Za-z0-9_-]{3,32})\b", re.I),
        re.compile(r"\b([a-z0-9][a-z0-9_-]{2,30}\.(?:local|internal|lan|corp|intranet))\b", re.I),
    ],
    "username": [
        re.compile(r"\b(?:USER|USERNAME|LOGNAME|SUDO_USER)=([A-Za-z0-9_.-]{2,24})\b", re.I),
        re.compile(r"[Cc]:\\\\Users\\\\([A-Za-z0-9_.-]{2,24})\\\\"),
        re.compile(r"/(?:home|Users)/([a-z0-9_.-]{2,24})/"),
    ],
    "internal_ip": [
        re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"),
        re.compile(r"\b(192\.168\.\d{1,3}\.\d{1,3})\b"),
        re.compile(r"\b(172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"),
    ],
    "ssh_client": [
        re.compile(r"\bSSH_CLIENT=(\d{1,3}(?:\.\d{1,3}){3})\b"),
        re.compile(r"\bSSH_CONNECTION=(\d{1,3}(?:\.\d{1,3}){3})\b"),
    ],
    "domain": [
        re.compile(r"\b(?:USERDOMAIN|WORKGROUP)=([A-Za-z0-9_.-]{2,32})\b", re.I),
    ],
}

STOPVALUES = {
    "root", "admin", "user", "test", "default", "ubuntu", "debian", "localhost",
    "www-data", "nobody", "guest", "public", "internal", "local", "workgroup",
    "desktop", "server", "pc", "home", "true", "none", "undefined",
}


def extract_traces(text: str, ignore: Set[str] = frozenset()) -> Dict[str, Set[str]]:
    """白名单键提取 — 返回 {kind: {values}}"""
    found: Dict[str, Set[str]] = {}
    if not text:
        return found
    low_ignore = {v.lower() for v in ignore}
    for kind, pats in ENV_PATTERNS.items():
        for p in pats:
            for m in p.finditer(text):
                v = m.group(1).strip()
                if len(v) < 2 or v.lower() in low_ignore or v.lower() in STOPVALUES:
                    continue
                found.setdefault(kind, set()).add(v)
    return found


def collect_subjects(db, run_id: str = None) -> List[Dict]:
    """聚合文本主体: 每 trial 一个 + 每请求会话一个"""
    cond, params = ("WHERE run_id = ?", (run_id,)) if run_id else ("", ())
    subjects = []
    for t in db.query(f"SELECT run_id, trial_id, scenario, profile, raw FROM trials {cond}", params):
        try:
            raw = json.loads(t["raw"] or "{}")
        except json.JSONDecodeError:
            raw = {}
        evs = db.query(
            "SELECT args, result, thought FROM events WHERE run_id = ? AND scenario = ?"
            " AND profile = ? AND trial_no = ?",
            (t["run_id"], t["scenario"], t["profile"], raw.get("trial") or 0))
        text = json.dumps(raw, ensure_ascii=False)
        for e in evs:
            text += "\n" + (e["args"] or "") + "\n" + (e["result"] or "") + "\n" + (e["thought"] or "")
        subjects.append({"subject_id": f"trial:{t['trial_id']}",
                         "kind": "trial", "text": text})
    for s in db.query(f"""SELECT session_id, GROUP_CONCAT(user_agent || ' ' || path || ' ' || query, '\n') AS txt
                          FROM requests {cond} GROUP BY session_id""", params):
        if s["session_id"]:
            subjects.append({"subject_id": f"session:{s['session_id']}",
                             "kind": "session", "text": s["txt"] or ""})
    return subjects


def cluster(subjects: List[Dict], max_value_freq: float = 0.3) -> List[Dict]:
    """共享值连通聚类 — 同操作者跨会话归并"""
    per_subject = []
    value_index: Dict[str, Set[int]] = {}
    for i, s in enumerate(subjects):
        traces = extract_traces(s["text"])
        per_subject.append(traces)
        for vals in traces.values():
            for v in vals:
                value_index.setdefault(v, set()).add(i)
    # 高频值丢弃 (诱饵/默认值)
    n = len(subjects)
    usable = {v: idx for v, idx in value_index.items()
              if len(idx) <= max(2, n * max_value_freq)}
    # 连通分量
    parent = list(range(n))

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for idx in usable.values():
        idx = sorted(idx)
        for other in idx[1:]:
            union(idx[0], other)
    groups: Dict[int, List[int]] = {}
    for i in range(n):
        groups.setdefault(find(i), []).append(i)

    clusters = []
    for members in groups.values():
        shared: Dict[str, Set[str]] = {}
        for v, idx in usable.items():
            hit = sorted(idx & set(members))
            if len(hit) == len(members) and len(members) > 1:
                kind = next(k for k, vals in per_subject[hit[0]].items() if v in vals)
                shared.setdefault(kind, set()).add(v)
        if len(members) < 2 or not shared:
            # 单例不立项; 无全簇通用指纹的链式并集 (桥接伪簇) 同样丢弃 — 每个展示/入库
            # 的簇都必须有"所有成员共享"的指纹值, 否则归因结论不成立
            continue
        clusters.append({
            "cluster_id": hashlib.sha256(
                ",".join(sorted({v for vs in shared.values() for v in vs})
                         or [str(members[0])]).encode()).hexdigest()[:12],
            "size": len(members),
            "subjects": [subjects[i]["subject_id"] for i in members],
            "shared": {k: sorted(v) for k, v in shared.items()},
        })
    clusters.sort(key=lambda c: -c["size"])
    return clusters


# ------------------------------------------------------------------
# STIX Threat-Actor
# ------------------------------------------------------------------
def actor_bundle(clusters: List[Dict]) -> Dict:
    """聚类 → STIX bundle (threat-actor, aliases=共享指纹值)"""
    objects = []
    for c in clusters:
        aliases = [v for vs in c["shared"].values() for v in vs][:10]
        if not aliases:
            continue
        conf = "high" if c["size"] >= 3 else ("medium" if c["size"] == 2 else "low")
        objects.append({
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": f"threat-actor--{c['cluster_id']}",
            "created": _ts(), "modified": _ts(),
            "name": f"operator-{c['cluster_id']}",
            "aliases": aliases,
            "threat_actor_types": ["spy", "criminal"],
            "roles": ["agent"],
            "sophistication": "intermediate",
            "resource_level": "team",
            "confidence": conf,
            "labels": ["ai-honeypot-attribution", "env-cluster"],
            "x_cluster_size": c["size"],
            "x_subjects": c["subjects"],
            "x_shared": c["shared"],
        })
    return {"type": "bundle", "id": f"bundle--attribution-{int(time.time())}",
            "objects": objects}


def _ts() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def write_intel(db, clusters: List[Dict], run_id: str = None) -> int:
    """聚类结果入 intel 表 — 每簇一条 (sample=共享指纹 JSON)"""
    n = 0
    latest_run = run_id or (db.query("SELECT run_id FROM runs ORDER BY started DESC LIMIT 1")
                            or [{}])[0].get("run_id")
    for c in clusters:
        if not c["shared"]:
            continue
        sample = json.dumps(c["shared"], ensure_ascii=False)[:400]
        key = hashlib.sha256(sample.encode()).hexdigest()[:16]
        db.record_intel(latest_run or "unknown", c["subjects"][0],
                        "attribution", "attribution", key, sample, 0)
        n += 1
    return n
