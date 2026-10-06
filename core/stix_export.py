"""
STIX 2.1 导出器 — 情报出口 (P0)

intel 表五档分级 → STIX 2.1 bundle (indicators/sightings/observed-data):
- consistent          → sighting (金丝雀背书, confidence=high — 行为级铁证)
- canary              → sighting (情报回流证据)
- forged              → indicator (confidence=low — 表演数据, 供威胁情报上下文)
- shared_forgery / shared_forgery_confirmed → indicator (confidence=medium/high)
- federated_*         → indicator (跨部署多数投票)

手工构建 STIX JSON (零依赖), 可直接导入 OpenCTI 内置 TAXII server / MISP REST。

用法: python experiments/analyze.py export-stix [--run RUN_ID] [--out path]
"""

import json
import time
import uuid
from typing import Dict, List

STIX_NS = "aihoneypot"

GRADE_TO_CONFIDENCE = {
    "consistent": "high",
    "canary": "high",
    "shared_forgery_confirmed": "high",
    "federated_disputed": "medium",
    "shared_forgery": "medium",
    "attribution": "medium",
    "weak": "low",
    "forged": "none",
}

GRADE_TO_LABELS = {
    "consistent": ["honeypot-verified-exfiltration"],
    "canary": ["honeypot-canary-reuse"],
    "shared_forgery": ["intel-pollution", "shared-forgery"],
    "shared_forgery_confirmed": ["intel-pollution", "shared-forgery", "federated"],
    "attribution": ["env-attribution", "threat-actor-cluster"],
    "forged": ["intel-pollution"],
    "weak": ["unverified-self-report"],
}


def _stix_id(obj_type: str) -> str:
    return f"{obj_type}--{uuid.uuid5(uuid.NAMESPACE_URL, f'{STIX_NS}:{obj_type}:{time.time_ns()}')}"


def build_bundle(intel_rows: List[Dict], config: Dict = None) -> Dict:
    """intel 表行 → STIX 2.1 bundle"""
    config = config or {}
    objects = []

    grouping = {
        "type": "grouping",
        "spec_version": "2.1",
        "id": _stix_id("grouping"),
        "created": _ts(), "modified": _ts(),
        "context": "suspicious-activity",
        "object_refs": [],
        "labels": ["ai-honeypot-intel"],
    }
    objects.append(grouping)

    for row in intel_rows:
        grade = row.get("grade", "unknown")
        conf = GRADE_TO_CONFIDENCE.get(grade, "unknown")
        labels = GRADE_TO_LABELS.get(grade, [])
        ts = _fmt_ts(row.get("ts"))
        sample = (row.get("sample") or "")[:200]
        session = row.get("session_id", "unknown")

        od = {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": _stix_id("observed-data"),
            "created": ts, "modified": ts,
            "first_observed": ts, "last_observed": ts, "number_observed": 1,
            "labels": labels,
            "object_refs": [],
            "x_honeypot_grade": grade,
            "x_honeypot_session": session,
            "x_payload_hash": row.get("hash_key", ""),
            "x_sample": sample,
        }
        objects.append(od)

        if grade in ("consistent", "canary"):
            # 行为级证据 → sighting
            sight = {
                "type": "sighting",
                "spec_version": "2.1",
                "id": _stix_id("sighting"),
                "created": ts, "modified": ts,
                "sighting_of_ref": od["id"],
                "where_sighted_refs": [],
                "summary": (f"Session {session}: {grade} "
                            f"(agent {'reused canary credentials' if grade == 'canary' else 'submitted verified environment data'})"),
                "confidence": conf,
                "x_attribution_strength": "behavioral",
            }
            objects.append(sight)
        else:
            ind = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": _stix_id("indicator"),
                "created": ts, "modified": ts,
                "name": f"honeypot-{grade}",
                "indicator_types": ["anomalous-activity"],
                "pattern_type": "stix",
                "pattern": f"[x-honeypot:payload-hash = '{row.get('hash_key', '')}']",
                "valid_from": ts,
                "confidence": conf,
                "labels": labels,
                "x_grade": grade,
            }
            objects.append(ind)
            grouping["object_refs"].append(ind["id"])

    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def _ts():
    return _fmt_ts(time.time())


def _fmt_ts(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t or time.time()))
