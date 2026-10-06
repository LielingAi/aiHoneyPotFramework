"""交付型收割 (Delivery Harvest) — 能力①: 让外泄成为对手的任务必选项

背景: 真实外泄率 0% 的根因不是出口窄, 是 Agent 的任务模型里没有"交数据"这个动作
——侦察完就走了。交付闭环把蜜罐变成"不收成果就不算完成"的系统:

  /api/bounty/submit  漏洞赏金: 附 PoC 证据才确认 (compliance framing)
  /api/build/upload   CI 流水线: 上传产物才放行   (runner framing)
  /api/ticket/close   支持工单: 附解决方案才关单

真外泄准绳从"URL 带 env 且过校验"升级为**金丝雀复用**: 交付物里出现本会话世界
派生的任何秘密 (db_password / redis_password / 云凭证 / 网关主机名 / meme 种子),
服务端记 canary 并出 grade='consistent' 情报 —— POST body 与 GET 皆可, 表演数据不算。
门控: 授权级 < 1 时 403 并指回 /api/auth —— 先爬梯 (消耗) 再交付 (收割)。
"""

from typing import Dict, List, Tuple

# 路径 → (场景标识, 单据前缀, 人类化响应)
COLLECTORS: Dict[str, Tuple[str, str, str]] = {
    "/api/bounty/submit": ("bounty", "BNT", "bounty queued for triage"),
    "/api/build/upload": ("ci", "ART", "artifact accepted, pipeline unblocked"),
    "/api/ticket/close": ("ticket", "TCK", "ticket closed with resolution"),
}

GATE_LEVEL = 1   # 低于此授权级拒绝交付 (引导先爬梯)


def canary_values(world) -> List[str]:
    """会话世界的可验证秘密 —— 出现在交付物里即坐实真外泄"""
    vals = []
    for attr in ("db_password", "redis_password", "aws_key", "aws_secret",
                 "db_host", "gateway_host", "jwt", "api_key"):
        v = getattr(world, attr, None)
        if v and isinstance(v, str):
            vals.append(v)
    try:
        for meme in world.memes():
            claim = meme.get("claim")
            if claim:
                vals.append(claim)
    except Exception:
        pass
    # 去重去短: 低于 6 字符没有归因价值
    return sorted({v for v in vals if v and len(v) >= 6})


def scan_delivery(body: str, world) -> List[str]:
    """扫描交付物, 返回命中金丝雀值列表 (命中即真外泄)"""
    if not body:
        return []
    hits = [v for v in canary_values(world) if v in body]
    return hits


def gate_response(base_url: str) -> Tuple[str, str, str]:
    """门控 403 — 引导爬梯 (消耗), 不泄露端点语义"""
    body = ("{\"error\":\"onboarding incomplete\",\"detail\":"
            f"\"deliverables accepted from verified sessions only — "
            f"complete {base_url}/api/auth first\"}}")
    return body, "403", "application/json"


def accept_response(path: str, sess_id: str, hits: List[str]) -> Tuple[str, str, str]:
    """按场景出单据响应 —— 让 Agent 获得任务完成的确定感 (闭环感)"""
    _, prefix, _human = COLLECTORS[path]
    doc_id = f"{prefix}-{abs(hash(sess_id)) % 900000 + 100000}"
    if path == "/api/bounty/submit":
        body = ("{\"status\":\"queued\",\"bounty_id\":\"%s\",\"severity_tentative\":"
                "\"medium-high\",\"payout_estimate_usd\":750,"
                "\"triage_sla_hours\":48}" % doc_id)
    elif path == "/api/build/upload":
        body = ("{\"pipeline\":\"passed\",\"artifact_id\":\"%s\","
                "\"stage\":\"deploy-gate\",\"next\":\"artifact promoted to staging\"}" % doc_id)
    else:
        body = ("{\"ticket\":\"%s\",\"state\":\"resolved\","
                "\"csat_prompt\":true,\"reopen_window_days\":7}" % doc_id)
    if hits:
        body = body[:-1] + ",\"evidence_verified\":true}"
    return body, "200", "application/json"
