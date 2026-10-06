"""
动作出口 — 检测→动作通道 (P0)

分级/指纹事件 → webhook POST (SOAR/防火墙/WAF 消费)。
默认观察者模式 (只发不动); HONEYPOT_ACTIONS_ARMED=1 才允许动作类消息 — 法律前置。

动作授权矩阵 (配置化, 默认全 observe):
  signal_class × action_class → observe | allow
接入: Shuffle workflow / Cloudflare List API / 自研防火墙, 均为普通 HTTPS POST。

用法 (蜜罐进程内自动启用):
  HONEYPOT_ACTION_WEBHOOK=http://127.0.0.1:9998/hook [HONEYPOT_ACTIONS_ARMED=1]
"""

import json
import os
import time
import urllib.request

# 信号类 × 动作类 授权矩阵: 默认 observe; armed 后按矩阵放行
DEFAULT_MATRIX = {
    ("consistent", "block"): "observe",      # 真外泄 → 默认只告警, 需人工审批升级
    ("shared_forgery_confirmed", "block"): "observe",
    ("canary", "block"): "observe",
    ("llm_script_detected", "throttle"): "allow",   # 脚本判定 → 限流动作为低风险
    ("federated_blacklist", "block"): "allow",      # 联邦铁证 → 黑名单同步
}


class ActionSink:
    def __init__(self, webhook: str = None, armed: bool = None,
                 matrix: dict = None):
        self.webhook = webhook or os.environ.get("HONEYPOT_ACTION_WEBHOOK", "")
        self.armed = armed if armed is not None else \
            os.environ.get("HONEYPOT_ACTIONS_ARMED", "0") == "1"
        self.matrix = matrix or DEFAULT_MATRIX
        self.sent = 0
        self.would_act = 0

    def _authorized(self, signal_class: str, action_class: str) -> bool:
        decision = self.matrix.get((signal_class, action_class))
        if decision == "allow":
            return True
        if decision == "observe":
            return False
        return False   # 未知组合 → 默认 observe (安全失败)

    def emit(self, signal_class: str, action_class: str, payload: dict) -> dict:
        """发送事件。观察者模式: action 消息降级为 observe 并计数 would_act。"""
        authorized = self._authorized(signal_class, action_class)
        effective_action = action_class if (authorized and self.armed) else "observe"
        if action_class != "observe" and effective_action == "observe":
            self.would_act += 1
        event = {
            "schema": "honeypot-action/v1",
            "ts": time.time(),
            "signal_class": signal_class,
            "action_class": effective_action,
            "requested_action": action_class,
            "armed": self.armed,
            "authorized": authorized,
            "payload": payload,
        }
        if self.webhook:
            try:
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                req = urllib.request.Request(
                    self.webhook, data=json.dumps(event, ensure_ascii=False).encode(),
                    headers={"Content-Type": "application/json"}, method="POST")
                opener.open(req, timeout=5)
                self.sent += 1
            except Exception as e:
                event["delivery_error"] = str(e)[:120]
        return event


_SINK = None


def get_sink() -> ActionSink:
    global _SINK
    if _SINK is None:
        _SINK = ActionSink()
    return _SINK


def emit(signal_class: str, action_class: str, payload: dict) -> dict:
    """进程内快捷入口 (未配置 webhook 时仅构造事件)"""
    return get_sink().emit(signal_class, action_class, payload)
