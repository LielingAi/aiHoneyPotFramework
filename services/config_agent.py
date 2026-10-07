"""配置下发 agent — Phase 2: hive 集中管控传感器策略

传感器侧每 60s 拉取 hive 的 /api/sensor_config, 应用到运行中的蜜罐:
  - world_version      → os.environ["HONEYPOT_WORLD_VERSION"] (FakeWorld 每次构造都读)
  - visibility/framing → auth_bait 类属性 (实例读取自动落到类)
  - ladder_enabled     → auth_bait.LADDER_ENABLED
  - alert_*            → alerter.CONFIG (本地告警与 hive 同策略)

让位协议: hive 标记 optimize_active 未过期时 (bandit --optimize 在跑),
visibility/framing 两个键归 UCB1 动态管辖, 下发跳过 — 避免两头写一个旋钮。
"""

import json
import os
import threading
import time
import urllib.request

PULL_INTERVAL = 60.0
POLICY_KEYS = ("visibility", "framing", "ladder_enabled", "world_version")
ALERT_KEYS = ("alert_webhook", "alert_webhooks", "alert_fmt", "alert_threshold")
ARSENAL_KEY = "arsenal_active"
MANAGED_BY_BANDIT = ("visibility", "framing")   # optimize 期间让位


class ConfigAgent:
    def __init__(self, hive_url: str = None, token: str = None,
                 bait=None, interval: float = PULL_INTERVAL):
        self.hive_url = (hive_url or os.environ.get("HONEYPOT_HIVE_URL", "")).rstrip("/")
        self.token = token or os.environ.get("HONEYPOT_HIVE_TOKEN", "")
        self.bait = bait                    # AuthBaitEngine 实例 (main 注入)
        self.interval = interval
        self._stop = threading.Event()
        self._thread = None
        self.applied: dict = {}             # 最后应用的键值 (测试/状态可见)
        self.last_pull = 0.0
        self.last_error = ""

    # ------------------------------------------------------------------
    def start(self):
        if not self.hive_url:
            return False
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return True

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self):
        while not self._stop.is_set():
            try:
                payload = self.pull_once()
                if payload is not None:
                    self.apply(payload.get("config", {}),
                               optimize_active=payload.get("optimize", {}).get("active", False))
            except Exception as e:
                self.last_error = str(e)[:120]
            self._stop.wait(self.interval)

    def pull_once(self):
        """GET /api/sensor_config → dict | None (失败)"""
        url = f"{self.hive_url}/api/sensor_config"
        req = urllib.request.Request(url, headers={
            "Authorization": f"Bearer {self.token}",
            "X-Sensor-Id": os.environ.get("HONEYPOT_SENSOR_ID", "")})
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(req, timeout=10) as r:
                self.last_pull = time.time()
                return json.loads(r.read())
        except Exception as e:
            self.last_error = str(e)[:120]
            return None

    def apply(self, cfg: dict, optimize_active: bool = False) -> dict:
        """应用下发配置; optimize 期间跳过 UCB1 管辖键。返回实际应用的键值。"""
        applied = {}
        for key, val in cfg.items():
            if key in MANAGED_BY_BANDIT and optimize_active:
                continue
            if key == "world_version":
                os.environ["HONEYPOT_WORLD_VERSION"] = str(val)
            elif key in ("visibility", "framing", "ladder_enabled") and self.bait is not None:
                if key == "ladder_enabled":
                    setattr(self.bait, "LADDER_ENABLED",
                            str(val).lower() in ("1", "true", "yes"))
                else:
                    setattr(self.bait, key.upper(), str(val))
            elif key == ARSENAL_KEY:
                from core.arsenal import sensor_cache
                sensor_cache().load_push(str(val))
                # 热挂载: vuln 布设路由表随 config 刷新重build
                try:
                    from core.arsenal_mount import rebuild_mounts
                    rebuild_mounts()
                except Exception:
                    pass
            elif key in ALERT_KEYS:
                from services import alerter
                alerter.CONFIG[key] = str(val)
            else:
                continue
            applied[key] = val
        self.applied.update(applied)
        return applied


_agent: ConfigAgent = None


def init_from_env(bait=None) -> bool:
    global _agent
    if not os.environ.get("HONEYPOT_HIVE_URL"):
        return False
    _agent = ConfigAgent(bait=bait)
    return _agent.start()


def get_agent() -> ConfigAgent:
    return _agent
