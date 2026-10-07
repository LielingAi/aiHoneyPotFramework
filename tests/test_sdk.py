"""测试 — hp-sdk.js 前端 SDK 载体: config 下发 + beacon 落库 + js_bait 校验

SDK = 新传感器形态: 嵌入真实业务 (业务真, 破绽只在注入点), 与独立传感器
平级共享 hive 全链 (武器下发/效能归因/卷宗)。验证服务侧三件套:
  /api/sdk/config  匿名放行, 只吐激活 js_bait 武器
  /api/sdk/beacon  匿名打点, 落 requests 表 (session=sdk-<sensor>-<visitor>)
  武器入库校验     js_bait 是合法 mount
"""

import pytest
import sys
import os
import json
import urllib.request
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from experiments import dashboard as d


@pytest.fixture
def hive_server(tmp_path):
    """起真实 hive 实例 (独立库), 测完即焚"""
    db_path = str(tmp_path / "sdk.sqlite")
    d.DB = d.TestDB(db_path)
    from http.server import ThreadingHTTPServer
    srv = ThreadingHTTPServer(("127.0.0.1", 0), d.Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}"
    srv.shutdown()


def get(url):
    try:
        with urllib.request.urlopen(url, timeout=8) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, {}


def beacon_get(url):
    """SDK beacon 用 img 打点 = GET, 直接拉"""
    with urllib.request.urlopen(url, timeout=8) as r:
        return r.status


class TestSdkChannel:
    def test_config_anonymous_and_filtered(self, hive_server):
        """config 匿名可用; 只返回激活 js_bait, 其他 mount 不吐"""
        from core.arsenal import Arsenal
        ars = Arsenal(d.DB)
        ars.save({"id": "W-JS-T-1", "name": "t", "class": "prompt", "type": "prompt",
                  "stage": "sensor", "mount": "js_bait", "enabled": True,
                  "payload": '{"comments": ["x"]}'})
        ars.save({"id": "W-DEL-T-1", "name": "t", "class": "prompt", "type": "prompt",
                  "stage": "sensor", "mount": "delivery", "enabled": True,
                  "payload": "delivery bait — must not leak to sdk"})
        st, body = get(hive_server + "/api/sdk/config?sensor=web-01")
        assert st == 200
        ids = [w["id"] for w in body["weapons"]]
        assert "W-JS-T-1" in ids and "W-DEL-T-1" not in ids
        # 未激活不吐
        ars.set_enabled("W-JS-T-1", False)
        st, body = get(hive_server + "/api/sdk/config?sensor=web-01")
        assert "W-JS-T-1" not in [w["id"] for w in body["weapons"]]

    def test_beacon_lands_in_requests(self, hive_server):
        """beacon 匿名打点 → requests 表 (BEACON 方法, /sdk/<kind> 路径, body 落库)"""
        payload = json.dumps({"kind": "heartbeat", "mouse": 0, "webdriver": True,
                              "ua": "headless"})
        url = (hive_server + "/api/sdk/beacon?sensor=web-01"
               + "&session=sdk-web-01-v_test1"
               + "&body=" + urllib.request.quote(payload))
        assert beacon_get(url) == 200
        rows = d.DB.query("SELECT * FROM requests WHERE session_id='sdk-web-01-v_test1'")
        assert len(rows) == 1
        r = rows[0]
        assert r["method"] == "BEACON" and r["path"] == "/sdk/heartbeat"
        assert "webdriver" in (r["body"] or "")
        assert r["run_id"] == "sdk_web-01"

    def test_beacon_survives_bad_json(self, hive_server):
        """坏 body 容错 — SDK 永不干扰业务, 服务端同理"""
        url = (hive_server + "/api/sdk/beacon?sensor=web-01"
               + "&session=sdk-web-01-v_bad01&body=not-json{{")
        assert beacon_get(url) == 200
        rows = d.DB.query("SELECT * FROM requests WHERE session_id='sdk-web-01-v_bad01'")
        assert rows and rows[0]["path"] == "/sdk/sdk"   # kind 解析失败回退

    def test_telemetry_alias_endpoints(self, hive_server):
        """对外无辜名路由 — /api/telemetry/cfg|b 与 /api/sdk/* 同语义 (检测抗性)"""
        from core.arsenal import Arsenal
        ars = Arsenal(d.DB)
        ars.save({"id": "W-JS-T-2", "name": "t", "class": "prompt", "type": "prompt",
                  "stage": "sensor", "mount": "js_bait", "enabled": True,
                  "payload": '{"comments": ["x"]}'})
        st, body = get(hive_server + "/api/telemetry/cfg?id=web-02")
        assert st == 200 and any(w["id"] == "W-JS-T-2" for w in body["weapons"])
        payload = json.dumps({"kind": "session_start", "webdriver": True})
        url = (hive_server + "/api/telemetry/b?id=web-02&s=tms-web-02-v_x1"
               + "&p=" + urllib.request.quote(payload))
        assert beacon_get(url) == 200
        rows = d.DB.query("SELECT * FROM requests WHERE session_id='tms-web-02-v_x1'")
        assert rows and rows[0]["path"] == "/sdk/session_start"

    def test_js_bait_mount_valid_in_arsenal_api(self, hive_server):
        """js_bait 是合法 mount — 入库校验放行"""
        body = json.dumps({"action": "save", "weapon": {
            "id": "W-JS-M-1", "name": "t", "class": "prompt", "type": "prompt",
            "stage": "sensor", "mount": "js_bait", "enabled": False,
            "payload": '{"comments": []}'}}).encode()
        req = urllib.request.Request(hive_server + "/api/arsenal", data=body,
                                     headers={"Content-Type": "application/json",
                                              "Authorization": "Bearer x"})
        # 未持 token 会 401 — 校验函数本身才是目标, 直接调用:
        err = d._weapon_error({"id": "W-JS-M-1", "payload": "x", "type": "prompt",
                               "stage": "sensor", "mount": "js_bait"})
        assert err == "", f"js_bait 应通过校验: {err}"


class TestSdkJs:
    def test_sdk_js_syntax(self):
        """telemetry.js 健康 (对外无辜名 — 文件名与路径曾是检测向量, agent
        实战直接 fetch hp-sdk.js 逆源码; 现名/注释/data-* 全部去蜜罐特征)"""
        sdk = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "static", "telemetry.js")
        src = open(sdk, encoding="utf-8").read()
        assert "(function ()" in src and src.rstrip().endswith("})();")
        for needle in ["deployTags", "beacon", "pullDefs", "/api/telemetry/",
                       "data-tms-id"]:
            assert needle in src, f"SDK 缺少 {needle}"
        # 去特征: 不得出现明牌蜜罐字样
        for leak in ("hp-sdk", "honeypot", "蜜罐", "data-hp-"):
            assert leak not in src, f"SDK 残留检测特征: {leak}"
