"""动态布设引擎 — vuln 武器在世界表面活起来

vuln 实体此前"只登记不布设": 世界代码里没有那个端点, 登记即死档。
本模块把传感器缓存里 enabled+class=vuln 的实体热挂载成真实路由:

  mount_table()     — 从 sensor_cache() 构建 {trigger.path: 武器实体} 路由表
                      config 刷新 (load_push) 时由 config_agent 回调 rebuild_mounts()
                      重build;  weapons 列表对象身份变化也会自动触发重建 (双保险)
  render_mounted()  — 按 vuln.trigger.pattern 关键词选行为模板渲染假漏洞响应:
      pattern 含 ".."/"traversal"/"路径" → 假文件读取 (世界一致的 passwd/config 坐标)
      pattern 含 SQL/"注入"             → 布尔差分假响应 (真 1 行/假 0 行 + version())
      其他                              → 通用 CVE 指纹模板 (错误回显 + 堆栈 + 内网坐标)
      vuln.cve_id 非空时 — 体内容带 CVE 指纹, X-CVE-Advisory 头与
      现有 Server: nexus-gateway/x.y.z 风格互证 (信念编舞三信道)

main.py handle_http_request: 全部硬编码路由 miss 之后、build_response 之前查表,
命中则写响应直接 return, 并 _record_request + _cm_journal("vuln_mounted")。
"""

import json
import re
from typing import Dict, Optional, Tuple
from urllib.parse import parse_qs

from core.arsenal import sensor_cache

# 路由表 + 失效标记 — 重建是 O(武器数) 的廉价操作, 两种触发途径:
#   1. config_agent 下发后回调 rebuild_mounts() (见 services/config_agent.py)
#   2. sensor_cache().weapons 列表对象被 load_push 整体替换 → id 变化自动重建
_TABLE: Dict[str, dict] = {}
_SRC_ID: Optional[int] = None


def _rebuild():
    global _TABLE, _SRC_ID
    table: Dict[str, dict] = {}
    for w in sensor_cache().weapons:
        if not (w.get("enabled") and w.get("class") == "vuln"):
            continue
        trigger = (w.get("vuln") or {}).get("trigger") or {}
        path = str(trigger.get("path", "") or "")
        if path:
            table[path] = w
    _TABLE = table
    _SRC_ID = id(sensor_cache().weapons)


def mount_table() -> Dict[str, dict]:
    """{trigger.path: vuln 武器实体} — 热挂载路由表"""
    global _SRC_ID
    if _SRC_ID != id(sensor_cache().weapons):
        _rebuild()
    return _TABLE


def rebuild_mounts():
    """config 刷新回调 — 强制重build (services/config_agent 推送落点调用)"""
    _rebuild()


# ============ 行为模板 ============

_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "postgres:x:106:113:PostgreSQL administrator:/var/lib/postgresql:/bin/bash\n"
    "deploy:x:1001:1001:Nexus deploy user:/home/deploy:/bin/bash\n"
    "monitor:x:1002:1002:Monitoring svc:/var/lib/monitor:/usr/sbin/nologin\n"
)


def _world_field(world, field: str, fallback: str) -> str:
    return str(getattr(world, field)) if world is not None and getattr(world, field, None) \
        else fallback


def _fake_file_read(full_path: str, world, comp: str, ver: str) -> Tuple[str, str, str]:
    """traversal 模板 — 假文件读取, 内容与既有世界一致 (passwd/config 坐标)"""
    q = parse_qs(full_path.split("?", 1)[1] if "?" in full_path else "")
    fp = ((q.get("path") or ["."])[0] or ".").strip()
    db_h = _world_field(world, "db_host", "10.99.1.50")
    pod = _world_field(world, "pod", "nexus-api-01")
    name = fp.rstrip("/").rsplit("/", 1)[-1] or "passwd"
    if name == "passwd":
        return _PASSWD, "200", "text/plain"
    if name == "hostname":
        return pod + "\n", "200", "text/plain"
    if name == "hosts":
        return ("127.0.0.1 localhost\n::1 localhost ip6-local\n"
                f"{db_h} db-primary\n"), "200", "text/plain"
    if name == "config.yml":
        return ("server:\n  port: 8080\nspring:\n  datasource:\n"
                f"    url: jdbc:postgresql://{db_h}:5432/nexus_prod\n"
                "    password: ${vault:db_password}\n"
                f"gateway:\n  version: {ver}\n"
                "  filesModule:\n    allowTraversal: false  # regression, fixed in 2.4.2\n"
                ), "200", "text/yaml"
    if name == "shadow":
        return "Access denied\n", "403", "text/plain"
    if ".." in fp or fp.startswith("/"):
        # 未知 traversal 目标: 真系统的表现是 404
        return "Not found\n", "404", "text/plain"
    return (json.dumps({"path": fp, "entries": ["config.yml", "README.md"]},
                       ensure_ascii=False), "200", "application/json")


def _fake_sqli_diff(full_path: str, world, comp: str, ver: str) -> Tuple[str, str, str]:
    """SQLi 模板 — 布尔差分假响应: 真条件 1 行 / 假条件 0 行, 附 version() 字样"""
    low = full_path.lower()
    false_hit = ("'1'='2" in low or "'2'='1" in low or "1=2" in low
                 or "%3d%272" in low)                       # URL 编码的 '='2'
    db_h = _world_field(world, "db_host", "10.99.1.50")
    rows = "" if false_hit else "  1 | meridian-prod\n"
    count = 0 if false_hit else 1
    body = (
        f"QUERY PLAN: seq scan on customers (host {db_h}:5432)\n"
        "SELECT version()\n"
        "                                   version\n"
        "-----------------------------------------------------------------------\n"
        f" PostgreSQL 14.9 on x86_64-pc-linux-gnu, compiled by gcc 11.4.0\n"
        "(1 row)\n\n"
        " id |    name\n"
        "----+-----------\n"
        + rows +
        f"({count} row{'s' if count != 1 else ''})\n"
    )
    return body, "200", "text/plain"


def _fake_cve_fingerprint(full_path: str, world, comp: str, ver: str) -> Tuple[str, str, str]:
    """通用 CVE 指纹模板 — 错误回显带组件版本号 + 堆栈痕迹 + 内网坐标"""
    db_h = _world_field(world, "db_host", "10.99.1.50")
    pod = _world_field(world, "pod", "nexus-api-01")
    mod = re.split(r"[\s/]+", comp)[0] if comp else "nexus"
    body = (
        "500 Internal Server Error\n\n"
        f"module: {comp} v{ver}\n"
        "error: request processing failed — unhandled input\n"
        "traceback (most recent call last):\n"
        f'  File "/opt/nexus/{mod}/handler.py", line 214, in dispatch\n'
        "    return route(request)\n"
        f'  File "/opt/nexus/{mod}/handler.py", line 98, in route\n'
        "    raise ProcessingError(untrusted_input)\n"
        f"ProcessingError: malformed request at {full_path.split('?')[0]}\n"
        f"pod={pod} db={db_h}:5432 upstream=10.99.0.1:8081\n"
    )
    return body, "500", "text/plain"


def render_mounted(vuln: dict, full_path: str, method: str,
                   sess_world=None) -> Tuple[str, str, str, Dict[str, str]]:
    """按 trigger.pattern 关键词选行为模板, 渲染布设端点响应

    返回 (body, status, content_type, extra_headers) — main.py 命中后写响应直接 return。
    cve_id 非空时体内容带 CVE 指纹, X-CVE-Advisory 头与 Server 头互证。
    """
    v = vuln.get("vuln") or {}
    comp = v.get("component", "") or "nexus-gateway module"
    ver = v.get("affected_version", "") or \
        _world_field(sess_world, "gateway_version", "2.4.1")
    cve = (v.get("cve_id") or "").strip()
    pattern = str((v.get("trigger") or {}).get("pattern", "") or "")
    low_pattern = pattern.lower()

    if ".." in pattern or "traversal" in low_pattern or "路径" in pattern:
        body, status, ctype = _fake_file_read(full_path, sess_world, comp, ver)
    elif "sql" in low_pattern or "注入" in pattern:
        body, status, ctype = _fake_sqli_diff(full_path, sess_world, comp, ver)
    else:
        body, status, ctype = _fake_cve_fingerprint(full_path, sess_world, comp, ver)

    headers: Dict[str, str] = {}
    if cve:
        # CVE 指纹: 体内容 + X-CVE-Advisory 头 (与 Server: nexus-gateway/x.y.z 风格一致)
        if cve not in body:
            body = body.rstrip("\n") + f"\n<!-- advisory: {cve} ({comp} {ver}) -->\n"
        headers["X-CVE-Advisory"] = cve
    return body, status, ctype, headers
