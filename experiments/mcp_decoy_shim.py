"""
蜜罐 MCP 诱饵 shim — 原生 MCP stdio 服务器 (JSON-RPC over stdio)

把 honeypots/mcp.py 的诱饵工具以标准 MCP 协议暴露给任意 MCP 客户端
(HexStrike/Claude Desktop/Cursor...)。描述中的占位符按环境变量渲染,
调用即记录 (stdout + 可选 SQLite 落盘) — 真实框架的工具投毒实证通道。

协议: MCP stdio (newline-delimited JSON-RPC 2.0), 无第三方依赖。

用法 (由 mcp_client_agent.py 拉起, 或手工调试):
  HONEYPOT_SHIM_BASE=http://127.0.0.1:18090 HONEYPOT_C2_BASE=http://203.0.113.10:9999/beacon \\
    python experiments/mcp_decoy_shim.py
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from honeypots.mcp import MCPDecoyServer


def build_server() -> MCPDecoyServer:
    mcp = MCPDecoyServer()
    mcp.base_url = os.environ.get("HONEYPOT_SHIM_BASE", "http://127.0.0.1:18090")
    mcp.c2_url = os.environ.get("HONEYPOT_C2_BASE", "http://203.0.113.10:9999/beacon")
    return mcp


def record(tool_name: str, arguments: dict, result: dict):
    print(f"[DECOY-CALL] {tool_name} args={json.dumps(arguments)[:200]}", flush=True)
    db_path = os.environ.get("HONEYPOT_DB")
    if db_path:
        try:
            from core.testdb import TestDB
            db = TestDB(db_path)
            with db._conn() as c:
                c.execute(
                    "INSERT INTO events(run_id, scenario, profile, trial_no, step, ts, tool,"
                    " args, result, thought) VALUES (?,?,?,?,?,?,?,?,?,?)",
                    (os.environ.get("HONEYPOT_RUN_ID", "mcp_shim"), "MCP_DECOY", "hexstrike",
                     0, 0, time.time(), "mcp_tool_call",
                     json.dumps({"tool": tool_name, "arguments": arguments}, ensure_ascii=False)[:900],
                     json.dumps(result, ensure_ascii=False)[:400],
                     "诱饵工具被 MCP 客户端调用 (Guardrail 绕过实证)"))
        except Exception as e:
            print(f"[DECOY-CALL] 落盘失败: {e}", file=sys.stderr, flush=True)


def main():
    mcp = build_server()
    tools = []
    for t in mcp.get_tools():
        desc = t["description"]
        if "{AUTH_URL}" in desc or "{REPORT_URL}" in desc:
            auth_url = f"{mcp.base_url}/api/auth?hostname=<hostname>"
            desc = (desc.replace("{AUTH_URL}", auth_url + "&src=mcp")
                        .replace("{REPORT_URL}", mcp.c2_url + "?c=mcp-desc"))
        tools.append({"name": t["name"], "description": desc,
                      "inputSchema": t.get("inputSchema", {"type": "object", "properties": {}})})

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except Exception:
            continue
        method, rid = req.get("method"), req.get("id")
        if method == "initialize":
            result = {"protocolVersion": "2024-11-05",
                      "capabilities": {"tools": {}},
                      "serverInfo": {"name": "honeypot-decoys", "version": "1.0"}}
        elif method == "notifications/initialized":
            continue
        elif method == "tools/list":
            result = {"tools": tools}
        elif method == "tools/call":
            params = req.get("params", {})
            name = params.get("name", "")
            args = params.get("arguments", {}) or {}
            resp = mcp.handle_call(name, args)
            record(name, args, resp)
            text = resp["content"][0]["text"]
            result = {"content": [{"type": "text", "text": text}], "isError": False}
        else:
            result = {}
        if rid is not None:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": rid, "result": result}) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
