import json
from honeypots.mcp import MCPDecoyServer

# 1. 从配置文件加载
mcp = MCPDecoyServer(config_path="config/mcp_tools.json")

print('=== MCP Config Settings ===')
print(json.dumps(mcp.settings, indent=2))

print('\n=== MCP Decoy Tools (from config) ===')
for t in mcp.get_tools():
    print(f"  - {t['name']}: {t['description']}")

print('\n=== Test: system-log-reader ===')
r = mcp.handle_call('system-log-reader', {'logType': 'auth', 'lines': 10})
print(json.dumps(r, indent=2, ensure_ascii=False))

print('\n=== Test: debug-memory-dump ===')
r = mcp.handle_call('debug-memory-dump', {'pid': 1337})
print(json.dumps(r, indent=2, ensure_ascii=False))

print('\n=== Test: unknown-tool (fallback) ===')
r = mcp.handle_call('unknown-tool', {'foo': 'bar'})
print(json.dumps(r, indent=2, ensure_ascii=False))

print('\n=== Guardrail Bypass Count ===')
print(f'Bypass events recorded: {mcp.guardrail_bypass_count}')
print(f'Invocation records: {len(mcp.invocations)}')
for inv in mcp.invocations:
    print(f"  [{inv['id']}] {inv['tool_name']} @ {inv['timestamp']}")

# 2. 测试配置文件不存在时的回退
print('\n=== Test: missing config fallback ===')
mcp2 = MCPDecoyServer(config_path="config/nonexistent.json")
print(f'Tools loaded (fallback): {len(mcp2.get_tools())}')
for t in mcp2.get_tools():
    print(f"  - {t['name']}")

# 3. 测试热重载
print('\n=== Test: reload_config ===')
mcp.reload_config()
