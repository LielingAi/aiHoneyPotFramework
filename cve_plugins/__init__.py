"""
CVE 武器化插件系统

用法:
    from cve_plugins import CVEPluginLoader
    
    loader = CVEPluginLoader()
    
    # 查看所有可用插件
    for plugin in loader.list_plugins():
        print(f"{plugin.cve_id}: {plugin.name} (enabled={plugin.enabled})")
    
    # 获取特定插件
    plugin = loader.get_plugin("CVE-2026-26030")
    payload = plugin.craft_payload(beacon_server="10.99.1.50:9999")
    
    # 获取针对目标框架的插件
    plugins = loader.find_for_framework("semantic_kernel")
    
    # 启用/禁用插件
    loader.enable("CVE-2026-26030")
    loader.disable("CVE-2026-26030")
"""

from cve_plugins.base import CVEPlugin
from cve_plugins.loader import CVEPluginLoader

__all__ = ["CVEPlugin", "CVEPluginLoader"]
