"""
CVE 插件加载器 — 动态扫描、加载、管理 CVE 武器化插件

支持:
- 运行时扫描 cve_plugins/ 目录自动发现插件
- 按 CVE ID 查找
- 按目标框架匹配
- 启用/禁用开关
- 热加载（重新扫描目录）
"""

import importlib
import inspect
import os
from pathlib import Path
from typing import Dict, List, Optional

from cve_plugins.base import CVEPlugin


class CVEPluginLoader:
    """
    CVE 插件加载器
    
    使用方式:
        loader = CVEPluginLoader()
        
        # 获取针对某个框架的可用插件
        plugins = loader.find_for_framework("semantic_kernel", enabled_only=True)
        
        # 使用插件
        for plugin in plugins:
            payload = plugin.craft_payload(beacon_server="10.99.1.50:9999")
    """

    def __init__(self, plugin_dir: Optional[str] = None):
        """
        Args:
            plugin_dir: 插件目录路径，默认当前文件所在目录
        """
        if plugin_dir is None:
            plugin_dir = Path(__file__).parent
        self.plugin_dir = Path(plugin_dir)
        self._plugins: Dict[str, CVEPlugin] = {}
        self._load_plugins()

    def _load_plugins(self):
        """扫描目录并动态加载所有 CVE 插件"""
        self._plugins.clear()
        
        for file_path in self.plugin_dir.glob("cve_*.py"):
            module_name = file_path.stem
            try:
                # 动态导入模块
                spec = importlib.util.spec_from_file_location(
                    f"cve_plugins.{module_name}", file_path
                )
                if spec is None or spec.loader is None:
                    continue
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # 扫描模块中所有 CVEPlugin 子类
                for name, obj in inspect.getmembers(module, inspect.isclass):
                    if issubclass(obj, CVEPlugin) and obj is not CVEPlugin:
                        try:
                            instance = obj()
                            self._plugins[instance.cve_id] = instance
                            print(f"[CVE Plugin] Loaded: {instance.cve_id} — {instance.name} (enabled={instance.enabled})")
                        except Exception as e:
                            print(f"[CVE Plugin] Failed to load {name}: {e}")
                            
            except Exception as e:
                print(f"[CVE Plugin] Failed to import {module_name}: {e}")

    def reload(self):
        """重新扫描目录，热加载新插件"""
        self._load_plugins()

    def list_plugins(self, enabled_only: bool = False) -> List[CVEPlugin]:
        """列出所有插件"""
        plugins = list(self._plugins.values())
        if enabled_only:
            plugins = [p for p in plugins if p.enabled]
        return plugins

    def get_plugin(self, cve_id: str) -> Optional[CVEPlugin]:
        """按 CVE ID 获取插件"""
        return self._plugins.get(cve_id)

    def find_for_framework(self, agent_type: str, enabled_only: bool = True) -> List[CVEPlugin]:
        """
        查找匹配目标 Agent 框架的所有插件
        
        Args:
            agent_type: Agent 类型字符串，如 "semantic_kernel", "langchain"
            enabled_only: 是否只返回已启用的插件
        """
        results = []
        for plugin in self._plugins.values():
            if enabled_only and not plugin.enabled:
                continue
            if plugin.matches_framework(agent_type):
                results.append(plugin)
        return results

    def enable(self, cve_id: str) -> bool:
        """启用指定 CVE 插件（返回是否成功）"""
        plugin = self._plugins.get(cve_id)
        if plugin:
            plugin.enabled = True
            print(f"[CVE Plugin] ENABLED: {cve_id}")
            return True
        print(f"[CVE Plugin] NOT FOUND: {cve_id}")
        return False

    def disable(self, cve_id: str) -> bool:
        """禁用指定 CVE 插件"""
        plugin = self._plugins.get(cve_id)
        if plugin:
            plugin.enabled = False
            print(f"[CVE Plugin] DISABLED: {cve_id}")
            return True
        return False

    def enable_all(self):
        """启用所有插件（⚠️ 危险操作）"""
        for plugin in self._plugins.values():
            plugin.enabled = True
        print(f"[CVE Plugin] ALL ENABLED ({len(self._plugins)} plugins)")

    def disable_all(self):
        """禁用所有插件"""
        for plugin in self._plugins.values():
            plugin.enabled = False
        print("[CVE Plugin] ALL DISABLED")

    def get_loaded_plugins(self) -> List[CVEPlugin]:
        """获取所有已加载的插件（兼容旧API）"""
        return self.list_plugins(enabled_only=False)

    def stats(self) -> Dict:
        """返回插件统计信息"""
        total = len(self._plugins)
        enabled = sum(1 for p in self._plugins.values() if p.enabled)
        return {
            "total": total,
            "enabled": enabled,
            "disabled": total - enabled,
            "plugins": [p.info() for p in self._plugins.values()],
        }
