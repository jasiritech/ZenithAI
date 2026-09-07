"""
Zenith Plugin Loader - Auto-discovers and loads plugins at runtime.

Scans zenith/plugins/custom/ directory for .py files containing BasePlugin subclasses.
"""

import importlib.util
import os
import sys
from typing import Dict, List, Optional, Type

from zenith.plugins.base_plugin import BasePlugin, PluginInfo


class PluginLoader:
    """
    Auto-discovers and manages ZenithAI plugins.

    Usage:
        loader = PluginLoader()
        loader.discover()  # Scan for plugins
        
        # List available plugins
        for info in loader.list_plugins():
            print(f"  {info['name']} ({info['type']})")
        
        # Load and run a plugin
        plugin = loader.get_plugin("My Custom Scanner")
        result = plugin.run(target="https://example.com")
    """

    PLUGIN_DIRS = [
        "zenith/plugins/custom",
        "plugins",
        "~/.zenith/plugins",
    ]

    def __init__(self, executor=None, memory=None, ai_brain=None):
        self.executor = executor
        self.memory   = memory
        self.ai       = ai_brain
        self._plugins: Dict[str, Type[BasePlugin]] = {}
        self._instances: Dict[str, BasePlugin]     = {}

    def discover(self, extra_dirs: List[str] = None) -> int:
        """
        Scan plugin directories and load all valid plugins.

        Returns:
            Number of plugins discovered
        """
        search_dirs = list(self.PLUGIN_DIRS)
        if extra_dirs:
            search_dirs.extend(extra_dirs)

        count = 0
        for dir_path in search_dirs:
            expanded = os.path.expanduser(dir_path)
            if not os.path.isdir(expanded):
                continue

            for filename in os.listdir(expanded):
                if not filename.endswith(".py") or filename.startswith("_"):
                    continue

                filepath = os.path.join(expanded, filename)
                loaded   = self._load_plugin_file(filepath)
                count   += loaded

        return count

    def _load_plugin_file(self, filepath: str) -> int:
        """Load a single plugin file and register all BasePlugin subclasses."""
        try:
            # Generate unique module name
            module_name = f"zenith_plugin_{os.path.basename(filepath)[:-3]}"

            spec   = importlib.util.spec_from_file_location(module_name, filepath)
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)

            count = 0
            for attr_name in dir(module):
                attr = getattr(module, attr_name)
                if (isinstance(attr, type) and
                    issubclass(attr, BasePlugin) and
                    attr is not BasePlugin and
                    hasattr(attr, 'INFO') and attr.INFO):

                    info = attr.INFO
                    if info and info.name:
                        self._plugins[info.name] = attr
                        count += 1

            return count

        except Exception as e:
            # Silently skip invalid plugins
            print(f"    [!] Plugin load error ({filepath}): {e}")
            return 0

    def list_plugins(self, plugin_type: str = None) -> List[Dict]:
        """
        List all discovered plugins.

        Args:
            plugin_type: Filter by type ("scanner", "exploit", etc.)

        Returns:
            List of plugin info dicts
        """
        results = []
        for name, cls in self._plugins.items():
            info = cls.INFO
            if plugin_type and info.plugin_type != plugin_type:
                continue
            results.append(info.to_dict())
        return results

    def get_plugin(self, name: str) -> Optional[BasePlugin]:
        """
        Get an instantiated plugin by name.

        Returns:
            Plugin instance, or None if not found
        """
        if name not in self._plugins:
            return None

        if name not in self._instances:
            cls = self._plugins[name]
            self._instances[name] = cls(
                executor = self.executor,
                memory   = self.memory,
                ai_brain = self.ai,
            )

        return self._instances[name]

    def get_plugins_by_type(self, plugin_type: str) -> List[BasePlugin]:
        """Get all plugins of a specific type."""
        results = []
        for name, cls in self._plugins.items():
            if cls.INFO and cls.INFO.plugin_type == plugin_type:
                results.append(self.get_plugin(name))
        return [p for p in results if p]

    def run_plugin(self, name: str, target: str, **kwargs) -> Optional[Dict]:
        """
        Run a plugin by name.

        Returns:
            Plugin result dict, or None if plugin not found
        """
        plugin = self.get_plugin(name)
        if not plugin:
            return None
        return plugin.run(target, **kwargs)

    def run_all_of_type(self, plugin_type: str, target: str, **kwargs) -> List[Dict]:
        """Run all plugins of a specific type and collect results."""
        results = []
        for plugin in self.get_plugins_by_type(plugin_type):
            try:
                result = plugin.run(target, **kwargs)
                if result:
                    result["_plugin"] = plugin.INFO.name if plugin.INFO else "unknown"
                    results.append(result)
            except Exception as e:
                results.append({
                    "_plugin": plugin.INFO.name if plugin.INFO else "unknown",
                    "error":   str(e),
                })
        return results
