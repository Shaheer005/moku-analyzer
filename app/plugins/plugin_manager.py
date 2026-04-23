"""
PluginManager — decides which plugins to run and collects all TestCases.
Pure — no network calls here.
"""
from typing import List
from app.core.scan_unit import ScanUnit
from app.core.test_case import TestCase
from app.plugins.base_plugin import BasePlugin
from app.plugins.xss_plugin import XSSPlugin
from app.plugins.sqli_plugin import SQLiPlugin
from app.plugins.csrf_plugin import CSRFPlugin


class PluginManager:
    def __init__(self):
        self._plugins: List[BasePlugin] = [
            XSSPlugin(),
            SQLiPlugin(),
            CSRFPlugin(),
        ]

    def generate_tests(self, scan_unit: ScanUnit) -> List[TestCase]:
        tests = []
        for plugin in self._plugins:
            if scan_unit.plugins and plugin.name not in scan_unit.plugins:
                continue
            plugin_tests = plugin.generate_tests(scan_unit)
            tests.extend(plugin_tests)
            print(f"[plugin_manager] {plugin.name} generated {len(plugin_tests)} tests")
        return tests

    def get_plugins(self) -> List[BasePlugin]:
        return self._plugins


plugin_manager = PluginManager()