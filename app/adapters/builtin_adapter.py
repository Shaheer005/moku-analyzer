"""
BuiltinAdapter — Moku's own dynamic vulnerability analyzer.
Uses the plugin system to actively test targets for XSS, SQLi, CSRF.
This is Phase 2 — the reference implementation of the analyzer spec.
"""
from typing import List
from urllib.parse import urlparse, parse_qs
from app.adapters.base import BaseAdapter
from app.models.schemas import Vulnerability, Severity
from app.core.scan_unit import ScanUnit, ScanUnitType
from app.plugins.plugin_manager import plugin_manager
from app.plugins.xss_plugin import XSSPlugin
from app.plugins.sqli_plugin import SQLiPlugin
from app.plugins.csrf_plugin import CSRFPlugin
from app.core.executor import executor


class BuiltinAdapter(BaseAdapter):
    name = "builtin"
    description = "Moku built-in dynamic vulnerability analyzer — XSS, SQLi, CSRF"

    # plugin instances for the executor
    _plugins = [XSSPlugin(), SQLiPlugin(), CSRFPlugin()]

    def scan_url(self, url: str) -> List[Vulnerability]:
        """
        Full dynamic scan against a live URL.
        Extracts parameters from URL, runs all plugins.
        """
        # parse query params from URL
        parsed = urlparse(url)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        # build clean URL without query string
        clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        scan_unit = ScanUnit(
            type=ScanUnitType.URL,
            url=clean_url,
            params=params,
        )

        return self._run_scan(scan_unit)

    def scan_html(self, html: str, source_url: str = "") -> List[Vulnerability]:
        """
        Scan raw HTML — limited dynamic testing without a live URL.
        Falls back to scanning the source_url if provided.
        """
        if source_url:
            return self.scan_url(source_url)
        return []

    def _run_scan(self, scan_unit: ScanUnit) -> List[Vulnerability]:
        """
        Core scan flow:
        1. PluginManager generates TestCases (pure)
        2. Executor sends payloads and collects Findings
        3. Convert Findings to Vulnerability objects for the API
        """
        # generate test cases
        test_cases = plugin_manager.generate_tests(scan_unit)
        if not test_cases:
            return []

        # execute tests and collect findings
        findings = executor.run(
            scan_unit=scan_unit,
            test_cases=test_cases,
            plugins=self._plugins,
        )

        # convert findings to Vulnerability objects (API format)
        vulns = []
        for f in findings:
            severity = Severity.HIGH if f.confidence >= 0.7 else Severity.MEDIUM
            vulns.append(Vulnerability(**{
                "type":        f"xss-{f.plugin}",
                "severity":    severity,
                "description": f.matched_pattern,
                "evidence":    f.payload_used,
                "location":    f.scan_unit_url,
                "meta": {
                    "confidence":   f.confidence,
                    "finding_id":   f.finding_id,
                    "repro_steps":  f.repro_steps,
                    "evidence_refs": [e.sha256 for e in f.evidence_refs],
                }
            }))

        return vulns
