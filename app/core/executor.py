"""
Executor — sends TestCase payloads to the target and collects responses.
Controls rate limiting, timeouts, and evidence saving.
The only component that makes network calls during a scan.
"""
import time
import requests
from typing import List, Tuple, Optional
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

from app.core.scan_unit import ScanUnit
from app.core.test_case import TestCase
from app.core.finding import Finding
from app.core.evidence_store import evidence_store
from app.plugins.base_plugin import BasePlugin


# safety limits — never exceed these
MAX_REQUESTS_PER_HOST = 30     # per scan session
REQUEST_DELAY_SECONDS = 0.5    # wait between requests (be polite)


class Executor:
    """
    Sends test payloads, collects responses, passes to plugins for analysis.
    Enforces rate limiting and timeouts.
    """

    def __init__(self):
        self._request_counts = {}    # host -> count
        self._session = requests.Session()
        self._session.headers.update({
            "User-Agent": "moku-analyzer/1.0 (security research)"
        })

    def run(
        self,
        scan_unit: ScanUnit,
        test_cases: List[TestCase],
        plugins: List[BasePlugin],
    ) -> List[Finding]:
        """
        Main execution loop:
          1. Fetch baseline response (no payload)
          2. For each test case: inject payload, send request, analyze response
          3. Collect all findings
        """
        findings = []
        host = urlparse(scan_unit.url).hostname or ""

        # Step 1 — fetch baseline (what the page looks like normally)
        baseline_body = self._fetch_baseline(scan_unit)
        print(f"[executor] baseline fetched for {scan_unit.url} ({len(baseline_body)} bytes)")

        # Step 2 — run each test case
        for test_case in test_cases:

            # rate limit check
            count = self._request_counts.get(host, 0)
            if count >= MAX_REQUESTS_PER_HOST:
                print(f"[executor] rate limit reached for {host} — skipping remaining tests")
                break

            # send the payload
            response_body, response_headers = self._send(scan_unit, test_case)

            # track request count
            self._request_counts[host] = count + 1

            if response_body is None:
                print(f"[executor] no response for {test_case.test_id} — skipping")
                continue

            # save full response as evidence
            evidence_store.save(
                data=f"TEST: {test_case.test_id}\nPAYLOAD: {test_case.payload}\nRESPONSE:\n{response_body[:4096]}",
                label=f"{test_case.plugin_name}_{test_case.mode.value}"
            )

            # ask each plugin to analyze the response
            for plugin in plugins:
                if plugin.name != test_case.plugin_name:
                    continue
                finding = plugin.analyze_response(
                    test_case=test_case,
                    response_body=response_body,
                    response_headers=response_headers,
                    baseline_body=baseline_body,
                )
                if finding:
                    print(f"[executor] FOUND: {finding.plugin} confidence={finding.confidence} on {test_case.test_id}")
                    findings.append(finding)

            # polite delay between requests
            time.sleep(REQUEST_DELAY_SECONDS)

        return findings

    def _fetch_baseline(self, scan_unit: ScanUnit) -> str:
        """Fetch the page without any payload — used for comparison."""
        try:
            resp = self._session.get(
                scan_unit.url,
                params=scan_unit.params,
                timeout=10,
            )
            return resp.text
        except Exception as e:
            print(f"[executor] baseline fetch failed: {e}")
            return ""

    def _send(
        self,
        scan_unit: ScanUnit,
        test_case: TestCase,
    ) -> Tuple[Optional[str], dict]:
        """
        Inject the test payload into the target parameter and send the request.
        Returns (response_body, response_headers) or (None, {}) on failure.
        """
        try:
            # build params with payload injected
            params = dict(scan_unit.params)
            params[test_case.target_name] = test_case.payload

            resp = self._session.request(
                method=scan_unit.method,
                url=scan_unit.url,
                params=params if scan_unit.method == "GET" else None,
                data=params if scan_unit.method == "POST" else None,
                headers=scan_unit.headers,
                timeout=test_case.timeout,
            )
            return resp.text, dict(resp.headers)

        except requests.Timeout:
            print(f"[executor] timeout on {test_case.test_id}")
            return None, {}
        except Exception as e:
            print(f"[executor] request failed on {test_case.test_id}: {e}")
            return None, {}


# shared instance
executor = Executor()