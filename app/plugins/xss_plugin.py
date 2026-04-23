"""
XSS Plugin — detects reflected Cross-Site Scripting.

Strategy (multi-stage, low false positives):
  Stage 1 DETECT  — inject a unique marker string, check if it reflects
                     unescaped in the response body.
  Stage 2 CONFIRM — inject a second variant payload, confirm reflection.

Why markers instead of real payloads:
  A unique random string like xssABC123 is safe to send and if it
  appears unescaped in the response we know reflection is happening.
  Only then do we send a real XSS payload to confirm exploitability.
"""
import uuid
import re
from typing import List, Optional
from datetime import datetime

from app.plugins.base_plugin import BasePlugin
from app.core.scan_unit import ScanUnit, ScanUnitType
from app.core.test_case import TestCase, TestMode
from app.core.finding import Finding
from app.core.evidence_store import evidence_store


class XSSPlugin(BasePlugin):
    name = "xss"

    def generate_tests(self, scan_unit: ScanUnit) -> List[TestCase]:
        """
        Generate XSS test cases for every injectable parameter.
        Each param gets a DETECT test first.
        """
        tests = []

        # collect all testable parameters
        targets = {}

        if scan_unit.type == ScanUnitType.PARAM and scan_unit.parameter_name:
            # single param scan
            targets[scan_unit.parameter_name] = scan_unit.sample_value or ""
        else:
            # URL scan — test all query params
            targets.update(scan_unit.params)

        for param_name, sample_value in targets.items():
            marker = f"xss{uuid.uuid4().hex[:8]}"   # unique per test

            # Stage 1 — detect: inject marker, look for unescaped reflection
            tests.append(TestCase(
                test_id=f"xss-detect-{param_name}-{marker[:6]}",
                plugin_name=self.name,
                injection_point=f"?{param_name}=",
                target_name=param_name,
                payload=f"<{marker}>",
                marker=marker,
                mode=TestMode.DETECT,
                timeout=10,
            ))

            # Stage 2 — confirm: real XSS payload
            tests.append(TestCase(
                test_id=f"xss-confirm-{param_name}-{marker[:6]}",
                plugin_name=self.name,
                injection_point=f"?{param_name}=",
                target_name=param_name,
                payload=f'"><script>alert("{marker}")</script>',
                marker=marker,
                mode=TestMode.CONFIRM,
                timeout=10,
            ))

        return tests

    def analyze_response(
        self,
        test_case: TestCase,
        response_body: str,
        response_headers: dict,
        baseline_body: str = "",
    ) -> Optional[Finding]:
        """
        Check if the marker appears unescaped in the response.
        Unescaped means the < and > are NOT converted to &lt; &gt;
        """
        if not test_case.marker:
            return None

        marker = test_case.marker

        # look for unescaped marker in response
        if test_case.mode == TestMode.DETECT:
            # check for <marker> appearing literally (unescaped)
            if f"<{marker}>" not in response_body:
                return None
            # make sure it's not just escaped HTML
            if f"&lt;{marker}&gt;" in response_body:
                return None

        elif test_case.mode == TestMode.CONFIRM:
            # check for the script tag appearing in response
            if marker not in response_body:
                return None
            if "script" not in response_body.lower():
                return None

        # get snippet around the marker for evidence
        idx = response_body.find(marker)
        snippet_start = max(0, idx - 100)
        snippet_end   = min(len(response_body), idx + 200)
        snippet = response_body[snippet_start:snippet_end]

        # save evidence
        evidence_ref = evidence_store.save(
            data=f"PAYLOAD: {test_case.payload}\nRESPONSE SNIPPET:\n{snippet}",
            label=f"xss_{test_case.mode.value}_response"
        )

        # confidence: detect=0.4, confirm=0.85
        confidence = 0.4 if test_case.mode == TestMode.DETECT else 0.85

        return Finding(
            finding_id=f"xss-{uuid.uuid4().hex[:8]}",
            plugin=self.name,
            scan_unit_url=test_case.injection_point,
            http_method="GET",
            payload_used=test_case.payload,
            matched_pattern=f"Unescaped marker <{marker}> found in response",
            response_snippet=snippet[:2048],
            evidence_refs=[evidence_ref],
            confidence=confidence,
            repro_steps=[
                f"1. Send GET request to {test_case.injection_point}",
                f"2. Set parameter '{test_case.target_name}' = '{test_case.payload}'",
                f"3. Observe unescaped reflection in response body",
            ],
            timestamp=datetime.utcnow(),
            notes=f"Stage: {test_case.mode.value}. Marker: {marker}",
        )