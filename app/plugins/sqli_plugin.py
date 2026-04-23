"""
SQLi Plugin — detects SQL Injection using boolean-differential technique.

Strategy (low false positives):
  Stage 1 DETECT  — send a TRUE condition payload (e.g. ' OR '1'='1)
                    and a FALSE condition (e.g. ' OR '1'='2).
                    If responses differ significantly = injection likely.
  Stage 2 CONFIRM — check response for SQL error messages as extra signal.

Why boolean-differential instead of error-based:
  Error-based breaks on hardened apps that suppress errors.
  Boolean differential works even when errors are hidden —
  the page content changes because the SQL query returns different rows.

No time-based (SLEEP) payloads by default — too aggressive and slow.
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


# SQL error patterns — if any appear in response, strong signal
SQL_ERROR_PATTERNS = [
    r"sql syntax.*mysql",
    r"warning.*mysql_",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"ora-\d{4,5}",           # Oracle errors
    r"sqlite3?\.",             # SQLite errors
    r"sqlstate\[",
    r"pg_query\(\)",           # PostgreSQL
    r"supplied argument is not a valid mysql",
    r"you have an error in your sql",
    r"microsoft.*odbc.*sql",
    r"jdbc\..*exception",
]


class SQLiPlugin(BasePlugin):
    name = "sqli"

    def generate_tests(self, scan_unit: ScanUnit) -> List[TestCase]:
        """
        Generate SQLi test cases for every injectable parameter.
        Each param gets:
          - a TRUE boolean payload
          - a FALSE boolean payload
          - an error-trigger payload
        """
        tests = []

        # collect testable parameters
        targets = {}
        if scan_unit.type == ScanUnitType.PARAM and scan_unit.parameter_name:
            targets[scan_unit.parameter_name] = scan_unit.sample_value or "1"
        else:
            targets.update(scan_unit.params)

        for param_name, sample_value in targets.items():
            marker = uuid.uuid4().hex[:8]

            # TRUE condition — should return normal/more results
            tests.append(TestCase(
                test_id=f"sqli-true-{param_name}-{marker}",
                plugin_name=self.name,
                injection_point=f"?{param_name}=",
                target_name=param_name,
                payload=f"{sample_value}' OR '1'='1",
                marker=marker,
                mode=TestMode.DETECT,
                timeout=10,
            ))

            # FALSE condition — should return empty/different results
            tests.append(TestCase(
                test_id=f"sqli-false-{param_name}-{marker}",
                plugin_name=self.name,
                injection_point=f"?{param_name}=",
                target_name=param_name,
                payload=f"{sample_value}' OR '1'='2",
                marker=marker,
                mode=TestMode.DETECT,
                timeout=10,
            ))

            # error trigger — single quote to provoke SQL error
            tests.append(TestCase(
                test_id=f"sqli-error-{param_name}-{marker}",
                plugin_name=self.name,
                injection_point=f"?{param_name}=",
                target_name=param_name,
                payload=f"{sample_value}'",
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
        Two detection signals:
        1. SQL error patterns in response body
        2. Response significantly different from baseline (boolean differential)
        """
        body_lower = response_body.lower()

        # Signal 1 — SQL error messages in response
        matched_error = None
        for pattern in SQL_ERROR_PATTERNS:
            match = re.search(pattern, body_lower)
            if match:
                matched_error = match.group(0)
                break

        # Signal 2 — boolean differential
        # TRUE response should be longer/different than FALSE response
        differential_detected = False
        if baseline_body and test_case.mode == TestMode.DETECT:
            size_diff = abs(len(response_body) - len(baseline_body))
            # if response differs by more than 20% from baseline = suspicious
            if len(baseline_body) > 0:
                diff_ratio = size_diff / len(baseline_body)
                if diff_ratio > 0.2:
                    differential_detected = True

        # no signal = no finding
        if not matched_error and not differential_detected:
            return None

        # build snippet
        if matched_error:
            idx = body_lower.find(matched_error[:20])
            snippet_start = max(0, idx - 100)
            snippet_end = min(len(response_body), idx + 300)
            snippet = response_body[snippet_start:snippet_end]
            matched_pattern = f"SQL error pattern detected: '{matched_error}'"
            confidence = 0.85   # error message = high confidence
        else:
            snippet = response_body[:500]
            matched_pattern = f"Boolean differential detected — response size differs significantly from baseline"
            confidence = 0.5    # differential alone = medium confidence

        # save evidence
        evidence_ref = evidence_store.save(
            data=f"PAYLOAD: {test_case.payload}\nRESPONSE SNIPPET:\n{snippet}",
            label=f"sqli_{test_case.mode.value}_response"
        )

        return Finding(
            finding_id=f"sqli-{uuid.uuid4().hex[:8]}",
            plugin=self.name,
            scan_unit_url=test_case.injection_point,
            http_method="GET",
            payload_used=test_case.payload,
            matched_pattern=matched_pattern,
            response_snippet=snippet[:2048],
            evidence_refs=[evidence_ref],
            confidence=confidence,
            repro_steps=[
                f"1. Send GET request to {test_case.injection_point}",
                f"2. Set parameter '{test_case.target_name}' = '{test_case.payload}'",
                f"3. Observe: {matched_pattern}",
            ],
            timestamp=datetime.utcnow(),
            notes=f"Signal: {'SQL error' if matched_error else 'boolean differential'}",
        )