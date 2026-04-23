"""
CSRF Plugin — detects missing Cross-Site Request Forgery protection on forms.

Strategy (heuristic only — no auto-submission of state-changing requests):
  - Parse HTML response for forms
  - Check each form for CSRF token fields
  - Check cookies for SameSite attribute
  - Report forms that accept POST with no token as vulnerable

Why heuristic only:
  Actually submitting state-changing requests (POST/DELETE) without
  permission is unethical and potentially illegal. We only inspect
  the form structure and headers — we never auto-submit.
"""
import uuid
import re
from typing import List, Optional
from datetime import datetime
from bs4 import BeautifulSoup

from app.plugins.base_plugin import BasePlugin
from app.core.scan_unit import ScanUnit, ScanUnitType
from app.core.test_case import TestCase, TestMode
from app.core.finding import Finding
from app.core.evidence_store import evidence_store


# common CSRF token field names to look for
CSRF_TOKEN_NAMES = [
    "csrf", "csrf_token", "csrftoken", "_token", "authenticity_token",
    "token", "nonce", "_csrf", "xsrf", "xsrf_token", "__requestverificationtoken"
]


class CSRFPlugin(BasePlugin):
    name = "csrf"

    def generate_tests(self, scan_unit: ScanUnit) -> List[TestCase]:
        """
        Generate one test case to fetch the page and inspect its forms.
        CSRF analysis happens in analyze_response — we just need the HTML.
        """
        return [TestCase(
            test_id=f"csrf-inspect-{uuid.uuid4().hex[:8]}",
            plugin_name=self.name,
            injection_point=scan_unit.url,
            target_name="forms",
            payload="",        # no payload — we just fetch and inspect
            mode=TestMode.DETECT,
            timeout=10,
        )]

    def analyze_response(
        self,
        test_case: TestCase,
        response_body: str,
        response_headers: dict,
        baseline_body: str = "",
    ) -> Optional[Finding]:
        """
        Parse HTML and check every POST form for CSRF token fields.
        Also check Set-Cookie headers for missing SameSite attribute.
        """
        findings_text = []
        soup = BeautifulSoup(response_body, "html.parser")

        # check all forms on the page
        forms = soup.find_all("form")
        vulnerable_forms = []

        for form in forms:
            method = form.get("method", "get").lower()
            action = form.get("action", test_case.injection_point)

            # only POST forms are CSRF-relevant
            if method != "post":
                continue

            # check if form has a CSRF token field
            inputs = form.find_all("input")
            input_names = [
                (i.get("name") or "").lower()
                for i in inputs
            ]

            has_token = any(
                any(token in name for token in CSRF_TOKEN_NAMES)
                for name in input_names
            )

            if not has_token:
                vulnerable_forms.append({
                    "action": action,
                    "inputs": [i.get("name") for i in inputs if i.get("name")]
                })
                findings_text.append(
                    f"POST form to '{action}' has no CSRF token field"
                )

        # check cookies for missing SameSite
        cookie_header = response_headers.get("Set-Cookie", "")
        if cookie_header and "samesite" not in cookie_header.lower():
            findings_text.append(
                "Set-Cookie header missing SameSite attribute"
            )

        # no issues found
        if not findings_text:
            return None

        snippet = "\n".join(findings_text)

        # save evidence
        evidence_ref = evidence_store.save(
            data=f"URL: {test_case.injection_point}\nFINDINGS:\n{snippet}",
            label="csrf_heuristic"
        )

        return Finding(
            finding_id=f"csrf-{uuid.uuid4().hex[:8]}",
            plugin=self.name,
            scan_unit_url=test_case.injection_point,
            http_method="GET",
            payload_used="(heuristic — no payload sent)",
            matched_pattern=findings_text[0],
            response_snippet=snippet[:2048],
            evidence_refs=[evidence_ref],
            confidence=0.6,
            repro_steps=[
                f"1. Visit {test_case.injection_point}",
                f"2. Inspect POST forms — no CSRF token present",
                f"3. A forged cross-origin POST request would be accepted",
            ],
            timestamp=datetime.utcnow(),
            notes=f"Found {len(vulnerable_forms)} vulnerable form(s). Heuristic only — no requests submitted.",
        )