"""
Mock vulnerability scanner adapter for testing.

This adapter provides hardcoded vulnerability results for testing purposes.
It returns the same three vulnerabilities regardless of input, allowing
developers to test the scanning pipeline without needing real scanners
or external dependencies.
"""

from typing import List
from app.adapters.base import BaseAdapter
from app.models.schemas import Vulnerability, Severity


class MockAdapter(BaseAdapter):
    """Mock adapter that returns fixed vulnerability results for testing."""
    name = "mock"  # Registry name for this adapter

    def scan_url(self, url: str) -> List[Vulnerability]:
        """Return mock vulnerabilities for URL scanning."""
        return [
            Vulnerability(
                type="xss-reflected",  # Cross-site scripting vulnerability
                severity=Severity.HIGH,
                description="Reflected XSS found in search parameter",
                evidence="?q=<script>alert(1)</script>",  # Example attack vector
                location=url,  # Target URL where vulnerability was found
            ),
            Vulnerability(
                type="missing-hsts",  # Missing security header
                severity=Severity.MEDIUM,
                description="HTTP Strict Transport Security header not set",
                location=url,
            ),
            Vulnerability(
                type="server-version-disclosure",  # Information disclosure
                severity=Severity.INFO,
                description="Server version exposed in response headers",
                location=url,
            ),
        ]

    def scan_html(self, html: str, source_url: str = "") -> List[Vulnerability]:
        """Return mock vulnerabilities for HTML content scanning."""
        # Use source_url if provided, otherwise location is unknown
        location = source_url or ""
        return [
            Vulnerability(
                type="xss-reflected",
                severity=Severity.HIGH,
                description="Reflected XSS found in search parameter",
                evidence="?q=<script>alert(1)</script>",
                location=location,
            ),
            Vulnerability(
                type="missing-hsts",
                severity=Severity.MEDIUM,
                description="HTTP Strict Transport Security header not set",
                location=location,
            ),
            Vulnerability(
                type="server-version-disclosure",
                severity=Severity.INFO,
                description="Server version exposed in response headers",
                location=location,
            ),
        ]
