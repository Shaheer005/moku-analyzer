"""Tests for the MockAdapter."""

import pytest
from app.adapters.mock_adapter import MockAdapter
from app.models.schemas import Severity


class TestMockAdapter:
    """Test MockAdapter functionality."""

    def setup_method(self):
        """Initialize MockAdapter for each test."""
        self.adapter = MockAdapter()

    def test_scan_url_returns_three_vulnerabilities(self):
        """MockAdapter.scan_url() should return exactly 3 vulnerabilities."""
        vulns = self.adapter.scan_url("http://example.com")
        assert len(vulns) == 3

    def test_scan_url_severity_levels(self):
        """Returned vulnerabilities should have correct severity levels."""
        vulns = self.adapter.scan_url("http://example.com")
        
        # Check severities
        severities = [v.severity for v in vulns]
        assert Severity.HIGH in severities
        assert Severity.MEDIUM in severities
        assert Severity.INFO in severities

    def test_scan_url_has_descriptions(self):
        """All vulnerabilities should have descriptions."""
        vulns = self.adapter.scan_url("http://example.com")
        for vuln in vulns:
            assert vuln.description is not None
            assert len(vuln.description) > 0

    def test_scan_url_has_types(self):
        """All vulnerabilities should have types."""
        vulns = self.adapter.scan_url("http://example.com")
        types = [v.vuln_type for v in vulns]
        assert "xss-reflected" in types
        assert "missing-hsts" in types
        assert "server-version-disclosure" in types

    def test_scan_html_returns_three_vulnerabilities(self):
        """MockAdapter.scan_html() should also return exactly 3 vulnerabilities."""
        vulns = self.adapter.scan_html("<html><body>test</body></html>")
        assert len(vulns) == 3

    def test_scan_html_severity_levels(self):
        """HTML scan should return correct severity levels."""
        vulns = self.adapter.scan_html("<html></html>")
        
        severities = [v.severity for v in vulns]
        assert Severity.HIGH in severities
        assert Severity.MEDIUM in severities
        assert Severity.INFO in severities

    def test_scan_html_with_source_url(self):
        """scan_html() should use source_url in location field."""
        source = "http://example.com/page"
        vulns = self.adapter.scan_html("<html></html>", source_url=source)
        
        for vuln in vulns:
            assert vuln.location == source

    def test_scan_html_without_source_url(self):
        """scan_html() should handle missing source_url."""
        vulns = self.adapter.scan_html("<html></html>")
        
        for vuln in vulns:
            assert vuln.location == ""

    def test_scan_url_includes_location(self):
        """Vulnerabilities should include the scanned URL as location."""
        url = "http://example.com/test"
        vulns = self.adapter.scan_url(url)
        
        for vuln in vulns:
            assert vuln.location == url

    def test_adapter_name(self):
        """Adapter should have correct name."""
        assert self.adapter.name == "mock"
