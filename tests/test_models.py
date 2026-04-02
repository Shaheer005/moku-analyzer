"""Tests for Pydantic models and schemas."""

import pytest
from pydantic import ValidationError
from app.models.schemas import (
    ScanRequest, ScanResult, ScanStatus, Severity, Vulnerability
)


class TestScanRequest:
    """Test ScanRequest model validation."""

    def test_valid_url_request(self):
        """Valid URL scan request should pass."""
        req = ScanRequest(method="url", url="http://example.com")
        assert req.method == "url"
        assert req.url == "http://example.com"
        assert req.adapter is None

    def test_valid_html_request(self):
        """Valid HTML scan request should pass."""
        req = ScanRequest(method="html", html="<html></html>")
        assert req.method == "html"
        assert req.html == "<html></html>"

    def test_missing_method_fails(self):
        """Request without method should fail."""
        with pytest.raises(ValidationError):
            ScanRequest(url="http://example.com")

    def test_invalid_method_fails(self):
        """Invalid method value should fail."""
        with pytest.raises(ValidationError):
            ScanRequest(method="invalid", url="http://example.com")

    def test_url_request_without_url_allowed(self):
        """URL method request without url field should be created (validation in route)."""
        req = ScanRequest(method="url")
        assert req.url is None


class TestVulnerability:
    """Test Vulnerability model."""

    def test_valid_vulnerability(self):
        """Valid vulnerability should be accepted."""
        vuln = Vulnerability(
            type="xss",
            severity=Severity.HIGH,
            description="XSS vulnerability found",
            location="http://example.com/page"
        )
        assert vuln.vuln_type == "xss"
        assert vuln.severity == Severity.HIGH
        assert vuln.description == "XSS vulnerability found"

    def test_vulnerability_with_meta(self):
        """Vulnerability with metadata should work."""
        vuln = Vulnerability(
            type="cve-2023-1234",
            severity=Severity.CRITICAL,
            description="Critical vulnerability",
            meta={"cve_id": "CVE-2023-1234", "cvss": 9.8}
        )
        assert vuln.meta["cve_id"] == "CVE-2023-1234"

    def test_missing_required_fields_fails(self):
        """Missing required fields should fail."""
        with pytest.raises(ValidationError):
            Vulnerability(severity=Severity.HIGH)


class TestScanStatus:
    """Test ScanStatus enum."""

    def test_all_status_values_exist(self):
        """All expected status values should exist."""
        assert ScanStatus.PENDING.value == "pending"
        assert ScanStatus.RUNNING.value == "running"
        assert ScanStatus.DONE.value == "done"
        assert ScanStatus.FAILED.value == "failed"

    def test_status_from_string(self):
        """Status should be creatable from string."""
        status = ScanStatus("done")
        assert status == ScanStatus.DONE


class TestScanResult:
    """Test ScanResult model."""

    def test_valid_result_with_vulnerabilities(self):
        """Valid result with vulnerabilities."""
        result = ScanResult(
            id="test-id",
            status=ScanStatus.DONE,
            vulnerabilities=[
                Vulnerability(
                    type="xss",
                    severity=Severity.HIGH,
                    description="XSS found"
                )
            ]
        )
        assert result.id == "test-id"
        assert result.status == ScanStatus.DONE
        assert len(result.vulnerabilities) == 1

    def test_result_with_error(self):
        """Result with error message."""
        result = ScanResult(
            id="test-id",
            status=ScanStatus.FAILED,
            error="Scanner timeout"
        )
        assert result.status == ScanStatus.FAILED
        assert result.error == "Scanner timeout"

    def test_result_without_vulnerabilities(self):
        """Result can have empty vulnerabilities list."""
        result = ScanResult(
            id="test-id",
            status=ScanStatus.DONE,
            vulnerabilities=[]
        )
        assert len(result.vulnerabilities) == 0


class TestSeverity:
    """Test Severity enum."""

    def test_all_severity_levels(self):
        """All severity levels should exist."""
        severities = [
            (Severity.INFO, "info"),
            (Severity.LOW, "low"),
            (Severity.MEDIUM, "medium"),
            (Severity.HIGH, "high"),
            (Severity.CRITICAL, "critical"),
        ]
        for sev, value in severities:
            assert sev.value == value
