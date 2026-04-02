"""Tests for API routes."""

import pytest
import json
import time
from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    """Create a test client for the FastAPI app."""
    # Import here to avoid import-time issues
    import main
    return TestClient(main.app)


class TestRoutes:
    """Test API endpoints."""

    def test_health_endpoint(self, client):
        """GET /health should return 200 with status ok."""
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert "adapters" in data
        assert isinstance(data["adapters"], list)

    def test_adapters_endpoint(self, client):
        """GET /adapters should return adapter list."""
        response = client.get("/adapters")
        assert response.status_code == 200
        data = response.json()
        assert "adapters" in data

    def test_post_scan_with_mock_adapter(self, client):
        """POST /scan with mock adapter should return 202 with job_id."""
        payload = {
            "method": "url",
            "url": "http://example.com",
            "adapter": "mock"
        }
        response = client.post("/scan", json=payload)
        assert response.status_code == 202
        data = response.json()
        assert "job_id" in data
        assert len(data["job_id"]) > 0

    def test_get_scan_result(self, client):
        """GET /scan/{id} should return the job result."""
        # First, submit a scan
        payload = {
            "method": "url",
            "url": "http://example.com",
            "adapter": "mock"
        }
        response = client.post("/scan", json=payload)
        job_id = response.json()["job_id"]
        
        # Then get the result
        response = client.get(f"/scan/{job_id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == job_id
        assert data["status"] in ["pending", "running", "done"]

    def test_post_scan_missing_url_returns_400(self, client):
        """POST /scan without url when method=url should fail."""
        payload = {
            "method": "url"
        }
        response = client.post("/scan", json=payload)
        assert response.status_code == 400

    def test_post_scan_missing_html_returns_400(self, client):
        """POST /scan without html when method=html should fail."""
        payload = {
            "method": "html"
        }
        response = client.post("/scan", json=payload)
        assert response.status_code == 400

    def test_post_scan_missing_method_returns_422(self, client):
        """POST /scan without method should return 422."""
        payload = {
            "url": "http://example.com"
        }
        response = client.post("/scan", json=payload)
        assert response.status_code == 422

    def test_post_scan_with_unknown_adapter_eventually_fails(self, client):
        """POST /scan with unknown adapter should eventually return failed status."""
        payload = {
            "method": "url",
            "url": "http://example.com",
            "adapter": "nonexistent_adapter"
        }
        response = client.post("/scan", json=payload)
        assert response.status_code == 202
        job_id = response.json()["job_id"]
        
        # Poll until done or failed (with timeout)
        for _ in range(50):
            response = client.get(f"/scan/{job_id}")
            data = response.json()
            if data["status"] in ["done", "failed"]:
                assert data["status"] == "failed"
                return
            time.sleep(0.1)
        
        # Should have failed by now
        pytest.fail("Scan did not fail within timeout")

    def test_get_nonexistent_job(self, client):
        """GET /scan with nonexistent job_id should return 404."""
        response = client.get("/scan/nonexistent-job-id-12345")
        assert response.status_code == 404

    def test_root_endpoint(self, client):
        """GET / should return service info."""
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
