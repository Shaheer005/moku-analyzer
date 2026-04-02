"""Tests for the JobStore."""

import pytest
import threading
from app.core.job_store import JobStore
from app.models.schemas import ScanResult, ScanStatus, Vulnerability, Severity


class TestJobStore:
    """Test JobStore operations."""

    def setup_method(self):
        """Create a fresh JobStore for each test."""
        self.store = JobStore()

    def test_create_job(self):
        """Creating a job should return a ScanResult with pending status."""
        self.store.create("test-job-1")
        result = self.store.get("test-job-1")
        assert result is not None
        assert result.id == "test-job-1"
        assert result.status == ScanStatus.PENDING

    def test_get_nonexistent_returns_none(self):
        """Getting a non-existent job should return None."""
        result = self.store.get("nonexistent-job")
        assert result is None

    def test_update_job(self):
        """Updating a job should persist the changes."""
        self.store.create("test-job-2")
        result = self.store.get("test-job-2")
        result.status = ScanStatus.RUNNING
        result.vulnerabilities = [
            Vulnerability(
                type="xss",
                severity=Severity.HIGH,
                description="XSS found"
            )
        ]
        self.store.update(result)
        
        updated = self.store.get("test-job-2")
        assert updated.status == ScanStatus.RUNNING
        assert len(updated.vulnerabilities) == 1

    def test_thread_safety_concurrent_creates(self):
        """Creating jobs concurrently should not cause errors."""
        created_ids = []
        errors = []

        def create_many(start_id):
            try:
                for i in range(10):
                    job_id = f"job-{start_id}-{i}"
                    self.store.create(job_id)
                    created_ids.append(job_id)
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=create_many, args=(i,))
            for i in range(3)
        ]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert len(created_ids) == 30  # 10 jobs × 3 threads

        # Verify all jobs exist
        for job_id in created_ids:
            result = self.store.get(job_id)
            assert result is not None
            assert result.id == job_id

    def test_update_sets_id_if_missing(self):
        """Update should work for jobs created independently."""
        result = ScanResult(
            id="manual-job",
            status=ScanStatus.DONE,
            vulnerabilities=[]
        )
        self.store.update(result)
        
        retrieved = self.store.get("manual-job")
        assert retrieved is not None
        assert retrieved.status == ScanStatus.DONE
