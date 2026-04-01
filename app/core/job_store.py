"""
In-memory job storage for scan results.

This module provides thread-safe storage for scan job results. It uses a simple
dictionary for now but can be easily replaced with Redis or a database later
without changing the interface used by other parts of the application.
"""

import threading
from typing import Dict, Optional
from app.models.schemas import ScanResult, ScanStatus


class JobStore:
    """
    Thread-safe in-memory store for scan jobs.
    Simple dict now — swap for Redis later without changing the interface.
    """

    def __init__(self):
        self._jobs: Dict[str, ScanResult] = {}  # Dictionary to store job results by ID
        self._lock = threading.Lock()           # Lock for thread safety during concurrent access

    def create(self, job_id: str) -> ScanResult:
        """Create a new job with PENDING status and store it."""
        result = ScanResult(id=job_id, status=ScanStatus.PENDING)
        with self._lock:  # Thread-safe update
            self._jobs[job_id] = result
        return result

    def get(self, job_id: str) -> Optional[ScanResult]:
        """Retrieve a job result by its ID."""
        with self._lock:  # Thread-safe read
            return self._jobs.get(job_id)

    def update(self, result: ScanResult) -> None:
        """Update an existing job result."""
        with self._lock:  # Thread-safe update
            self._jobs[result.id] = result

    def all_ids(self):
        """Get a list of all job IDs currently stored."""
        with self._lock:  # Thread-safe read
            return list(self._jobs.keys())


# Single shared instance used across the entire application
job_store = JobStore()
