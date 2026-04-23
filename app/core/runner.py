"""
Background job execution for vulnerability scans.

This module handles the actual execution of scan jobs in background threads.
It coordinates between the job store, adapter registry, and individual scanner
adapters to perform vulnerability scans asynchronously.
"""

from app.core.job_store import job_store
from app.adapters.registry import registry
from app.models.schemas import ScanRequest, ScanResult, ScanStatus

# Default adapter to use if none is specified in the request
DEFAULT_ADAPTER = "builtin"


def run_scan_job(job_id: str, request: ScanRequest) -> None:
    """
    Runs in a background thread (via FastAPI BackgroundTasks).

    Flow:
      1. Mark job as RUNNING
      2. Pick the adapter (from request, or default)
      3. Call adapter.scan()
      4. Store results → mark DONE (or FAILED on error)
    """

    # Step 1: Update job status to RUNNING
    result = job_store.get(job_id)
    result.status = ScanStatus.RUNNING
    job_store.update(result)

    try:
        # Step 2: Select the scanner adapter to use
        adapter_name = request.adapter or DEFAULT_ADAPTER
        adapter = registry.get(adapter_name)

        # Step 3: Execute the scan using the selected adapter
        vulns = adapter.scan(
            method=request.method,
            html=request.html,
            url=request.url,
            cookies=request.cookies,
        )

        # Step 4: Store successful results and mark as DONE
        result.vulnerabilities = vulns
        result.status = ScanStatus.DONE

    except KeyError as e:
        # Handle case where requested adapter doesn't exist
        result.status  = ScanStatus.FAILED
        result.error   = str(e)

    except Exception as e:
        # Handle any other scan errors
        result.status  = ScanStatus.FAILED
        result.error   = f"Scan failed: {str(e)}"

    finally:
        # Always update the job store with final status
        job_store.update(result)
