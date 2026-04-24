"""
API routes and endpoints for the moku-analyzer service.

This module defines the REST API endpoints that clients use to interact with
the vulnerability scanning service. It handles scan submission, result retrieval,
and health checks.
"""

from fastapi import APIRouter, BackgroundTasks, HTTPException
from app.models.schemas import ScanRequest, ScanResult, SubmitResponse
from app.core.job_store import job_store
from app.core.runner import run_scan_job
from app.adapters.registry import registry
import uuid

# Create the API router that will be mounted in the main FastAPI app
router = APIRouter()


@router.post("/scan", response_model=SubmitResponse, status_code=202)
async def submit_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Submit a new scan job.
    Returns a job_id immediately — client polls GET /scan/{id} for results.
    Matches Go client's SubmitScan().
    """
    # Validate the request based on the scan method
    if request.method == "url" and not request.url:
        raise HTTPException(status_code=400, detail="url is required when method is 'url'")
    if request.method == "html" and not request.html:
        raise HTTPException(status_code=400, detail="html is required when method is 'html'")

    # Generate a unique job ID and create a job record
    from app.core.database import db
    job_id = db.get_next_scan_id()
    job_store.create(job_id)

    # Start the scan in the background so the API returns immediately
    background_tasks.add_task(run_scan_job, job_id, request)

    return SubmitResponse(job_id=job_id)


@router.get("/scan/{job_id}", response_model=ScanResult)
async def get_scan(job_id: str):
    """
    Poll for scan results.
    Returns status: pending | running | done | failed.
    Matches Go client's GetScan().
    """
    # Retrieve the job result from storage
    result = job_store.get(job_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Job '{job_id}' not found")
    return result


@router.get("/")
async def root():
    """
    Root endpoint for browser checks.
    """
    return {
        "status": "ok",
        "service": "moku-analyzer",
    }


@router.get("/health")
async def health():
    """
    Health check endpoint that shows service status and available adapters.
    """
    return {
        "status":   "ok",
        "adapters": registry.available(),  # List of registered scanner adapters
    }


@router.get("/adapters")
async def list_adapters():
    """List all registered scanner adapters."""
    return {
        "status": "ok",
        "adapters": registry.available(),
    }


@router.get("/scans")
async def get_scans():
    """Get all scan history."""
    from app.core.database import db
    scans = db.get_history()
    return {"scans": scans}


@router.get("/scan/{job_id}/download")
async def download_scan(job_id: str, format: str = "csv"):
    """Download scan report as CSV or TXT."""
    from app.core.database import db
    from app.core.report_generator import ReportGenerator

    scan, vulns = db.get_scan_with_vulns(job_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    generator = ReportGenerator(scan['url'], scan['adapter'], job_id)

    if format.lower() == "txt":
        content = generator.generate_txt(scan, vulns)
        return {
            "content": content,
            "filename": f"{job_id}.txt",
            "format": "text/plain"
        }
    else:  # csv default
        content = generator.generate_csv(vulns)
        return {
            "content": content,
            "filename": f"{job_id}.csv",
            "format": "text/csv"
        }
