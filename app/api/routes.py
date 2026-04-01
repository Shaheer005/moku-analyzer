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
    job_id = str(uuid.uuid4())
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
