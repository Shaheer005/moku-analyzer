"""
Data models and schemas for the moku-analyzer API.

This module defines Pydantic models that represent the data structures used
throughout the application. These models validate API requests and responses,
and match the expected format for communication with the Go backend service.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Any, Dict
from enum import Enum
import uuid


class ScanMethod(str, Enum):
    """Enumeration of available scanning methods."""
    HTML = "html"  # Scan HTML content directly
    URL  = "url"   # Scan a URL endpoint


class ScanStatus(str, Enum):
    """Enumeration of possible scan job statuses."""
    PENDING = "pending"  # Job submitted but not started
    RUNNING = "running"  # Scan is currently executing
    DONE    = "done"     # Scan completed successfully
    FAILED  = "failed"   # Scan failed with an error


class Severity(str, Enum):
    """Enumeration of vulnerability severity levels."""
    INFO     = "info"     # Informational finding
    LOW      = "low"      # Low-risk vulnerability
    MEDIUM   = "medium"   # Medium-risk vulnerability
    HIGH     = "high"     # High-risk vulnerability
    CRITICAL = "critical" # Critical-risk vulnerability


# ── matches Go's models.ScanRequest ──────────────────────────────────────────
class ScanRequest(BaseModel):
    """Request model for submitting a new scan job."""
    method:  ScanMethod
    html:    Optional[str] = None   # HTML content when method = "html"
    url:     Optional[str] = None   # URL to scan when method = "url"
    adapter: Optional[str] = None   # Scanner adapter to use (default: builtin)


# ── matches Go's models.Vulnerability ────────────────────────────────────────
class Vulnerability(BaseModel):
    """Model representing a single vulnerability finding."""
    vuln_type:   str            = Field(..., alias="type")  # Type of vulnerability
    severity:    Severity                                   # Severity level
    description: str                                        # Human-readable description
    evidence:    Optional[str]  = None                      # Proof of the vulnerability
    location:    Optional[str]  = None                      # Where it was found (URL/selector)
    meta:        Optional[Dict[str, Any]] = None            # Additional metadata

    class Config:
        populate_by_name = True  # Allow using field names instead of aliases


# ── matches Go's models.ScanResult ───────────────────────────────────────────
class ScanResult(BaseModel):
    """Model representing the result of a completed scan."""
    id:              str                    # Unique job identifier
    status:          ScanStatus             # Current job status
    vulnerabilities: List[Vulnerability] = []  # List of found vulnerabilities
    error:           Optional[str]       = None   # Error message if status is FAILED


# ── response for POST /scan ───────────────────────────────────────────────────
class SubmitResponse(BaseModel):
    """Response model for scan submission endpoint."""
    job_id: str  # The job ID to use for checking results
