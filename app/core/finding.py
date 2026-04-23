"""
Finding — a confirmed vulnerability with full evidence chain.
Every finding references immutable sha256 evidence blobs.
This is the auditable output of the dynamic analyzer.
"""
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum

class EvidenceRef(BaseModel):
    sha256:   str        # hash of the raw request/response blob
    size:     int        # bytes
    path:     str        # filesystem path to the blob
    label:    str        # e.g. "detect_request", "confirm_response"

class Finding(BaseModel):
    finding_id:        str
    plugin:            str              # which plugin found this
    scan_unit_url:     str              # target URL
    http_method:       str
    payload_used:      str              # exact payload that triggered it
    matched_pattern:   str              # what in the response confirmed it
    response_snippet:  str              # ≤ 2KB of relevant response
    evidence_refs:     List[EvidenceRef] = []
    confidence:        float            # 0.0 – 1.0
    scoring_version:   str = "v1"
    repro_steps:       List[str] = []   # human-readable steps to reproduce
    timestamp:         datetime = None
    notes:             Optional[str] = None
    meta:              Dict[str, Any] = {}