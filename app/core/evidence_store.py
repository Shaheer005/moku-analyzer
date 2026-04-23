"""
EvidenceStore — saves raw request/response blobs to disk.
Uses sha256 content addressing — same content = same hash = stored once.
Findings reference blobs by hash, not by copy.
"""
import hashlib
import os
from app.core.finding import EvidenceRef

EVIDENCE_DIR = "evidence"   # folder in project root

class EvidenceStore:
    def __init__(self, base_dir: str = EVIDENCE_DIR):
        self.base_dir = base_dir
        os.makedirs(base_dir, exist_ok=True)

    def save(self, data: str, label: str) -> EvidenceRef:
        """
        Save a blob (request or response text) to disk.
        Returns an EvidenceRef with sha256 hash and path.
        """
        raw = data.encode("utf-8")
        sha = hashlib.sha256(raw).hexdigest()
        path = os.path.join(self.base_dir, sha)

        if not os.path.exists(path):
            with open(path, "wb") as f:
                f.write(raw)

        return EvidenceRef(
            sha256=sha,
            size=len(raw),
            path=path,
            label=label,
        )

    def load(self, sha256: str) -> str:
        """Load a blob by its sha256 hash."""
        path = os.path.join(self.base_dir, sha256)
        if not os.path.exists(path):
            raise FileNotFoundError(f"Evidence blob not found: {sha256}")
        with open(path, "rb") as f:
            return f.read().decode("utf-8")

# single shared instance
evidence_store = EvidenceStore()