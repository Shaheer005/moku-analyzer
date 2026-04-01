"""
Built-in vulnerability scanner adapter.

This is a placeholder adapter that serves as the default scanner. It currently
returns no vulnerabilities but provides the framework for implementing custom
vulnerability detection logic in the future.
"""

from typing import List
from app.adapters.base import BaseAdapter
from app.models.schemas import Vulnerability


class BuiltinAdapter(BaseAdapter):
    """
    Placeholder for the reference vulnerability analyzer (Phase 2).
    Returns empty results for now so the full pipeline is testable end-to-end.
    Replace scan_url / scan_html with real checks in Phase 2.
    """
    name = "builtin"  # Registry name for this adapter

    def scan_url(self, url: str) -> List[Vulnerability]:
        """Scan a live URL for vulnerabilities (placeholder implementation)."""
        # Phase 2: fetch URL and run checks
        return []

    def scan_html(self, html: str, source_url: str = "") -> List[Vulnerability]:
        """Scan HTML content for vulnerabilities (placeholder implementation)."""
        # Phase 2: parse HTML and run checks
        return []
