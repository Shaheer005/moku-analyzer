"""
Base adapter class for vulnerability scanners.

This module defines the abstract base class that all vulnerability scanner
adapters must implement. It provides a common interface for different scanning
tools while allowing each adapter to handle URLs and HTML content differently.
"""

from abc import ABC, abstractmethod
from typing import List
from app.models.schemas import Vulnerability, ScanMethod


class BaseAdapter(ABC):
    """
    Every vulnerability scanner adapter must extend this class.

    The contract is simple:
      - receive either a URL string or raw HTML string
      - return a list of Vulnerability objects

    Moku's Go client doesn't care which adapter runs —
    it only sees the ScanResult at the API layer.
    """

    # Set this in every subclass — used as the registry key for adapter lookup
    name: str = "base"

    @abstractmethod
    def scan_url(self, url: str, cookies: dict = None) -> List[Vulnerability]:
        """Run a scan against a live URL. Return found vulnerabilities."""
        ...

    @abstractmethod
    def scan_html(self, html: str, source_url: str = "", cookies: dict = None) -> List[Vulnerability]:
        """Run a scan against raw HTML content. Return found vulnerabilities."""
        ...

    def scan(self, method: ScanMethod, html: str = None, url: str = None, cookies: dict = None) -> List[Vulnerability]:
        """
        Dispatch to the right scan method based on the request.
        Adapters don't need to override this — just implement scan_url / scan_html.
        """
        if method == ScanMethod.URL and url:
            return self.scan_url(url, cookies)
        elif method == ScanMethod.HTML and html:
            return self.scan_html(html, source_url=url or "", cookies=cookies)
        else:
            raise ValueError(f"Invalid scan method or missing payload: method={method}, url={url}, html={'<set>' if html else None}")
