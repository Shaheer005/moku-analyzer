"""
Nikto web vulnerability scanner adapter.

This adapter integrates the Nikto web server scanner. Nikto is a comprehensive
web server scanner that performs comprehensive tests against web servers for
multiple items including potentially dangerous files and programs.
"""

import subprocess
from typing import List
from app.adapters.base import BaseAdapter
from app.models.schemas import Vulnerability, Severity


class NiktoAdapter(BaseAdapter):
    """
    Adapter for Nikto web vulnerability scanner.
    Runs Nikto scans on URLs and parses the output.
    """
    name = "nikto"  # Registry name for this adapter

    def scan_url(self, url: str, cookies: dict = None) -> List[Vulnerability]:
        """
        Scan a URL using Nikto.
        """
        try:
            # Execute nikto as a subprocess
            result = subprocess.run(
                ["nikto", "-h", url, "-nointeractive"],  # -h for host, -nointeractive for batch mode
                capture_output=True,  # Capture stdout and stderr
                text=True,           # Return strings instead of bytes
                timeout=120,         # 2 minute timeout
            )
            return self._parse(result.stdout, url)
        except subprocess.TimeoutExpired:
            raise RuntimeError("Nikto scan timed out after 120 seconds.")
        except FileNotFoundError:
            raise RuntimeError(
                "nikto binary not found. Make sure nikto is installed and in PATH."
            )

    def scan_html(self, html: str, source_url: str = "", cookies: dict = None) -> List[Vulnerability]:
        """
        Nikto works on live URLs, not raw HTML.
        If a source_url is available we fall back to scanning that URL.
        """
        if source_url:
            return self.scan_url(source_url)
        # Nothing we can do without a URL since nikto needs live targets
        return []

    def _parse(self, output: str, url: str) -> List[Vulnerability]:
        """
        Parse nikto's output into Vulnerability objects.
        Lines starting with + are findings.
        """
        vulns = []

        for line in output.strip().splitlines():
            line = line.strip()
            # Nikto findings start with "+" character
            if line.startswith("+"):
                try:
                    # Create vulnerability object for each finding
                    vuln = Vulnerability(**{
                        "type": "nikto-finding",  # Generic type for nikto findings
                        "severity": Severity.INFO,  # Default to info level
                        "description": line,       # Use the full line as description
                        "location": url,           # Target URL
                        "meta": {
                            "raw_line": line,      # Keep original line for reference
                        }
                    })
                    vulns.append(vuln)
                except Exception as e:
                    # Skip malformed lines and log error
                    print(f"[nikto_adapter] Skipped parsing line: {e}")
                    continue

        return vulns
