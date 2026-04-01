"""
Nuclei vulnerability scanner adapter.

This adapter integrates the Nuclei vulnerability scanner tool. Nuclei is a
fast vulnerability scanner that uses templates to detect various security
issues in web applications and network services.
"""

import subprocess
import re
from typing import List
from app.adapters.base import BaseAdapter
from app.models.schemas import Vulnerability, Severity

# Map nuclei severity strings to our internal Severity enum
SEVERITY_MAP = {
    "info":     Severity.INFO,
    "low":      Severity.LOW,
    "medium":   Severity.MEDIUM,
    "high":     Severity.HIGH,
    "critical": Severity.CRITICAL,
}


class NucleiAdapter(BaseAdapter):
    """Adapter for the Nuclei vulnerability scanner."""
    name = "nuclei"  # Registry name for this adapter

    def scan_url(self, url: str) -> List[Vulnerability]:
        """Run nuclei against a live URL and return parsed vulnerabilities."""
        try:
            # Execute nuclei as a subprocess with timeout
            result = subprocess.run(
                [
                    "nuclei",
                    "-u", url,        # Target URL to scan
                    "-silent",        # Suppress banner/progress, output text format
                ],
                capture_output=True,  # Capture stdout and stderr
                text=True,           # Return strings instead of bytes
                timeout=300,         # 5 minute timeout - nuclei can be slow
            )
        except FileNotFoundError:
            raise RuntimeError(
                "nuclei binary not found. Make sure nuclei is installed and in PATH."
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError("Nuclei scan timed out after 300 seconds.")

        return self._parse(result.stdout)

    def scan_html(self, html: str, source_url: str = "") -> List[Vulnerability]:
        """
        Nuclei works on live URLs, not raw HTML.
        If a source_url is available we fall back to scanning that URL.
        """
        if source_url:
            return self.scan_url(source_url)
        # Nothing we can do without a URL since nuclei needs live targets
        return []

    def _parse(self, output: str) -> List[Vulnerability]:
        """Parse nuclei's text output format into Vulnerability objects.

        Format: [template-id] [protocol] [severity] url/target [optional: results]
        Example: [apache-mod-negotiation-listing:exposed_files] [http] [low] http://scanme.nmap.org/index ["index.html"]
        """
        vulns = []

        # Regex pattern to parse nuclei output - results are optional
        pattern = r'^\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)\s*(.*)$'

        for line in output.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            match = re.match(pattern, line)
            if not match:
                # Skip lines that don't match format (like stats)
                continue

            try:
                template_id = match.group(1)    # Template identifier
                protocol = match.group(2)      # Protocol (http, dns, etc.)
                severity_str = match.group(3).lower()  # Severity level
                target = match.group(4)        # Target URL/IP
                results_str = match.group(5).strip() if match.group(5) else ""  # Optional results

                # Convert nuclei severity to our enum
                severity = SEVERITY_MAP.get(severity_str, Severity.INFO)

                # Create human-readable description from template ID
                description = template_id.replace('-', ' ').replace(':', ' ').title()

                # Create vulnerability object with parsed data
                vuln = Vulnerability(**{
                    "type": template_id,
                    "severity": severity,
                    "description": description,
                    "evidence": results_str if results_str else None,
                    "location": target,
                    "meta": {
                        "protocol": protocol,
                        "raw_line": line,  # Keep original line for debugging
                    }
                })
                vulns.append(vuln)

            except Exception as e:
                # Skip malformed lines and log the error
                print(f"[nuclei_adapter] Skipped parsing line: {e}")
                continue

        return vulns
