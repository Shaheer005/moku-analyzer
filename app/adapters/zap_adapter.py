"""
OWASP ZAP adapter for active vulnerability scanning.

This adapter runs ZAP in command-line mode against a URL and parses the
result JSON report into Vulnerability objects.
"""

import json
import os
import subprocess
from typing import List
from app.adapters.base import BaseAdapter
from app.models.schemas import Vulnerability, Severity


class ZAPAdapter(BaseAdapter):
    """ZAP scanner adapter."""
    name = "zap"
    description = "OWASP ZAP — active web vulnerability scanner"

    def scan_url(self, url: str) -> List[Vulnerability]:
        """Run zap.sh quick scan and parse results."""
        output_file = "zap_results.json"

        cmd = ["zap.sh", "-cmd", "-quickurl", url, "-quickout", output_file]

        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=600)
        except FileNotFoundError:
            raise RuntimeError("ZAP executable not found. Install OWASP ZAP and ensure zap.sh is in PATH.")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"ZAP scan failed: {e.stderr or e.stdout}")
        except subprocess.TimeoutExpired:
            raise RuntimeError("ZAP scan timed out")

        if not os.path.exists(output_file):
            raise RuntimeError("ZAP output file not found after scan")

        with open(output_file, "r", encoding="utf-8") as f:
            try:
                report = json.load(f)
            except json.JSONDecodeError:
                raise RuntimeError("Failed to parse ZAP output JSON")

        # ZAP quick scan JSON can contain site/alerts with risk levels.
        vulns: List[Vulnerability] = []

        # Map common ZAP risk levels to our Severity enum
        severity_map = {
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
            "informational": Severity.INFO,
            "info": Severity.INFO,
        }

        site_alerts = report.get("site", [])
        for site in site_alerts:
            for alert in site.get("alerts", []):
                raw_risk = str(alert.get("risk", "info")).lower()
                severity = severity_map.get(raw_risk, Severity.INFO)

                vuln = Vulnerability(
                    **{
                        "type": alert.get("alert", "zap-alert"),
                        "severity": severity,
                        "description": alert.get("alert", "ZAP finding"),
                        "location": url,
                        "evidence": alert.get("evidence"),
                        "meta": {
                            "param": alert.get("param"),
                            "confidence": alert.get("confidence"),
                            "solution": alert.get("solution"),
                        },
                    }
                )
                vulns.append(vuln)

        return vulns

    def scan_html(self, html: str, source_url: str = "") -> List[Vulnerability]:
        """ZAP works on live URLs only."""
        return []
