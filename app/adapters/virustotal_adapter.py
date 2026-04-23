"""
VirusTotal adapter for URL reputation checks.

This adapter submits URLs to VirusTotal for analysis and then fetches the
analysis report, turning malicious vendor flags into Vulnerability objects.
"""

import os
import time
import requests
from typing import List
from app.adapters.base import BaseAdapter
from app.models.schemas import Vulnerability, Severity


class VirusTotalAdapter(BaseAdapter):
    """VirusTotal scanner adapter."""
    name = "virustotal"
    description = "VirusTotal — checks URL/domain against 90+ security vendor databases"

    def scan_url(self, url: str, cookies: dict = None) -> List[Vulnerability]:
        """Submit URL and parse analysis from VirusTotal API."""
        api_key = os.getenv("VIRUSTOTAL_API_KEY")
        if not api_key:
            raise RuntimeError("VIRUSTOTAL_API_KEY is not set in environment")

        headers = {"x-apikey": api_key}

        # Submit URL for scanning
        try:
            submit_resp = requests.post(
                "https://www.virustotal.com/api/v3/urls",
                headers=headers,
                data={"url": url},
                timeout=30,
            )
        except requests.RequestException as e:
            raise RuntimeError(f"VirusTotal submission request failed: {e}")

        if submit_resp.status_code not in (200, 201):
            error_msg = submit_resp.json().get("error", {}).get("message", submit_resp.text)
            raise RuntimeError(f"VirusTotal submit error {submit_resp.status_code}: {error_msg}")

        analysis_id = submit_resp.json().get("data", {}).get("id")
        if not analysis_id:
            raise RuntimeError("VirusTotal response missing analysis id")

        # Fetch analysis report (may require polling until ready)
        report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
        report_data = None

        for _ in range(10):
            try:
                report_resp = requests.get(report_url, headers=headers, timeout=30)
            except requests.RequestException as e:
                raise RuntimeError(f"VirusTotal report request failed: {e}")

            if report_resp.status_code != 200:
                err_msg = report_resp.json().get("error", {}).get("message", report_resp.text)
                raise RuntimeError(f"VirusTotal report error {report_resp.status_code}: {err_msg}")

            report_data = report_resp.json().get("data", {})
            status = report_data.get("attributes", {}).get("status")

            if status == "completed":
                break

            time.sleep(2)

        if report_data is None or report_data.get("attributes", {}).get("status") != "completed":
            raise RuntimeError("VirusTotal analysis did not complete in time")

        results = report_data.get("attributes", {}).get("results", {})

        vulnerabilities: List[Vulnerability] = []
        malicious_count = 0
        total_vendors = len(results)

        for vendor, detection in results.items():
            category = str(detection.get("category", "")).lower()
            if category in ("malicious", "suspicious"):
                malicious_count += 1
                vulnerabilities.append(
                    Vulnerability(
                        **{
                            "type": "malicious-url",
                            "severity": Severity.CRITICAL,
                            "description": f"Flagged as malicious by {vendor}: {category}",
                            "location": url,
                            "evidence": str(detection),
                            "meta": {
                                "vendor": vendor,
                                "result": detection,
                            },
                        }
                    )
                )

        # Add a summary finding
        vulnerabilities.append(
            Vulnerability(
                **{
                    "type": "virustotal-summary",
                    "severity": Severity.HIGH if malicious_count > 0 else Severity.INFO,
                    "description": f"{malicious_count}/{total_vendors} vendors labeled URL malicious/suspicious",
                    "location": url,
                    "evidence": None,
                    "meta": {
                        "malicious_count": malicious_count,
                        "total_vendors": total_vendors,
                    },
                }
            )
        )

        return vulnerabilities

    def scan_html(self, html: str, source_url: str = "", cookies: dict = None) -> List[Vulnerability]:
        """VirusTotal works on URLs only."""
        return []
