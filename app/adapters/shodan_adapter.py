"""
Shodan adapter for passive reconnaissance.

This adapter queries the Shodan Host API for the target IP and converts
open ports/services and CVE findings into Vulnerability objects.
"""

import os
import socket
import requests
from typing import List
from app.adapters.base import BaseAdapter
from app.models.schemas import Vulnerability, Severity


class ShodanAdapter(BaseAdapter):
    """Shodan scanner adapter."""
    name = "shodan"
    description = "Shodan — passive reconnaissance using Shodan's internet scan database"

    def scan_url(self, url: str) -> List[Vulnerability]:
        """Scan a URL by resolving hostname and querying Shodan host info."""
        api_key = os.getenv("SHODAN_API_KEY")
        if not api_key:
            raise RuntimeError("SHODAN_API_KEY is not set in environment")

        # Resolve hostname to IP
        try:
            hostname = url.split("://")[-1].split("/")[0]
            ip = socket.gethostbyname(hostname)
        except socket.gaierror as e:
            raise RuntimeError(f"Failed to resolve hostname: {e}")

        shodan_url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"

        try:
            resp = requests.get(shodan_url, timeout=30)
        except requests.RequestException as e:
            raise RuntimeError(f"Shodan API request failed: {e}")

        if resp.status_code != 200:
            # Graceful API error handling
            exc = resp.json().get("error", resp.text)
            raise RuntimeError(f"Shodan API error {resp.status_code}: {exc}")

        data = resp.json()
        vulns: List[Vulnerability] = []

        # Open ports and service info
        for service in data.get("data", []):
            port = service.get("port")
            product = service.get("product") or "unknown"
            vuln = Vulnerability(
                **{
                    "type": "open-port",
                    "severity": Severity.INFO,
                    "description": f"Open port: {port} running {product}",
                    "location": url,
                    "evidence": f"{port}/{product}",
                    "meta": {
                        "ip": ip,
                        "hostnames": data.get("hostnames", []),
                        "service_raw": service,
                    },
                }
            )
            vulns.append(vuln)

        # Known CVEs
        for item in data.get("vulns", {}).keys() if isinstance(data.get("vulns"), dict) else []:
            vuln = Vulnerability(
                **{
                    "type": item,
                    "severity": Severity.HIGH,
                    "description": f"Known CVE detected by Shodan: {item}",
                    "location": url,
                    "evidence": None,
                    "meta": {
                        "ip": ip,
                    },
                }
            )
            vulns.append(vuln)

        return vulns

    def scan_html(self, html: str, source_url: str = "") -> List[Vulnerability]:
        """Shodan works on URLs only."""
        return []
