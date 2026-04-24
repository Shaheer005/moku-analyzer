"""
ReportGenerator — generates CSV and TXT reports from vulnerability data.
Returns strings, does not save to disk.
"""
from typing import List, Dict


class ReportGenerator:
    def __init__(self, url: str, adapter: str, scan_id: str = ""):
        self.url = url
        self.adapter = adapter
        self.scan_id = scan_id

    def generate_csv(self, vulnerabilities: List[Dict]) -> str:
        """Generate CSV content as string."""
        lines = []
        lines.append("Severity,Vulnerability Type,Description,Evidence,Location,Confidence")

        for v in vulnerabilities:
            severity = v.get('severity', '').upper()
            vuln_type = v.get('type', '')
            description = v.get('description', '').replace(',', ';')
            evidence = str(v.get('evidence', '')).replace(',', ';')
            location = str(v.get('location', '')).replace(',', ';')
            confidence = v.get('confidence', 'N/A')

            lines.append(f'{severity},{vuln_type},{description},{evidence},{location},{confidence}')

        return "\n".join(lines)

    def generate_txt(self, scan_data: Dict, vulnerabilities: List[Dict]) -> str:
        """Generate TXT report as string."""
        lines = []
        lines.append("=" * 80)
        lines.append("VULNERABILITY SCAN REPORT")
        lines.append("=" * 80)
        lines.append("")
        lines.append(f"Target URL:     {self.url}")
        lines.append(f"Scanner:        {self.adapter}")
        lines.append(f"Scan ID:        {self.scan_id}")
        lines.append(f"Scan Date:      {scan_data.get('timestamp', 'N/A')}")
        lines.append(f"Total Issues:   {scan_data.get('total_vulns', 0)}")
        lines.append(f"  Critical:     {scan_data.get('critical_count', 0)}")
        lines.append(f"  High:         {scan_data.get('high_count', 0)}")
        lines.append(f"  Medium:       {scan_data.get('medium_count', 0)}")
        lines.append(f"  Low:          {scan_data.get('low_count', 0)}")
        lines.append(f"  Info:         {scan_data.get('info_count', 0)}")
        lines.append("=" * 80)
        lines.append("")

        if not vulnerabilities:
            lines.append("[*] No vulnerabilities found.")
        else:
            by_severity = {}
            for v in vulnerabilities:
                sev = v.get('severity', 'info').upper()
                if sev not in by_severity:
                    by_severity[sev] = []
                by_severity[sev].append(v)

            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                if sev in by_severity:
                    count = len(by_severity[sev])
                    lines.append(f"\n{sev} SEVERITY ({count} found)")
                    lines.append("-" * 80)
                    for v in by_severity[sev]:
                        lines.append(f"\n  Type:       {v.get('type', 'N/A')}")
                        lines.append(f"  Desc:       {v.get('description', 'N/A')}")
                        if v.get('evidence'):
                            lines.append(f"  Evidence:   {v['evidence']}")
                        if v.get('confidence'):
                            lines.append(f"  Confidence: {v['confidence']}")

        lines.append("\n" + "=" * 80)
        lines.append("END OF REPORT")
        lines.append("=" * 80)

        return "\n".join(lines)