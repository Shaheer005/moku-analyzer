"""
moku-analyzer CLI — vulnerability scanner with database and reporting.
Reports are downloaded from API, not saved to project folder.
"""
import sys
import time
import requests
import os
from pathlib import Path
from app.core.database import db

API = "http://127.0.0.1:8080"
DOWNLOADS_FOLDER = str(Path.home() / "Downloads")


def scan(url, adapter="nuclei", cookies=None):
    """Run a scan and download report automatically."""
    print(f"\n[*] Scanning: {url}")
    print(f"[*] Using:    {adapter}")
    if cookies:
        print(f"[*] Cookies:  {cookies}")
    print("[*] Please wait...\n")

    # submit scan
    try:
        r = requests.post(f"{API}/scan", json={
            "method": "url",
            "url": url,
            "adapter": adapter,
            "cookies": cookies or {}
        })
        job_id = r.json()["job_id"]
    except Exception as e:
        print(f"[!] Could not connect to server. Is it running? (python run.py)")
        sys.exit(1)

    # poll until done
    for i in range(60):
        time.sleep(5)
        r2 = requests.get(f"{API}/scan/{job_id}")
        result = r2.json()
        status = result["status"]

        if status == "running":
            print(f"[*] scanning... ({(i+1)*5}s)", end="\r")

        elif status == "done":
            vulns = result["vulnerabilities"]
            print(f"\n[+] Scan complete!\n")

            if not vulns:
                print("[*] No vulnerabilities found.")
            else:
                print(f"[*] Found {len(vulns)} vulnerabilities:\n")
                for v in vulns:
                    sev = v['severity'].upper()
                    print(f"[{sev}] {v['type']}")
                    print(f"      {v['description']}")
                    if v.get('evidence'):
                        print(f"      Evidence: {v['evidence']}")
                    print()

            # Download CSV report
            download_report(job_id, "csv")

            # Ask for TXT
            if vulns:
                ans = input("[?] Also download as TXT? (y/n): ").lower()
                if ans == 'y':
                    download_report(job_id, "txt")

            print(f"\n[*] Scan ID: {job_id}")
            return

        elif status == "failed":
            print(f"\n[!] Scan failed: {result.get('error')}")
            return

    print("\n[!] Scan timed out.")


def download_report(scan_id: str, format: str = "csv"):
    """Download report from API and save to Downloads folder."""
    try:
        r = requests.get(f"{API}/scan/{scan_id}/download?format={format}")
        if r.status_code != 200:
            print(f"[!] Failed to download {format.upper()} report")
            return

        data = r.json()
        content = data['content']
        filename = data['filename']

        filepath = os.path.join(DOWNLOADS_FOLDER, filename)
        with open(filepath, 'w') as f:
            f.write(content)

        print(f"[+] {format.upper()} Report downloaded: {filepath}")
    except Exception as e:
        print(f"[!] Error downloading report: {e}")


def show_history():
    """Show all past scans."""
    try:
        r = requests.get(f"{API}/scans")
        scans = r.json().get('scans', [])
    except:
        from app.core.database import db
        scans = db.get_history()

    if not scans:
        print("[*] No scan history found.")
        return

    print("\n" + "=" * 100)
    print("SCAN HISTORY")
    print("=" * 100)
    print(f"{'Scan ID':<12} {'URL':<40} {'Scanner':<12} {'Date':<19} {'Issues':<8}")
    print("-" * 100)

    for scan in scans:
        url = scan['url'][:40] if len(scan['url']) > 40 else scan['url']
        print(f"{scan['id']:<12} {url:<40} {scan['adapter']:<12} {scan['timestamp']:<19} {scan['total_vulns']:<8}")

    print("=" * 100)
    print(f"Use: python scan.py --download <scan_id> [csv|txt] to download report\n")


def download_old_scan(scan_id: str, format: str = "csv"):
    """Download report for an old scan."""
    print(f"\n[*] Downloading {format.upper()} report for scan {scan_id}...")
    download_report(scan_id, format)


def export_all():
    """Export all scans to CSV."""
    try:
        from app.core.database import db
        filename = db.export_all_csv(os.path.join(DOWNLOADS_FOLDER, "all_scans_export.csv"))
        print(f"[+] Exported all scans to: {filename}")
    except Exception as e:
        print(f"[!] Error exporting: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scan.py <url> [adapter]")
        print("       python scan.py https://target.com")
        print("       python scan.py https://target.com nuclei")
        print("\nCommands:")
        print("       python scan.py --history                    (show all past scans)")
        print("       python scan.py --download <id> [csv|txt]   (download old scan report)")
        print("       python scan.py --export-all                (export all scans)")
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "--history":
        show_history()
    elif cmd == "--download":
        if len(sys.argv) < 3:
            print("Usage: python scan.py --download <scan_id> [csv|txt]")
            sys.exit(1)
        scan_id = sys.argv[2]
        format = sys.argv[3] if len(sys.argv) > 3 else "csv"
        download_old_scan(scan_id, format)
    elif cmd == "--export-all":
        export_all()
    else:
        url = cmd
        adapter = sys.argv[2] if len(sys.argv) > 2 else "nuclei"
        scan(url, adapter)