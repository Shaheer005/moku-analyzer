"""
moku-analyzer CLI — vulnerability scanner with database and reporting.
Reports are downloaded from API, not saved to project folder.
"""
import sys
import time
import requests
import os
from pathlib import Path
from colorama import init, Fore, Back, Style
from app.core.cli_display import (
    print_banner, print_menu, print_adapters, print_scanning,
    print_results, print_history_table, print_success,
    print_error, print_info, print_status, get_input
)

init(autoreset=True)

API = "http://127.0.0.1:8080"
DOWNLOADS_FOLDER = str(Path.home() / "Downloads")


def scan(url, adapter="builtin", cookies=None):
    """Run a scan and download report automatically."""
    print_scanning(url, adapter)

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
        print_error("Could not connect to server. Is it running? (python run.py)")
        sys.exit(1)

    # poll until done
    for i in range(60):
        time.sleep(5)
        r2 = requests.get(f"{API}/scan/{job_id}")
        result = r2.json()
        status = result["status"]

        if status == "running":
            print(f"  {Fore.YELLOW}Scanning... ({(i+1)*5}s){Style.RESET_ALL}", end="\r")

        elif status == "done":
            vulns = result["vulnerabilities"]
            print_results(vulns)

            # Download CSV report
            download_report(job_id, "csv")
            print_success(f"CSV report downloaded")

            # Ask for TXT
            if vulns:
                ans = get_input("Also download as TXT (y/n)") or "n"
                if ans.lower() == 'y':
                    download_report(job_id, "txt")
                    print_success("TXT report downloaded")

            print_info(f"Scan ID: {job_id}")
            return

        elif status == "failed":
            print_error(f"Scan failed: {result.get('error')}")
            return

    print_error("Scan timed out")
    return


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
        print_info("No scan history found.")
        return
    print_history_table(scans)


def download_old_scan(scan_id: str, format: str = "csv"):
    """Download report for an old scan."""
    print_info(f"Downloading {format.upper()} report for scan {scan_id}...")
    download_report(scan_id, format)
    print_success(f"{format.upper()} report downloaded")


def export_all():
    """Export all scans to CSV."""
    try:
        from app.core.database import db
        filename = db.export_all_csv(os.path.join(DOWNLOADS_FOLDER, "all_scans_export.csv"))
        print_success(f"Exported all scans to: {filename}")
    except Exception as e:
        print_error(f"Error exporting: {e}")


if __name__ == "__main__":
    # Check adapter availability
    import shutil
    from app.core.database import db

    adapter_statuses = [
        ("Builtin scanner",  "ok",   "ready"),
        ("Nuclei",           "warn"  if not shutil.which("nuclei")   else "ok", "not installed" if not shutil.which("nuclei")   else "ready"),
        ("Nikto",            "warn"  if not shutil.which("nikto")    else "ok", "not installed" if not shutil.which("nikto")    else "ready"),
        ("Shodan",           "error" if not os.getenv("SHODAN_API_KEY")      else "ok", "API key missing" if not os.getenv("SHODAN_API_KEY")      else "ready"),
        ("VirusTotal",       "error" if not os.getenv("VIRUSTOTAL_API_KEY")  else "ok", "API key missing" if not os.getenv("VIRUSTOTAL_API_KEY")  else "ready"),
        ("OWASP ZAP",        "warn"  if not shutil.which("zap.sh")   else "ok", "not installed" if not shutil.which("zap.sh")   else "ready"),
    ]

    if len(sys.argv) < 2:
        print_banner()
        print_status(db_ok=True, adapter_statuses=adapter_statuses)

        while True:
            print_menu()
            choice = get_input("Enter choice (1-5)")

            if choice == "1":
                url = get_input("Enter target URL")
                if not url:
                    print_error("URL is required")
                    continue
                print_adapters()
                adapter_map = {"1": "builtin", "2": "nuclei", "3": "nikto", "4": "shodan", "5": "virustotal", "6": "zap"}
                sel = get_input("Select adapter (1-6) [default: 1]") or "1"
                adapter = adapter_map.get(sel, "builtin")
                scan(url, adapter)

            elif choice == "2":
                show_history()

            elif choice == "3":
                scan_id = get_input("Enter scan ID")
                fmt = get_input("Format csv or txt [default: csv]") or "csv"
                download_old_scan(scan_id, fmt)

            elif choice == "4":
                export_all()

            elif choice == "5":
                print_info("Goodbye!")
                sys.exit(0)

            else:
                print_error("Invalid choice, enter 1-5")
    else:
        cmd = sys.argv[1]
        if cmd == "--history":
            show_history()
        elif cmd == "--download":
            if len(sys.argv) < 3:
                print_error("Usage: python scan.py --download <scan_id> [csv|txt]")
                sys.exit(1)
            download_old_scan(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "csv")
        elif cmd == "--export-all":
            export_all()
        else:
            scan(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "builtin")