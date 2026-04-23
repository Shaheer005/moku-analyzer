"""
moku-analyzer CLI — simple one-command scanner.
Usage: python scan.py <url> [adapter]
Example: python scan.py http://scanme.nmap.org
Example: python scan.py http://scanme.nmap.org nuclei
"""
import sys
import time
import requests

API = "http://127.0.0.1:8080"

def scan(url, adapter="nuclei"):
    print(f"\n🔍 Scanning: {url}")
    print(f"🔧 Using:    {adapter}")
    print("⏳ Please wait...\n")

    # submit scan
    try:
        r = requests.post(f"{API}/scan", json={
            "method": "url",
            "url": url,
            "adapter": adapter
        })
        job_id = r.json()["job_id"]
    except Exception as e:
        print(f"❌ Could not connect to server. Is it running? (python run.py)")
        sys.exit(1)

    # poll until done
    for i in range(60):
        time.sleep(5)
        r2 = requests.get(f"{API}/scan/{job_id}")
        result = r2.json()
        status = result["status"]

        if status == "running":
            print(f"   scanning... ({(i+1)*5}s)", end="\r")

        elif status == "done":
            vulns = result["vulnerabilities"]
            print(f"\n✅ Scan complete!\n")

            if not vulns:
                print("   No vulnerabilities found.")
            else:
                print(f"   Found {len(vulns)} vulnerabilities:\n")
                for v in vulns:
                    sev = v['severity'].upper()
                    print(f"   [{sev}] {v['type']}")
                    print(f"          {v['description']}")
                    if v.get('evidence'):
                        print(f"          Evidence: {v['evidence']}")
                    print()
            return

        elif status == "failed":
            print(f"\n❌ Scan failed: {result.get('error')}")
            return

    print("\n⚠️  Scan timed out — try polling manually.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scan.py <url> [adapter]")
        print("       python scan.py http://scanme.nmap.org")
        print("       python scan.py http://scanme.nmap.org nuclei")
        sys.exit(1)

    url     = sys.argv[1]
    adapter = sys.argv[2] if len(sys.argv) > 2 else "nuclei"
    scan(url, adapter)