"""
moku-analyzer CLI — simple one-command scanner.
Usage: python scan.py <url> [adapter] [--cookies KEY1=VAL1,KEY2=VAL2]
Example: python scan.py http://scanme.nmap.org
Example: python scan.py http://scanme.nmap.org nuclei
Example: python scan.py http://localhost/dvwa/vulnerabilities/xss_r/ builtin --cookies PHPSESSID=abc123
"""
import sys
import time
import requests

API = "http://127.0.0.1:8080"

def parse_cookies(cookie_str):
    """Parse cookie string like 'KEY1=VAL1,KEY2=VAL2' into dict."""
    if not cookie_str:
        return {}
    cookies = {}
    for pair in cookie_str.split(','):
        if '=' in pair:
            key, val = pair.split('=', 1)
            cookies[key.strip()] = val.strip()
    return cookies

def scan(url, adapter="nuclei", cookies=None):
    print(f"\n[*] Scanning: {url}")
    print(f"[*] Using:    {adapter}")
    if cookies:
        print(f"[*] Cookies:  {cookies}")
    print("Please wait...\n")

    # submit scan
    try:
        payload = {
            "method": "url",
            "url": url,
            "adapter": adapter
        }
        if cookies:
            payload["cookies"] = cookies
        r = requests.post(f"{API}/scan", json=payload)
        job_id = r.json()["job_id"]
    except Exception as e:
        print(f"[-] Could not connect to server. Is it running? (python run.py)")
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
            print(f"\n[+] Scan complete!\n")

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
            print(f"\n[-] Scan failed: {result.get('error')}")
            return

    print("\n[!] Scan timed out — try polling manually.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scan.py <url> [adapter] [--cookies KEY1=VAL1,KEY2=VAL2]")
        print("       python scan.py http://scanme.nmap.org")
        print("       python scan.py http://scanme.nmap.org nuclei")
        print("       python scan.py http://localhost/dvwa/vulnerabilities/xss_r/ builtin --cookies PHPSESSID=abc123")
        sys.exit(1)

    url = sys.argv[1]
    adapter = "nuclei"
    cookies = None

    # parse remaining args
    i = 2
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--cookies" and i + 1 < len(sys.argv):
            cookies = parse_cookies(sys.argv[i + 1])
            i += 2
        elif not arg.startswith("--"):
            adapter = arg
            i += 1
        else:
            i += 1

    scan(url, adapter, cookies)