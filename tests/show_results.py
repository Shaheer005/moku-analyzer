import urllib.request
import json

resp = urllib.request.urlopen('http://127.0.0.1:8080/scan/f88cf4b3-3c06-4a69-8845-406173576cc2')
result = json.loads(resp.read().decode())

print(f"Status: {result['status']}")
print(f"Total Vulnerabilities Found: {len(result['vulnerabilities'])}")
print("\n" + "="*60)
print("VULNERABILITY SUMMARY")
print("="*60)

for i, vuln in enumerate(result['vulnerabilities'], 1):
    # Extract clean type without ANSI codes
    vuln_type = vuln['type']
    # Remove ANSI escape codes
    import re
    clean_type = re.sub(r'\x1b\[[0-9;]*m', '', vuln_type)
    severity = vuln['severity']
    print(f"{i:2d}. Type: {clean_type}")
    print(f"    Severity: {severity}")
    print(f"    Location: {vuln['location']}")
    print()
