import urllib.request
import json
import time

# Submit scan with nikto adapter
data = json.dumps({'method': 'url', 'url': 'http://scanme.nmap.org', 'adapter': 'nikto'})
req = urllib.request.Request(
    'http://127.0.0.1:8080/scan',
    data=data.encode(),
    headers={'Content-Type': 'application/json'},
    method='POST'
)
resp = urllib.request.urlopen(req)
result = json.loads(resp.read().decode())
job_id = result['job_id']
print(f'Job ID: {job_id}')
print('Waiting 2 minutes for scan to complete...')
time.sleep(120)

# Poll results
resp2 = urllib.request.urlopen(f'http://127.0.0.1:8080/scan/{job_id}')
final_result = json.loads(resp2.read().decode())
print('\n=== FINAL SCAN RESULT ===')
print(f"Status: {final_result['status']}")
print(f"Total Vulnerabilities: {len(final_result['vulnerabilities'])}")
if final_result['vulnerabilities']:
    print("\nFindings:")
    for i, vuln in enumerate(final_result['vulnerabilities'][:5], 1):
        print(f"{i}. {vuln['description'][:80]}...")
