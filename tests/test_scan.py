import urllib.request
import json
import time

# Submit scan
data = json.dumps({'method': 'url', 'url': 'http://testphp.vulnweb.com', 'adapter': 'nuclei'})
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
print('Waiting 3 minutes for scan to complete...')
time.sleep(180)

# Poll results
resp2 = urllib.request.urlopen(f'http://127.0.0.1:8080/scan/{job_id}')
final_result = json.loads(resp2.read().decode())
print('\n=== FINAL SCAN RESULT ===')
print(json.dumps(final_result, indent=2))
