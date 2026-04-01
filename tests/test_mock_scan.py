import urllib.request
import json
import time

payload = json.dumps({'method': 'url', 'url': 'http://scanme.nmap.org', 'adapter': 'mock'})
req = urllib.request.Request('http://127.0.0.1:8080/scan', data=payload.encode(), headers={'Content-Type': 'application/json'}, method='POST')
resp = urllib.request.urlopen(req)
job_id = json.loads(resp.read().decode())['job_id']
print('Job ID:', job_id)

# Wait for it to run in background
time.sleep(1)

resp2 = urllib.request.urlopen(f'http://127.0.0.1:8080/scan/{job_id}')
result = json.loads(resp2.read().decode())
print(json.dumps(result, indent=2))
