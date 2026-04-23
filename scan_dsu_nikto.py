import requests, json, time

print('=== Phase 1 Scan: DSU Website (Nikto) ===')
print('Target: https://www.dsu.edu.pk/')
print('Adapter: nikto')
print()

# Submit scan with Nikto
r = requests.post('http://127.0.0.1:8080/scan', json={
    'method': 'url',
    'url': 'https://www.dsu.edu.pk/',
    'adapter': 'nikto'
})
job_id = r.json()['job_id']
print(f'Job submitted: {job_id}')
print('Running Nikto scan - please wait 1-2 minutes...')
time.sleep(120)

# Poll result
r2 = requests.get(f'http://127.0.0.1:8080/scan/{job_id}')
result = r2.json()
print(f'Status: {result["status"]}')
print(f'Vulnerabilities found: {len(result["vulnerabilities"])}')
print()

# Show vulnerabilities
for i, v in enumerate(result['vulnerabilities'][:10]):
    print(f'{i+1}. [{v["severity"].upper()}] {v["type"]}')
    print(f'   {v["description"]}')
    print()

if result.get('error'):
    print(f'Error: {result["error"]}')