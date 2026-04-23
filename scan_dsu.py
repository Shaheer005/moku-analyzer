import requests, json, time

print('=== Phase 1 Scan: DSU Website ===')
print('Target: https://www.dsu.edu.pk/')
print('Adapter: nuclei')
print()

# Submit scan
r = requests.post('http://127.0.0.1:8080/scan', json={
    'method': 'url',
    'url': 'https://www.dsu.edu.pk/',
    'adapter': 'nuclei'
})
job_id = r.json()['job_id']
print(f'Job submitted: {job_id}')
print('Running Nuclei scan - please wait 2-3 minutes...')
time.sleep(180)

# Poll result
r2 = requests.get(f'http://127.0.0.1:8080/scan/{job_id}')
result = r2.json()
print(f'Status: {result["status"]}')
print(f'Vulnerabilities found: {len(result["vulnerabilities"])}')
print()

# Show first 10 vulnerabilities
for i, v in enumerate(result['vulnerabilities'][:10]):
    print(f'{i+1}. [{v["severity"].upper()}] {v["type"]}')
    print(f'   {v["description"]}')
    print(f'   Location: {v["location"]}')
    print()

if len(result['vulnerabilities']) > 10:
    print(f'... and {len(result["vulnerabilities"]) - 10} more vulnerabilities')

if result.get('error'):
    print(f'Error: {result["error"]}')