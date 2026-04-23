import requests, json, time

print('=== Phase 1 Scan: DSU Website (Shodan) ===')
print('Target: dsu.edu.pk')
print('Adapter: shodan')
print()

# Submit scan with Shodan
r = requests.post('http://127.0.0.1:8080/scan', json={
    'method': 'url',
    'url': 'https://www.dsu.edu.pk/',
    'adapter': 'shodan'
})
job_id = r.json()['job_id']
print(f'Job submitted: {job_id}')
print('Running Shodan scan - please wait 30 seconds...')

# Poll result immediately since Shodan is fast
time.sleep(30)
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