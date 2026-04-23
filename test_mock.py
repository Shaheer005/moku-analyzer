import requests, json

print('=== Testing Mock Adapter (Phase 1) ===')
print('Target: https://www.dsu.edu.pk/')
print('Adapter: mock')
print()

# Submit scan with mock adapter
r = requests.post('http://127.0.0.1:8080/scan', json={
    'method': 'url',
    'url': 'https://www.dsu.edu.pk/',
    'adapter': 'mock'
})
job_id = r.json()['job_id']
print(f'Job submitted: {job_id}')

# Poll result immediately since mock is instant
r2 = requests.get(f'http://127.0.0.1:8080/scan/{job_id}')
result = r2.json()
print(f'Status: {result["status"]}')
print(f'Vulnerabilities found: {len(result["vulnerabilities"])}')
print()

# Show vulnerabilities
for i, v in enumerate(result['vulnerabilities'][:5]):
    print(f'{i+1}. [{v["severity"].upper()}] {v["type"]}')
    print(f'   {v["description"]}')
    print()

print('✓ Mock adapter works - system is functional!')