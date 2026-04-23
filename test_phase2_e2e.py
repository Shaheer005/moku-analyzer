import requests, time, json

print('=== Phase 2 End-to-End Test ===')
print('Target: http://testphp.vulnweb.com/listproducts.php?cat=1')
print('Adapter: builtin (XSS + SQLi + CSRF)')
print()

# submit scan
r = requests.post('http://127.0.0.1:8080/scan', json={
    'method': 'url',
    'url': 'http://testphp.vulnweb.com/listproducts.php?cat=1',
    'adapter': 'builtin'
})
job_id = r.json()['job_id']
print(f'Job submitted: {job_id}')
print('Waiting 60 seconds for scan...')
time.sleep(60)

# poll result
r2 = requests.get(f'http://127.0.0.1:8080/scan/{job_id}')
result = r2.json()
print(f'Status: {result["status"]}')
print(f'Vulnerabilities found: {len(result["vulnerabilities"])}')
print()
for v in result['vulnerabilities']:
    print(f'  TYPE:     {v["type"]}')
    print(f'  SEVERITY: {v["severity"]}')
    print(f'  DESC:     {v["description"]}')
    print(f'  EVIDENCE: {v["evidence"]}')
    print()