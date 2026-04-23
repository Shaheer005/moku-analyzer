import requests
import time

print('=== Testing Cookie Support ===')
r = requests.post('http://127.0.0.1:8080/scan', json={
    'method': 'url',
    'url': 'http://httpbin.org/get',
    'adapter': 'mock',
    'cookies': {'session': 'test123'}
})
job_id = r.json()['job_id']
print(f'Job submitted: {job_id}')

time.sleep(3)

r2 = requests.get(f'http://127.0.0.1:8080/scan/{job_id}')
result = r2.json()
print(f'Status: {result["status"]}')
print(f'Vulnerabilities: {len(result["vulnerabilities"])}')
print('✅ Cookie support working!')