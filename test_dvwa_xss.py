import requests
import time
import json

# 1. Get fresh session cookie
print('Step 1: Authenticating to DVWA...')
session = requests.Session()
session.post('http://localhost/dvwa/login.php', data={
    'username': 'admin',
    'password': 'password',
    'Login': 'Login'
})
cookies = session.cookies.get_dict()
phpsessid = cookies.get('PHPSESSID')
print(f'Session: {phpsessid}')

# 2. Submit builtin scan with real DVWA XSS page
print('\nStep 2: Submitting builtin scan against DVWA XSS page...')
r = requests.post('http://127.0.0.1:8080/scan', json={
    'method': 'url',
    'url': 'http://localhost/dvwa/vulnerabilities/xss_r/',
    'adapter': 'builtin',
    'cookies': {'PHPSESSID': phpsessid}
})
job_id = r.json()['job_id']
print(f'Job: {job_id}')

# 3. Wait for scan
print('\nStep 3: Scanning (180 seconds)...')
for i in range(36):
    time.sleep(5)
    r_status = requests.get(f'http://127.0.0.1:8080/scan/{job_id}')
    status = r_status.json()['status']
    elapsed = (i + 1) * 5
    print(f'  [{elapsed}s] Status: {status}')
    if status == 'done' or status == 'failed':
        break

# 4. Get results
print('\nStep 4: Retrieving results...')
r2 = requests.get(f'http://127.0.0.1:8080/scan/{job_id}')
result = r2.json()
print(f'Status: {result["status"]}')
print(f'Vulnerabilities found: {len(result["vulnerabilities"])}')

if result.get('error'):
    print(f'Error: {result["error"]}\n')

for v in result['vulnerabilities']:
    print(f'\n[{v["severity"].upper()}] {v["type"]}')
    print(f'  Description: {v["description"]}')
    print(f'  Evidence: {v["evidence"]}')
    if v.get('location'):
        print(f'  Location: {v["location"]}')
    if v.get('meta'):
        print(f'  Meta: {json.dumps(v["meta"], indent=2)}')

print('\n' + '='*60)
print('Test Complete!')
