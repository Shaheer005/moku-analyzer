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

# Verify we can access XSS page with our session
print('\nVerifying authenticated access...')
test_resp = session.get('http://localhost/dvwa/vulnerabilities/xss_r/?name=test')
if 'dvwa' in test_resp.text.lower() and phpsessid in str(session.cookies):
    print(f'✓ Successfully logged in, can access restricted pages')
else:
    print(f'✗ Authentication may have failed')
    print(f'Response length: {len(test_resp.text)}')

# 2. Submit builtin scan with real DVWA XSS page (WITH query parameter)
print('\nStep 2: Submitting builtin scan against DVWA XSS page...')
r = requests.post('http://127.0.0.1:8080/scan', json={
    'method': 'url',
    'url': 'http://localhost/dvwa/vulnerabilities/xss_r/?name=defaultparam',
    'adapter': 'builtin',
    'cookies': {'PHPSESSID': phpsessid}
})
job_id = r.json()['job_id']
print(f'Job: {job_id}')

# 3. Wait for scan
print('\nStep 3: Scanning (up to 180 seconds)...')
for i in range(36):
    time.sleep(5)
    r_status = requests.get(f'http://127.0.0.1:8080/scan/{job_id}')
    status_data = r_status.json()
    status = status_data['status']
    elapsed = (i + 1) * 5
    vulns_count = len(status_data.get('vulnerabilities', []))
    print(f'  [{elapsed:3d}s] Status: {status:10s} | Vulnerabilities: {vulns_count}')
    if status == 'done' or status == 'failed':
        break

# 4. Get results
print('\nStep 4: Detailed Results')
print('='*60)
r2 = requests.get(f'http://127.0.0.1:8080/scan/{job_id}')
result = r2.json()
print(f'Status: {result["status"]}')
print(f'Vulnerabilities found: {len(result["vulnerabilities"])}')

if result.get('error'):
    print(f'Error: {result["error"]}\n')

if result['vulnerabilities']:
    for i, v in enumerate(result['vulnerabilities'], 1):
        print(f'\n[{i}] {v["severity"].upper()} - {v["type"]}')
        print(f'    Description: {v["description"]}')
        print(f'    Evidence: {v.get("evidence", "N/A")[:100]}...')
        if v.get('location'):
            print(f'    Location: {v["location"]}')
        if v.get('meta'):
            meta = v.get('meta', {})
            if 'confidence' in meta:
                print(f'    Confidence: {meta["confidence"]}')
else:
    print('\nNo vulnerabilities detected')

print('\n' + '='*60)
print('Test Complete!')
