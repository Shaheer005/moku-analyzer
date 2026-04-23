import requests
import time
import json
from bs4 import BeautifulSoup

print('='*70)
print('COMPREHENSIVE DVWA XSS TEST WITH BUILTIN ANALYZER')
print('='*70)

# Step 1: Get fresh DVWA session with proper CSRF handling
print('\n[STEP 1] Authenticating to DVWA with CSRF...')
session = requests.Session()
while True:
    resp = session.get('http://localhost/dvwa/login.php')
    soup = BeautifulSoup(resp.text, 'html.parser')
    csrf_token = soup.find('input', {'name': 'user_token'})
    if csrf_token:
        csrf_value = csrf_token.get('value')
        break

login_resp = session.post('http://localhost/dvwa/login.php', data={
    'username': 'admin',
    'password': 'password',
    'Login': 'Login', 
    'user_token': csrf_value
})

phpsessid = session.cookies.get('PHPSESSID')
security = session.cookies.get('security', 'unknown')
print(f'✓ Authenticated successfully')
print(f'  PHPSESSID: {phpsessid}')
print(f'  Security Level: {security}')

# Verify we can access the XSS page
xss_test = session.get('http://localhost/dvwa/vulnerabilities/xss_r/?name=test')
if '<img' not in xss_test.text and 'dvwa' in xss_test.text.lower():
    print('✓ Can access XSS vulnerability page')
else:
    print('✗ Cannot properly access XSS page')

# Step 2: Submit builtin scan job via API
print('\n[STEP 2] Submitting builtin adapter scan to moku-analyzer API...')
scan_payload = {
    'method': 'url',
    'url': 'http://localhost/dvwa/vulnerabilities/xss_r/?name=injected',
    'adapter': 'builtin',
    'cookies': {'PHPSESSID': phpsessid, 'security': security}
}
print(f'Payload: {json.dumps(scan_payload, indent=2)}')

api_resp = requests.post('http://127.0.0.1:8080/scan', json=scan_payload)
job_id = api_resp.json()['job_id']
print(f'✓ Scan job submitted: {job_id}')

# Step 3: Poll for results  
print('\n[STEP 3] Waiting for scan to complete (up to 180 seconds)...')
for i in range(36):
    time.sleep(5)
    status_resp = requests.get(f'http://127.0.0.1:8080/scan/{job_id}')
    status_data = status_resp.json()
    status = status_data['status']
    vulns_count = len(status_data.get('vulnerabilities', []))
    elapsed = (i + 1) * 5
    
    status_symbol = '●' if status == 'running' else '✓' if status == 'done' else '✗' if status == 'failed' else '○'
    print(f'[{elapsed:3d}s] {status_symbol} Status: {status:10s} | Found: {vulns_count} vulns', end='\r')
    
    if status in ['done', 'failed']:
        print()  # newline
        break

# Step 4: Display results
print('\n[STEP 4] RESULTS')
print('='*70)
result = requests.get(f'http://127.0.0.1:8080/scan/{job_id}').json()

print(f'\nJob Status: {result["status"]}')
print(f'Total Vulnerabilities: {len(result["vulnerabilities"])}')

if result.get('error'):
    print(f'\nError: {result["error"]}')

if result['vulnerabilities']:
    print('\nVULNERABILITIES DETECTED:')
    for i, vuln in enumerate(result['vulnerabilities'], 1):
        print(f'\n[{i}] {vuln["severity"].upper()} - {vuln["type"]}')
        print(f'    Description: {vuln["description"]}')
        print(f'    Evidence: {vuln.get("evidence", "N/A")[:80]}...')
        if vuln.get('meta'):
            meta = vuln['meta']
            if isinstance(meta, dict):
                print(f'    Confidence: {meta.get("confidence", "N/A")}')
                if meta.get('finding_id'):
                    print(f'    Finding ID: {meta.get("finding_id")}')
else:
    print('\n⚠ No vulnerabilities detected by builtin adapter')
    print('\nNOTE: This could indicate:')
    print('- Cookies not being properly forwarded to the executor')
    print('- XSS detection thresholds not met')
    print('- Parameter names not matching what the adapter expects')

print('\n' + '='*70)
print('TEST COMPLETE')
print('='*70)
