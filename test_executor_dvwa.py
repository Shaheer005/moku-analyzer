from app.core.scan_unit import ScanUnit, ScanUnitType
from app.core.executor import Executor
from app.core.test_case import TestCase, TestMode
import requests
from bs4 import BeautifulSoup

# Get authenticated PHPSESSID
print('Step 1: Getting DVWA session...')
session = requests.Session()
resp = session.get('http://localhost/dvwa/login.php')
soup = BeautifulSoup(resp.text, 'html.parser')
csrf_token = soup.find('input', {'name': 'user_token'}).get('value')

session.post('http://localhost/dvwa/login.php', data={
    'username': 'admin',
    'password': 'password',
    'Login': 'Login',
    'user_token': csrf_token
})

phpsessid = session.cookies.get('PHPSESSID')
security = session.cookies.get('security', 'impossible')
print(f'✓ Got session: PHPSESSID={phpsessid}, security={security}')

# Create a scan unit with cookies
print('\nStep 2: Creating ScanUnit with DVWA cookies...')
scan_unit = ScanUnit(
    type=ScanUnitType.URL,
    url='http://localhost/dvwa/vulnerabilities/xss_r/',
    params={'name': 'baseline'},
    cookies={'PHPSESSID': phpsessid, 'security': security}
)

# Create executor and fetch baseline
print('\nStep 3: Testing executor with DVWA...')
executor = Executor()

# Fetch baseline
baseline_resp = executor._fetch_baseline(scan_unit)
print(f'Baseline response length: {len(baseline_resp)}')
print(f'Contains XSS form: {"XSS" in baseline_resp}')
print(f'Contains login page: {"Login" in baseline_resp}')

if len(baseline_resp) < 2000:
    print(f'\nBaseline response:\n{baseline_resp[:1000]}')
else:
    # Check for XSS form
    if '<form' in baseline_resp and 'name' in baseline_resp:
        print('✓ Got valid XSS page with form')
    else:
        print('✗ Response doesn\'t look like XSS page')

# Test a payload request
print('\nStep 4: Sending test payload...')
test_case = TestCase(
    test_id='test-xss-1',
    plugin_name='xss',
    injection_point='?name=',
    target_name='name',
    payload='<xssmarker123>',
    marker='xssmarker123',
    mode=TestMode.DETECT,
    timeout=10
)

response_body, response_headers = executor._send(scan_unit, test_case)
print(f'Response length: {len(response_body) if response_body else 0}')
print(f'Payload reflected: {"xssmarker123" in (response_body or "")}')

if response_body and len(response_body) > 500:
    print('✓ Got response from DVWA')
    # Look for our payload
    if 'xssmarker123' in response_body:
        idx = response_body.find('xssmarker123')
        snippet = response_body[idx-50:idx+100]
        print(f'   Found payload at position {idx}')
        print(f'   Context: ...{snippet}...')
    else:
        print('✗ Payload not reflected in response')
else:
    print('✗ No response or very short response')
