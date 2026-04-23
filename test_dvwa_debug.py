import requests
from bs4 import BeautifulSoup

session = requests.Session()

# Login
resp = session.get('http://localhost/dvwa/login.php')
soup = BeautifulSoup(resp.text, 'html.parser')
csrf_token = soup.find('input', {'name': 'user_token'}).get('value')

session.post('http://localhost/dvwa/login.php', data={
    'username': 'admin',
    'password': 'password',
    'Login': 'Login',
    'user_token': csrf_token
})

# Get security level
level_resp = session.get('http://localhost/dvwa/security.php')
soup = BeautifulSoup(level_resp.text, 'html.parser')
print('Security Level Page:')
print(level_resp.text[:2000])

# Test simple payload
print('\n\nTesting XSS with different payloads...')
xss_page_resp = session.get('http://localhost/dvwa/vulnerabilities/xss_r/')
soup = BeautifulSoup(xss_page_resp.text, 'html.parser')
xss_csrf = soup.find('input', {'name': 'user_token'}).get('value')

# Simple test
resp = session.post('http://localhost/dvwa/vulnerabilities/xss_r/', data={
    'name': 'testvalue123',
    'user_token': xss_csrf,
    'Submit': 'Submit'
})

print(f'Response length: {len(resp.text)}')
print(f'Contains form: {"<form" in resp.text}')
print(f'Contains "testvalue123": {"testvalue123" in resp.text}')
print(f'\nResponse preview (around form submission):')

# Find the part of the response after form
if '<form' in resp.text:
    form_idx = resp.text.find('<form')
    snippet = resp.text[form_idx:form_idx+2000]
    print(snippet[:1000])
else:
    print(resp.text[:1500])
