import requests
from bs4 import BeautifulSoup

# Login to DVWA
session = requests.Session()
session.post('http://localhost/dvwa/login.php', data={
    'username': 'admin',
    'password': 'password',
    'Login': 'Login'
})

# Get the XSS page HTML
print('Fetching DVWA XSS page...')
resp = session.get('http://localhost/dvwa/vulnerabilities/xss_r/')

soup = BeautifulSoup(resp.text, 'html.parser')

# Find all forms
forms = soup.find_all('form')
print(f'Found {len(forms)} forms')
for i, form in enumerate(forms):
    print(f'\nForm {i+1}:')
    print(f'  Action: {form.get("action")}')
    print(f'  Method: {form.get("method", "GET")}')
    inputs = form.find_all('input')
    for inp in inputs:
        print(f'    Input: name="{inp.get("name")}" type="{inp.get("type")}" value="{inp.get("value")}"')

# Find all text mentioning input or parameter
text = soup.get_text()
lines = text.split('\n')
for i, line in enumerate(lines):
    if 'name=' in line.lower() or 'param' in line.lower() or 'input' in line.lower():
        print(f'Line {i}: {line.strip()[:100]}')

# Show raw HTML snippet
print('\n\nPage HTML (first 2000 chars):')
print(resp.text[:2000])
