import requests

# Login to DVWA
session = requests.Session()
session.post('http://localhost/dvwa/login.php', data={
    'username': 'admin',
    'password': 'password',
    'Login': 'Login'
})

# Test XSS reflection
marker = 'xsstest12345'
url = f'http://localhost/dvwa/vulnerabilities/xss_r/?name={marker}'
resp = session.get(url)

print('Testing DVWA XSS page reflection...')
print(f'URL: {url}')
print(f'Response length: {len(resp.text)}')
print()

# Check if marker is in response
if marker in resp.text:
    print(f'✓ Marker "{marker}" found in response')
    # Find context around marker
    idx = resp.text.find(marker)
    start = max(0, idx - 100)
    end = min(len(resp.text), idx + 200)
    snippet = resp.text[start:end]
    print(f'  Context: ...{snippet}...')
else:
    print(f'✗ Marker "{marker}" NOT found in response')

# Show first 3000 chars of response
print()
print('Response preview (first 3000 chars):')
print(resp.text[:3000])
