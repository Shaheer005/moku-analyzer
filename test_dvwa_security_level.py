import requests
from bs4 import BeautifulSoup

# Get session and login
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

print('Logged in successfully')
print(f'Cookies: {session.cookies.get_dict()}')

# Access security settings page
print('\nAccessing security settings page...')
security_resp = session.get('http://localhost/dvwa/security.php')

soup = BeautifulSoup(security_resp.text, 'html.parser')

# Find the form and security level selector
form = soup.find('form')
print(f'Found form: {form is not None}')

# Look for the security level options
select_elem = soup.find('select')
if select_elem:
    options = select_elem.find_all('option')
    print('\nAvailable security levels:')
    for opt in options:
        value = opt.get('value')
        text = opt.get_text()
        is_selected = opt.get('selected') is not None
        print(f'  - {value}: {text} {"(SELECTED)" if is_selected else ""}')
        
    # Try to set to 'low'
    print('\nAttempting to set security level to "low"...')
    
    # Get CSRF token from security page
    csrf_input = soup.find('input', {'name': 'user_token'})
    csrf_value = csrf_input.get('value') if csrf_input else None
    
    change_resp = session.post('http://localhost/dvwa/security.php', data={
        'security': 'low',
        'user_token': csrf_value,
        'submit': 'Submit'
    })
    
    print('Security change submitted')
    
    # Verify the change
    verify_resp = session.get('http://localhost/dvwa/security.php')
    verify_soup = BeautifulSoup(verify_resp.text, 'html.parser')
    
    for opt in verify_soup.find('select').find_all('option'):
        if opt.get('selected') is not None:
            print(f'✓ Security level is now: {opt.get_text().strip()}')

print(f'\nCookies after change: {session.cookies.get_dict()}')

# Test XSS with new security level
print('\nTesting XSS with new security level...')
xss_resp = session.get('http://localhost/dvwa/vulnerabilities/xss_r/?name=<testxss>')
print(f'Response length: {len(xss_resp.text)}')
print(f'Payload reflected: {"testxss" in xss_resp.text}')

if 'testxss' in xss_resp.text:
    idx = xss_resp.text.find('testxss')
    snippet = xss_resp.text[idx-50:idx+100]
    print(f'✓ XSS payload reflected!')
    print(f'  Context: ...{snippet}...')
