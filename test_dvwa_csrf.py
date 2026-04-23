import requests
from bs4 import BeautifulSoup

session = requests.Session()

# First, get the login page to extract CSRF token
print('Step 1: Getting DVWA login page...')
resp = session.get('http://localhost/dvwa/login.php')
soup = BeautifulSoup(resp.text, 'html.parser')

# Find the CSRF token
token_input = soup.find('input', {'name': 'user_token'})
csrf_token = token_input.get('value') if token_input else None
print(f'CSRF Token found: {csrf_token}')

# Try login with CSRF token
print('\nStep 2: Attempting login...')
login_data = {
    'username': 'admin',
    'password': 'password',
    'Login': 'Login',
    'user_token': csrf_token
}

print(f'Login payload: {login_data}')
login_resp = session.post('http://localhost/dvwa/login.php', data=login_data)

print(f'Login response status: {login_resp.status_code}')
print(f'Cookies after login: {session.cookies.get_dict()}')

# Try to access a restricted page
print('\nStep 3: Accessing vulnerability page...')
vuln_resp = session.get('http://localhost/dvwa/vulnerabilities/xss_r/?name=test')

if 'dvwa' in vuln_resp.text.lower() and 'login' not in vuln_resp.text.lower():
    print('✓ Successfully accessed vulnerability page!')
    print(f'Response preview: {vuln_resp.text[:500]}')
else:
    print('✗ Still getting login page')
    print(f'Response length: {len(vuln_resp.text)}')
    
    # Try with different credentials
    print('\nStep 4: Trying default DVWA credentials (admin/admin)...')
    resp2 = session.get('http://localhost/dvwa/login.php')
    soup2 = BeautifulSoup(resp2.text, 'html.parser')
    token_input2 = soup2.find('input', {'name': 'user_token'})
    csrf_token2 = token_input2.get('value') if token_input2 else None
    
    login_data2 = {
        'username': 'admin',
        'password': 'admin',
        'Login': 'Login',
        'user_token': csrf_token2
    }
    
    login_resp2 = session.post('http://localhost/dvwa/login.php', data=login_data2)
    vuln_resp2 = session.get('http://localhost/dvwa/vulnerabilities/xss_r/?name=test')
    
    if 'dvwa' in vuln_resp2.text.lower() and 'login' not in vuln_resp2.text.lower():
        print('✓ Successfully logged in with admin/admin!')
    else:
        print('✗ admin/admin also failed')
