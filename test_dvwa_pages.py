import requests
from bs4 import BeautifulSoup

# Login to DVWA
session = requests.Session()
print('Logging into DVWA...')
login_resp = session.post('http://localhost/dvwa/login.php', data={
    'username': 'admin', 
    'password': 'password',
    'Login': 'Login'
})

if 'login' in login_resp.text.lower():
    print('✗ Login failed')
else:
    print('✓ Login successful')

# Navigate to different DVWA pages
pages = [
    ('/dvwa/index.php', 'Dashboard'),
    ('/dvwa/vulnerabilities/xss_r/', 'Reflected XSS'),
    ('/dvwa/vulnerabilities/xss_s/', 'Stored XSS'),
    ('/dvwa/vulnerabilities/sqli/', 'SQL Injection'),
]

for path, name in pages:
    resp = session.get(f'http://localhost{path}')
    soup = BeautifulSoup(resp.text, 'html.parser')
    
    # Getting title
    title = soup.find('title')
    title_text = title.get_text() if title else 'N/A'
    
    # Check if it's login page or actual page
    is_login = 'login' in resp.text.lower() and 'password' in resp.text.lower()
    
    print(f'\n{name} ({path}):')
    print(f'  Title: {title_text}')
    print(f'  Is Login Page: {is_login}')
    print(f'  Response Length: {len(resp.text)}')
    
    if not is_login:
        # Show a snippet of actual content
        lines = resp.text.split('\n')
        for line in lines[20:40]:
            if line.strip():
                print(f'  Content: {line.strip()[:80]}...')
                break
