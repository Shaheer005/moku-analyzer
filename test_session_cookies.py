import requests

# Test 1: Setting cookies on a session
print('Test 1: Setting cookies directly on session')
session = requests.Session()
session.cookies.set('PHPSESSID', 'test123')
session.cookies.set('security', 'impossible')

resp = session.get('http://httpbin.org/cookies')
print(f'Cookies sent: {resp.json()}')

# Test 2: Using update_session_cookies() pattern
print('\nTest 2: Alternative cookie setting method')
session2 = requests.Session()
cookie_dict = {'PHPSESSID': 'test456', 'security': 'off'}

from http.cookiejar import Cookie
import time

# Create proper cookies
domain = '.httpbin.org'
for key, value in cookie_dict.items():
    c = Cookie(
        version=0,
        name=key,
        value=value,
        port=None,
        port_specified=False,
        domain=domain,
        domain_specified=True,
        domain_initial_dot=True,
        path='/',
        path_specified=True,
        secure=False,
        expires=None,
        discard=False,
        comment=None,
        comment_url=None,
        rest={},
        rfc2109=False
    )
    session2.cookies.set_cookie(c)

resp2 = session2.get('http://httpbin.org/cookies')
print(f'Cookies sent: {resp2.json()}')

# Test 3: Simple way - just pass as dict to request
print('\nTest 3: Pass cookies dict directly to request')
resp3 = requests.get('http://httpbin.org/cookies', cookies={'test': 'value123'})
print(f'Cookies sent: {resp3.json()}')
