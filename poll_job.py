import requests, json
r = requests.get('http://127.0.0.1:8080/scan/0d395324-7670-4384-a02b-e7d871f71589')
result = r.json()
print(f'Status: {result["status"]}')
print(f'Vulnerabilities found: {len(result["vulnerabilities"])}')
for v in result['vulnerabilities']:
    print(f'  TYPE: {v["type"]} | SEVERITY: {v["severity"]}')
    print(f'  DESC: {v["description"]}')
    print()
if result.get('error'):
    print(f'Error: {result["error"]}')