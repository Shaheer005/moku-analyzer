import requests, json, time

job_id = 'a23e3eae-7e00-4e7d-94f6-908e4b54b89a'
print('Checking scan status...')
time.sleep(60)  # Wait another minute

r = requests.get(f'http://127.0.0.1:8080/scan/{job_id}')
result = r.json()
print(f'Status: {result["status"]}')
print(f'Vulnerabilities found: {len(result["vulnerabilities"])}')

if result['status'] == 'done':
    print()
    for i, v in enumerate(result['vulnerabilities'][:5]):
        print(f'{i+1}. [{v["severity"].upper()}] {v["type"]}')
        print(f'   {v["description"]}')
        print()
else:
    print('Scan still in progress...')