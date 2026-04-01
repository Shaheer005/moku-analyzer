import re

sample_output = """[apache-mod-negotiation-listing:exposed_files] [http] [low] http://scanme.nmap.org/index ["index.html"] [path="/index"]
[waf-detect:apachegeneric] [http] [info] http://scanme.nmap.org
[CVE-2023-48795] [javascript] [medium] scanme.nmap.org:22 ["Vulnerable to Terrapin"]
[ssh-auth-methods] [javascript] [info] scanme.nmap.org:22 ["["publickey","password"]"]"""

pattern = r'^\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)\s+(.*?)$'

for line in sample_output.split('\n'):
    line = line.strip()
    if not line:
        continue
    match = re.match(pattern, line)
    if match:
        print(f"✓ MATCHED: {line[:60]}...")
        print(f"  Template: {match.group(1)}, Protocol: {match.group(2)}, Severity: {match.group(3)}, Target: {match.group(4)}")
    else:
        print(f"✗ NO MATCH: {line[:60]}...")
