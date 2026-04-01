import subprocess

# Test nuclei with simplified command
result = subprocess.run(
    ["nuclei", "-u", "http://scanme.nmap.org", "-jsonl", "-silent", "-stats"],
    capture_output=True,
    text=True,
    timeout=300
)

print("Return code:", result.returncode)
print("\n=== STDOUT (first 2000 chars) ===")
print(result.stdout[:2000])
print("\n=== STDERR (first 1000 chars) ===")
print(result.stderr[:1000])
print("\n=== STDOUT LINES ===")
lines = [l for l in result.stdout.split('\n') if l.strip()]
print(f"Total lines: {len(lines)}")
for i, line in enumerate(lines[:5]):
    print(f"Line {i}: {line[:100]}")
