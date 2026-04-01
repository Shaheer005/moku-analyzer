import subprocess
import json

result = subprocess.run(
    ["nuclei", "-u", "http://scanme.nmap.org", "-jsonl", "-silent"],
    capture_output=True,
    text=True,
    timeout=180
)

print("=== STDOUT ===")
print(result.stdout[:1000])
print("\n=== STDERR ===")
print(result.stderr[:500])
print("\n=== LINE COUNT ===")
print(f"Total lines: {len(result.stdout.strip().split(chr(10)))}")

# Try parsing first line
lines = result.stdout.strip().split('\n')
if lines and lines[0]:
    try:
        sample = json.loads(lines[0])
        print("\n=== FIRST OBJECT KEYS ===")
        print(list(sample.keys()))
        print("\n=== FIRST OBJECT ===")
        print(json.dumps(sample, indent=2)[:500])
    except Exception as e:
        print(f"Parse error: {e}")
