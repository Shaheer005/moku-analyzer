import re

# Test the problem line
line = "[waf-detect:apachegeneric] [http] [info] http://scanme.nmap.org"

# Original pattern
pattern1 = r'^\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)\s+(.*?)$'
match1 = re.match(pattern1, line)
print(f"Pattern 1 (.*?): {bool(match1)}")

# Updated pattern - make results optional
pattern2 = r'^\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)\s*(.*)$'
match2 = re.match(pattern2, line)
print(f"Pattern 2 with optional space: {bool(match2)}")
if match2:
    print(f"  Groups: template='{match2.group(1)}', protocol='{match2.group(2)}', severity='{match2.group(3)}', target='{match2.group(4)}', results='{match2.group(5)}'")

# Better pattern - target can be followed by results or nothing
pattern3 = r'^\[([^\]]+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)(?:\s+(.*))?$'
match3 = re.match(pattern3, line)
print(f"Pattern 3 with optional group: {bool(match3)}")
if match3:
    print(f"  Groups: template='{match3.group(1)}', protocol='{match3.group(2)}', severity='{match3.group(3)}', target='{match3.group(4)}', results='{match3.group(5)}'")
