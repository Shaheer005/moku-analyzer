from app.adapters.builtin_adapter import BuiltinAdapter
from app.core.scan_unit import ScanUnit
import requests

url = "https://www.daraz.pk/products/summers-baggy-trousers-for-men-pleated-men-trousers-plated-trousers-for-men-loose-fit-trousers-for-boys-summers-terry-fabric-wide-leg-men-trousers-i1952548996-s14014460502.html?scm=1007.51610.379274.0&pvid=54684cdc-a72e-4ba9-a35f-0ebb6d65acbd&search=flashsale&spm=a2a0e.tm80335142.FlashSale.d_1952548996"
print(f"[DEBUG] Testing: {url}\n")

# Step 1: Check if we can fetch the URL
try:
    r = requests.get(url, timeout=10)
    print(f"[DEBUG] URL fetch: {r.status_code}")
    print(f"[DEBUG] Response length: {len(r.text)} bytes")
    print(f"[DEBUG] Response preview: {r.text[:200]}\n")
except Exception as e:
    print(f"[ERROR] Cannot fetch URL: {e}\n")
    exit(1)

# Step 2: Check builtin adapter
adapter = BuiltinAdapter()
print(f"[DEBUG] Running builtin adapter...\n")

try:
    vulns = adapter.scan_url(url)
    print(f"[DEBUG] Vulnerabilities found: {len(vulns)}")
    for v in vulns:
        print(f"  - {v.type}: {v.description}")
        if v.evidence:
            print(f"    Evidence: {v.evidence}")
except Exception as e:
    print(f"[ERROR] Adapter error: {e}")
    import traceback
    traceback.print_exc()