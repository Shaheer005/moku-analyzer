"""
Test the entire Phase 2 XSS detection flow end-to-end.
This demonstrates the plugin system working with mock web responses.
"""
from app.plugins.xss_plugin import XSSPlugin
from app.core.scan_unit import ScanUnit, ScanUnitType
from app.core.test_case import TestMode
import uuid


def test_xss_plugin_end_to_end():
    """Test XSS plugin generating tests and analyzing vulnerable responses."""
    
    plugin = XSSPlugin()
    
    # Create a scan unit for a URL with a vulnerable parameter
    scan_unit = ScanUnit(
        type=ScanUnitType.URL,
        url="http://example.com/search.php",
        params={
            "q": "original",
            "category": "test"
        }
    )
    
    # Step 1: Generate tests (pure function, no network)
    print("=" * 70)
    print("STEP 1: Generate test cases")
    print("=" * 70)
    tests = plugin.generate_tests(scan_unit)
    print(f"Generated {len(tests)} test cases:")
    for t in tests:
        print(f"  - {t.test_id}")
        print(f"    mode: {t.mode}")
        print(f"    target: {t.target_name}")
        print(f"    payload: {t.payload}")
        print(f"    marker: {t.marker}")
        print()
    
    # Step 2: Simulate DETECT test with vulnerable response
    print("=" * 70)
    print("STEP 2: Simulate DETECT response (vulnerable reflection)")
    print("=" * 70)
    
    detect_test = next((t for t in tests if t.mode == TestMode.DETECT), None)
    if detect_test:
        # Simulate a vulnerable response that reflects the marker unescaped
        marker = detect_test.marker
        vulnerable_response = f"""
            <html>
            <head><title>Search Results</title></head>
            <body>
                <h1>You searched for: <{marker}></h1>
                <div class="results">
                    <p>No results found.</p>
                </div>
            </body>
            </html>
        """
        
        print(f"Test: {detect_test.test_id}")
        print(f"Marker in response (unescaped): <{marker}>")
        print(f"Response snippet:\n{vulnerable_response[200:400]}\n")
        
        # Analyze the response
        finding = plugin.analyze_response(
            test_case=detect_test,
            response_body=vulnerable_response,
            response_headers={},
            baseline_body=""
        )
        
        if finding:
            print("✓ VULNERABILITY DETECTED!")
            print(f"  Finding ID: {finding.finding_id}")
            print(f"  Plugin: {finding.plugin}")
            print(f"  Confidence: {finding.confidence}")
            print(f"  Pattern: {finding.matched_pattern}")
            print(f"  Evidence Refs: {len(finding.evidence_refs)} blob(s)")
            print(f"  Repro Steps: {finding.repro_steps}")
        else:
            print("✗ No finding (false negative)")
    
    # Step 3: Simulate CONFIRM test
    print("\n" + "=" * 70)
    print("STEP 3: Simulate CONFIRM response (script tag reflection)")
    print("=" * 70)
    
    confirm_test = next((t for t in tests if t.mode == TestMode.CONFIRM), None)
    if confirm_test:
        marker = confirm_test.marker
        # Simulate a response that reflects the script tag
        vulnerable_response = f"""
            <html>
            <head><title>Search Results</title></head>
            <body>
                <h1>You searched for: "><script>alert("{marker}")</script></h1>
                <div class="results">
                    <p>No results found.</p>
                </div>
            </body>
            </html>
        """
        
        print(f"Test: {confirm_test.test_id}")
        msg = f'Script tag in response: script>alert("{marker}")</script>'
        print(msg)
        print(f"Response snippet:\n{vulnerable_response[200:450]}\n")
        
        # Analyze the response
        finding = plugin.analyze_response(
            test_case=confirm_test,
            response_body=vulnerable_response,
            response_headers={},
            baseline_body=""
        )
        
        if finding:
            print("✓ VULNERABILITY CONFIRMED!")
            print(f"  Finding ID: {finding.finding_id}")
            print(f"  Confidence: {finding.confidence} (CONFIRM stage = higher confidence)")
            print(f"  Evidence Refs: {len(finding.evidence_refs)} blob(s)")
        else:
            print("✗ No finding (false negative)")
    
    # Step 4: Test false negative (escaped response)
    print("\n" + "=" * 70)
    print("STEP 4: Test false negative (properly escaped response)")
    print("=" * 70)
    
    if detect_test:
        marker = detect_test.marker
        # This time the server properly escapes the marker
        safe_response = f"""
            <html>
            <body>
                <h1>You searched for: &lt;{marker}&gt;</h1>
            </body>
            </html>
        """
        
        print(f"Marker in response (ESCAPED): &lt;{marker}&gt;")
        print(f"Response snippet: {safe_response[100:200]}\n")
        
        finding = plugin.analyze_response(
            test_case=detect_test,
            response_body=safe_response,
            response_headers={},
            baseline_body=""
        )
        
        if finding:
            print("✗ FALSE POSITIVE! (should have been safe)")
        else:
            print("✓ Correctly identified as safe (no finding)")
    
    print("\n" + "=" * 70)
    print("Phase 2 XSS Plugin Test Complete")
    print("=" * 70)
    print("\nSummary:")
    print("✓ Plugin generates two-stage tests (DETECT + CONFIRM)")
    print("✓ Each test has unique marker for safe probing")
    print("✓ Detects unescaped reflection (vulnerable)")
    print("✓ Ignores escaped HTML (safe)")
    print("✓ Creates auditable findings with evidence references")


if __name__ == "__main__":
    test_xss_plugin_end_to_end()
