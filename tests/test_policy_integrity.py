import pandas as pd
import os
import sys
import rov_utils

def test_tier1_gravity():
    """Verify that Tier 1 networks have significant customer cones."""
    print("[*] Testing Tier 1 Gravity...")
    if not os.path.exists(rov_utils.FILE_AUDIT_FINAL):
        print("    [!] Audit file missing, skipping.")
        return True

    df = pd.read_csv(rov_utils.FILE_AUDIT_FINAL)
    # Check a few major Tier 1s that should NEVER have zero cones
    major_t1s = [3356, 174, 2914, 2828, 1239]
    
    failed = False
    for asn in major_t1s:
        row = df[df['asn'] == asn]
        if row.empty:
            print(f"    [FAIL] AS{asn} missing from audit results.")
            failed = True
            continue
        
        cone = int(row.iloc[0]['cone'])
        if cone < 100:
            print(f"    [FAIL] AS{asn} has suspiciously low cone: {cone}")
            failed = True
        else:
            print(f"    [PASS] AS{asn} gravity: {cone}")
    
    return not failed

def test_verdict_consistency():
    """Ensure classification logic correctly buckets our standard labels."""
    print("[*] Testing Verdict Classification...")
    test_cases = [
        ("REGRESSED", "VULNERABLE"),
        ("UNRELIABLE", "VULNERABLE"),
        ("VOLATILE", "SECURE"),
        ("STUB: PASSIVE (Clean Pipe)", "SECURE"),
        ("PARTIAL: VULNERABLE (Mixed)", "PARTIAL")
    ]
    
    failed = False
    for input_v, expected_cat in test_cases:
        actual = rov_utils.classify_verdict(input_v)
        if actual != expected_cat:
            print(f"    [FAIL] '{input_v}' mapped to {actual}, expected {expected_cat}")
            failed = True
        else:
            print(f"    [PASS] '{input_v}' -> {actual}")
            
    return not failed

if __name__ == "__main__":
    t1_ok = test_tier1_gravity()
    verdict_ok = test_verdict_consistency()
    
    if not (t1_ok and verdict_ok):
        print("\n[!] INTEGRITY TESTS FAILED")
        sys.exit(1)
    
    print("\n[+] ALL INTEGRITY TESTS PASSED")
    sys.exit(0)
