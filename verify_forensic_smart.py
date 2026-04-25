import argparse
import os
import json
import yaml
import time
import rov_utils
import verify_forensic_path_v2 as forensic
import batch_verify_smart_v4 as smart

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("asn", type=int, help="ASN to verify")
    args = parser.parse_args()

    if not forensic.ATLAS_API_KEY:
        print("[!] Missing RIPE Atlas API Key in secrets.yaml")
        return

    asn = args.asn
    print(f"\n--- SMART FORENSIC ANALYSIS: AS{asn} ---")
    
    # 1. Resolve IPs
    ip_v = forensic.resolve_ip(forensic.DOMAIN_VALID)
    ip_i = forensic.resolve_ip(forensic.DOMAIN_INVALID)
    
    # 2. Find Best Probes (Using Customer Cone)
    probes = smart.find_best_probes_in_cone(asn, count=5)
    if not probes:
        print(f"    [!] No probes found in cone of AS{asn}")
        return

    # 3. Launch Test
    print(f"    - Found {len(probes)} probes. Launching...")
    raw_results = forensic.run_forensic_test(asn, probes, ip_v, ip_i)
    
    if raw_results:
        # 4. Use the ENHANCED analysis logic
        analysis = forensic.analyze_results(asn, raw_results)
        
        # Save Result
        out_file = os.path.join("data/atlas", f"as_{asn}.json")
        with open(out_file, 'w') as f:
            json.dump(analysis, f, indent=2)
            
        color = "\033[92m" if "SECURE" in analysis['verdict'] else "\033[91m"
        print(f"\n    [+] ANALYSIS COMPLETE")
        print(f"    - Verdict:  {color}{analysis['verdict']}\033[0m")
        print(f"    - Notes:    {analysis['notes']}")
        print(f"    - Boundary: {analysis.get('filter_boundary')}")
        print(f"    - Passed:   {analysis.get('last_passed')}")
        print(f"    - Valid P:  {analysis['valid_path']}")
        print(f"    - Invalid P:{analysis['invalid_path']}")
    else:
        print("    [!] Forensic test failed.")

if __name__ == "__main__":
    main()
