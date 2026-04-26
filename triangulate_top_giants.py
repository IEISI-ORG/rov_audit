import argparse
import pandas as pd
import os
import json
import time
from datetime import datetime, timezone
import rov_utils
import verify_forensic_path_v2 as forensic
import batch_verify_smart_v4 as smart

# --- CONFIGURATION ---
DIR_ATLAS = "data/atlas"
DEFAULT_LIMIT = 5
TOP_N_GIANTS = 1000

def find_triangulated_probes(target_asn, probe_count=5):
    """
    Finds probes in different downstream networks to triangulate the provider's status.
    Attempts to pick 1 probe each from 'probe_count' different customer ASNs.
    """
    print(f"    - Triangulating probes for AS{target_asn}...")
    
    # 1. Get all customers from packed data
    asn_data = rov_utils.load_all_asn_data()
    customers = []
    for asn, data in asn_data.items():
        if target_asn in data.get('upstreams', []):
            customers.append({
                'asn': asn,
                'is_single': (len(data.get('upstreams', [])) == 1),
                'cone': data.get('cone_size', 0)
            })
    
    # Sort: Single-homed first (highest fidelity), then by cone size (importance)
    customers.sort(key=lambda x: (not x['is_single'], -x['cone']))
    
    selected_probes = []
    seen_asns = set()
    
    # 2. Iterate customers and pick ONE probe from each until we hit probe_count
    for c in customers:
        if len(selected_probes) >= probe_count:
            break
            
        c_asn = c['asn']
        p_ids = forensic.get_probes(c_asn, count=1) # Just one per network for triangulation
        if p_ids:
            selected_probes.append(p_ids[0])
            seen_asns.add(c_asn)
            print(f"      * Perspective added: AS{c_asn} (Cone: {c['cone']})")
            
    # 3. Fallback: If we don't have enough, allow multiple probes per ASN or target ASN itself
    if len(selected_probes) < probe_count:
        print(f"      ! Low diversity in cone, adding fallback probes...")
        local = forensic.get_probes(target_asn, count=(probe_count - len(selected_probes)))
        selected_probes.extend(local)
        
    return selected_probes[:probe_count]

def main():
    parser = argparse.ArgumentParser(description="Triangulate ROV status for the top 1000 internet giants.")
    parser.add_argument("--limit", type=int, default=DEFAULT_LIMIT, help="Number of giants to test in this run")
    parser.add_argument("--force", action="store_true", help="Ignore 7-day TTL")
    args = parser.parse_args()

    if not forensic.ATLAS_API_KEY:
        print("[!] Missing RIPE Atlas API Key"); return

    # 1. Load Audit and pick Top 1000
    if not os.path.exists(rov_utils.FILE_AUDIT_FINAL):
        print(f"[!] Audit file missing."); return

    df = pd.read_csv(rov_utils.FILE_AUDIT_FINAL)
    df['cone'] = pd.to_numeric(df['cone'], errors='coerce').fillna(0).astype(int)
    
    # Filter for Top Giants
    giants = df.sort_values(by='cone', ascending=False).head(TOP_N_GIANTS)
    
    targets = []
    now = datetime.now(timezone.utc)
    
    print(f"[*] Scanning Top {TOP_N_GIANTS} Giants for re-verification targets...")
    
    for _, row in giants.iterrows():
        asn = int(row['asn'])
        file_path = os.path.join(DIR_ATLAS, f"as_{asn}.json")
        
        needs_test = True
        if not args.force and os.path.exists(file_path):
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    ts_str = data.get('timestamp')
                    if ts_str:
                        last_test = datetime.fromisoformat(ts_str)
                        if (now - last_test).days < 7:
                            needs_test = False
            except: pass
            
        if needs_test:
            targets.append((asn, row['name'], row['cone']))
        
        if len(targets) >= args.limit:
            break

    if not targets:
        print("[*] All giants have been verified within the last 7 days.")
        return

    # 2. Run Tests
    ip_v = forensic.resolve_ip(forensic.DOMAIN_VALID)
    ip_i = forensic.resolve_ip(forensic.DOMAIN_INVALID)

    for asn, name, cone in targets:
        print(f"\n>>> Triangulating AS{asn} ({name}) | Cone: {cone}")
        probes = find_triangulated_probes(asn)
        
        if not probes:
            print(f"    [!] No probes found for AS{asn}. Skipping.")
            continue
            
        print(f"    - Selected {len(probes)} unique perspective probes. Launching...")
        raw_results = forensic.run_forensic_test(asn, probes, ip_v, ip_i)
        
        if raw_results:
            analysis = forensic.analyze_results(asn, raw_results)
            with open(os.path.join(DIR_ATLAS, f"as_{asn}.json"), 'w') as f:
                json.dump(analysis, f, indent=2)
            
            color = "\033[92m" if "SECURE" in analysis['verdict'] else "\033[91m"
            boundary_info = f"Boundary: {analysis.get('filter_boundary')}" if analysis.get('filter_boundary') else f"Last Passed: {analysis.get('last_passed')}"
            print(f"    - VERDICT: {color}{analysis['verdict']}\033[0m | {boundary_info}")
        else:
            print(f"    [!] Test failed for AS{asn}")

if __name__ == "__main__":
    main()
