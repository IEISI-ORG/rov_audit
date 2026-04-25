import argparse
import pandas as pd
import os
import json
import yaml
import time
import glob
from datetime import datetime, timezone, timedelta
import rov_utils
import verify_forensic_path_v2 as forensic

# --- CONFIGURATION ---
DIR_ATLAS = "data/atlas"
TEST_TTL_DAYS = 7
MAX_TARGETS_PER_RUN = 5

def get_smart_targets(limit=5):
    """
    Finds targets that:
    1. Are high-impact (large cone)
    2. Are REGRESSED or VULNERABLE or UNRELIABLE
    3. Haven't been tested in the last 7 days
    """
    if not os.path.exists(rov_utils.FILE_AUDIT_FINAL):
        print(f"[!] {rov_utils.FILE_AUDIT_FINAL} not found.")
        return []

    df = pd.read_csv(rov_utils.FILE_AUDIT_FINAL)
    df['cone'] = pd.to_numeric(df['cone'], errors='coerce').fillna(0).astype(int)
    
    # Priority 1: REGRESSED giants
    # Priority 2: VULNERABLE/UNRELIABLE giants
    # Priority 3: Large Unverified transit
    
    def get_priority(row):
        v = str(row['verdict']).upper()
        cone = row['cone']
        if "REGRESSED" in v: return 100 + (cone / 1000)
        if "UNRELIABLE" in v or "VULNERABLE" in v: return 50 + (cone / 1000)
        if "UNVERIFIED" in v: return 10 + (cone / 1000)
        return 0
    
    df['priority'] = df.apply(get_priority, axis=1)
    candidates = df[df['priority'] > 0].sort_values(by='priority', ascending=False)
    
    targets = []
    now = datetime.now(timezone.utc)
    
    for _, row in candidates.iterrows():
        asn = int(row['asn'])
        file_path = os.path.join(DIR_ATLAS, f"as_{asn}.json")
        
        needs_test = True
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                    ts_str = data.get('timestamp')
                    if ts_str:
                        last_test = datetime.fromisoformat(ts_str)
                        if (now - last_test).days < TEST_TTL_DAYS:
                            needs_test = False
            except: pass
            
        if needs_test:
            targets.append(asn)
            
        if len(targets) >= limit:
            break
            
    return targets

def find_best_probes_in_cone(target_asn, count=5):
    """
    Finds probes inside the customer cone of target_asn.
    Prefers single-homed customers for high fidelity.
    """
    print(f"    - Searching for probes in the customer cone of AS{target_asn}...")
    
    # 1. Find customers from local cache
    # We use the logic from find_proxy_probes.py but integrated
    customers = []
    asn_data = rov_utils.load_all_asn_data()
    
    for asn, data in asn_data.items():
        if target_asn in data.get('upstreams', []):
            customers.append({
                'asn': asn,
                'is_single': (len(data.get('upstreams', [])) == 1)
            })
    
    # Sort: single-homed first
    customers.sort(key=lambda x: not x['is_single'])
    
    # 2. Check for probes in these customers
    found_probes = []
    # Check top 50 customers to avoid API hammering
    for c in customers[:50]:
        p_ids = forensic.get_probes(c['asn'], count=2)
        if p_ids:
            found_probes.extend(p_ids)
            print(f"      * Found {len(p_ids)} probes in customer AS{c['asn']}")
        
        if len(found_probes) >= count:
            break
            
    # 3. Fallback: Check target ASN itself
    if len(found_probes) < count:
        local_probes = forensic.get_probes(target_asn, count=(count - len(found_probes)))
        found_probes.extend(local_probes)
        if local_probes:
            print(f"      * Found {len(local_probes)} probes inside AS{target_asn} (Fallback)")
            
    return found_probes[:count]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=MAX_TARGETS_PER_RUN)
    args = parser.parse_args()

    if not forensic.ATLAS_API_KEY:
        print("[!] Missing RIPE Atlas API Key in secrets.yaml")
        return

    # Ensure DIR_ATLAS exists
    os.makedirs(DIR_ATLAS, exist_ok=True)

    # 1. Get Targets
    targets = get_smart_targets(limit=args.limit)
    if not targets:
        print("[*] No high-priority targets need testing today (TTL Active).")
        return
        
    print(f"[*] Smart Selection identified {len(targets)} targets for re-verification.")
    
    # 2. DNS Resolve targets once
    ip_v = forensic.resolve_ip(forensic.DOMAIN_VALID)
    ip_i = forensic.resolve_ip(forensic.DOMAIN_INVALID)
    if not ip_v or not ip_i:
        print("[!] DNS Resolution failed for test domains.")
        return

    # 3. Run Tests
    for asn in targets:
        print(f"\n>>> Verifying AS{asn} via Customer Cone probes...")
        
        probes = find_best_probes_in_cone(asn, count=5)
        if not probes:
            print(f"    [!] No usable probes found in cone of AS{asn}. Skipping.")
            continue
            
        print(f"    - Selected {len(probes)} probes for forensic trace.")
        raw_results = forensic.run_forensic_test(asn, probes, ip_v, ip_i)
        
        if raw_results:
            analysis = forensic.analyze_results(asn, raw_results)
            
            # Save Result
            out_file = os.path.join(DIR_ATLAS, f"as_{asn}.json")
            with open(out_file, 'w') as f:
                json.dump(analysis, f, indent=2)
                
            color = "\033[92m" if "SECURE" in analysis['verdict'] else "\033[91m"
            print(f"    - VERDICT: {color}{analysis['verdict']}\033[0m ({analysis['notes']})")
        else:
            print(f"    [!] Forensic test failed for AS{asn}")

if __name__ == "__main__":
    main()
