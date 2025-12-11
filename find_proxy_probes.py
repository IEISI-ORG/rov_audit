import os
import json
import argparse
import glob
from ripe.atlas.cousteau import ProbeRequest

# --- CONFIGURATION ---
DIR_JSON = "data/parsed"

def find_customers(target_asn):
    """
    Scans local JSON files to find ASNs that list target_asn as an upstream.
    Returns list of dicts: {'asn': 123, 'is_single_homed': True}
    """
    print(f"[*] Scanning local cache for customers of AS{target_asn}...")
    customers = []
    
    files = glob.glob(os.path.join(DIR_JSON, "*.json"))
    for f in files:
        try:
            with open(f, 'r') as h:
                data = json.load(h)
                
                # Check if target is in this ASN's upstream list
                if target_asn in data.get('upstreams', []):
                    # Found a customer!
                    upstreams = data['upstreams']
                    customers.append({
                        'asn': data['asn'],
                        'name': data.get('name', 'Unknown'),
                        'upstream_count': len(upstreams),
                        'is_single_homed': (len(upstreams) == 1)
                    })
        except: pass
        
    return customers

def check_atlas_for_probes(asn_list):
    """
    Batched query to RIPE Atlas to find probe counts for a list of ASNs.
    """
    if not asn_list: return {}
    
    # We query individually here because cousteau filters are AND based usually
    # For speed, we just check existence.
    results = {}
    
    print(f"[*] Checking RIPE Atlas for probes in {len(asn_list)} customer networks...")
    
    for i, item in enumerate(asn_list):
        asn = item['asn']
        try:
            filters = {"asn_v4": asn, "status": 1}
            probes = ProbeRequest(**filters)
            # We just need the count and IDs
            ids = [p["id"] for p in probes]
            if ids:
                results[asn] = ids
                
            # Progress output
            print(f"    - Checking AS{asn}... {len(ids)} probes found", end="\r")
        except: pass
        
    print(f"\n[*] Probe search complete.")
    return results

def main():
    parser = argparse.ArgumentParser(description="Find downstream customers with RIPE Atlas probes.")
    parser.add_argument("asn", type=int, help="Target Upstream ASN")
    args = parser.parse_args()

    # 1. Find Customers
    customers = find_customers(args.asn)
    if not customers:
        print("[-] No customers found in local cache. (Did you run the bulk scraper?)")
        return

    # Sort: Single-homed first (Best fidelity), then by ASN
    customers.sort(key=lambda x: (not x['is_single_homed'], x['asn']))
    
    print(f"    - Found {len(customers)} downstream customers in local cache.")

    # 2. Check for Probes
    # Limit to checking top 100 to avoid rate limits if the cone is huge
    check_list = customers[:100]
    probe_map = check_atlas_for_probes(check_list)

    # 3. Output
    print("\n" + "="*80)
    print(f"PROXY PROBE CANDIDATES FOR AS{args.asn}")
    print("="*80)
    print(f"{'CUST_ASN':<10} | {'Type':<12} | {'Probes':<6} | {'Name'}")
    print("-" * 80)

    found_any = False
    for c in customers:
        asn = c['asn']
        if asn in probe_map:
            found_any = True
            p_ids = probe_map[asn]
            htype = "Single-Homed" if c['is_single_homed'] else "Multi-Homed"
            color = "\033[92m" if c['is_single_homed'] else "\033[93m"
            reset = "\033[0m"
            
            print(f"{color}AS{asn:<8}{reset} | {htype:<12} | {len(p_ids):<6} | {c['name'][:40]}")

    if not found_any:
        print("[-] No probes found in the top 100 customers.")
        print("    Try scraping more downstream ASNs or the cone is just dark.")
    else:
        print("\n[+] To test, use: python3 verify_via_proxy.py [TARGET_ASN] --proxy-asn [CUST_ASN]")

if __name__ == "__main__":
    main()
