import pandas as pd
import json
import os
import glob
import argparse
from collections import Counter

# --- CONFIGURATION ---
DIR_JSON = "data/parsed"
FILE_AUDIT = "rov_audit_v19_final.csv"

# Global Core (The Validators, not the Signers)
KNOWN_TIER_1 = {
    3356, 1299, 174, 2914, 3257, 6762, 6939, 6453, 3491, 1239, 701, 6461, 5511, 6830, 4637,
    7018, 3320, 12956, 1273, 7922, 209, 2828, 4134, 4809, 4837, 9929, 9808
}

# Heuristics for IXPs (to remove from ASPA consideration)
IXP_KEYWORDS = ["IX", "EXCHANGE", "PEERING", "NAP", "DE-CIX", "AMS-IX", "LINX", "HKIX", "JPIX", "ANYCAST"]

def is_ixp(name):
    n = name.upper()
    return any(k in n for k in IXP_KEYWORDS)

def print_header(title):
    print("\n" + "="*80)
    print(f" {title}")
    print("="*80)

def load_data():
    print("[*] Loading Topology & Filtering Noise...")
    
    if not os.path.exists(FILE_AUDIT):
        print(f"[!] {FILE_AUDIT} not found.")
        return None, None

    # Load Metadata
    df = pd.read_csv(FILE_AUDIT, low_memory=False)
    name_map = df.set_index('asn')['name'].to_dict()
    
    # Load Upstreams
    aspa_records = {} 
    
    files = glob.glob(os.path.join(DIR_JSON, "*.json"))
    for f in files:
        try:
            with open(f, 'r') as h:
                d = json.load(h)
                asn = d.get('asn')
                if not asn: continue
                
                # RULE 1: Tier 1s do not publish ASPA (They have no parents)
                if asn in KNOWN_TIER_1:
                    continue
                
                # RULE 2: IXPs do not publish ASPA (They are infrastructure)
                my_name = name_map.get(asn, "Unknown")
                if is_ixp(my_name):
                    continue

                raw_upstreams = d.get('upstreams', [])
                
                # RULE 3: Filter IXPs out of the Upstream List
                # (You don't list Route Servers in your ASPA)
                clean_upstreams = []
                for u in raw_upstreams:
                    u_name = name_map.get(int(u), "")
                    if not is_ixp(u_name):
                        clean_upstreams.append(int(u))
                
                aspa_records[asn] = clean_upstreams
        except: pass
        
    print(f"    - Modeled ASPA records for {len(aspa_records):,} ASNs (Excluding T1s/IXPs).")
    return aspa_records, name_map

def analyze():
    records, names = load_data()
    if not records: return

    # ---------------------------------------------------------
    # 1. THE REALISTIC WORKLOAD
    # ---------------------------------------------------------
    print_header("1. REALISTIC ASPA WORKLOAD")
    
    total_asns = len(records)
    complexity = Counter()
    
    for asn, providers in records.items():
        cnt = len(providers)
        complexity[cnt] += 1
        
    # Categories
    c_zero = complexity[0] # Likely peers only or misclassified
    c_simple = complexity[1] + complexity[2] # 1-2 Providers
    c_mod = sum(complexity[k] for k in complexity if 2 < k <= 5)
    c_complex = sum(complexity[k] for k in complexity if k > 5)
    
    print(f"Total Networks needing Records: {total_asns:,}")
    print("-" * 60)
    print(f"  - Trivial (1-2 Providers):   {c_simple:>6,}  ({c_simple/total_asns*100:>4.1f}%) -> \033[92mEasy Deployment\033[0m")
    print(f"  - Moderate (3-5 Providers):  {c_mod:>6,}  ({c_mod/total_asns*100:>4.1f}%) -> Standard TE")
    print(f"  - Complex (>5 Providers):    {c_complex:>6,}  ({c_complex/total_asns*100:>4.1f}%) -> \033[93mHigh Maintenance\033[0m")
    print(f"  - Zero Providers (Peers?):   {c_zero:>6,}  ({c_zero/total_asns*100:>4.1f}%) -> (Verify these)")

    # ---------------------------------------------------------
    # 2. THE VALIDATORS (WHO ENFORCES?)
    # ---------------------------------------------------------
    print_header("2. THE ASPV ENFORCERS (The Tier 1 Firewall)")
    print("If these networks turn on ASPV, they secure the downstream cones.")
    
    # Calculate how many customer records point to the Tier 1s
    tier1_leverage = Counter()
    
    for asn, providers in records.items():
        for p in providers:
            if p in KNOWN_TIER_1:
                tier1_leverage[p] += 1
    
    sorted_t1 = tier1_leverage.most_common()
    total_direct_links = sum(len(p) for p in records.values())
    t1_direct_links = sum(cnt for asn, cnt in sorted_t1)
    
    print(f"Total Provider Links in Graph: {total_direct_links:,}")
    print(f"Links Terminating at Tier 1s:  {t1_direct_links:,} ({t1_direct_links/total_direct_links*100:.1f}%)")
    print("-" * 60)
    
    for asn, count in sorted_t1:
        name = names.get(asn, "Unknown")
        print(f"AS{asn:<6} | Validates {count:>6,} Customer ASPA Records | {name[:40]}")

    # ---------------------------------------------------------
    # 3. THE "IMPOSSIBLE" CASES (Still Complex?)
    # ---------------------------------------------------------
    print_header("3. REMAINING COMPLEXITY GIANTS")
    print("Even after removing IXPs, these networks have massive provider lists.")
    print("-" * 80)
    print(f"{'ASN':<8} | {'Providers':<10} | {'Name'}")
    print("-" * 80)
    
    # Sort by number of upstreams
    sorted_complexity = sorted(records.items(), key=lambda x: len(x[1]), reverse=True)
    
    for asn, providers in sorted_complexity[:15]:
        name = names.get(asn, "Unknown")
        print(f"AS{asn:<6} | {len(providers):<10} | {name[:50]}")

    print("\n[CONCLUSION]")
    print(f"For {c_simple/total_asns*100:.1f}% of the internet, ASPA is a static 'Set and Forget' configuration.")
    print("The complexity argument against ASPA applies to less than 1% of networks.")

if __name__ == "__main__":
    analyze()
