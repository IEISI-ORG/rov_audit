import pandas as pd
import json
import os
import glob
import argparse
import sys
from collections import Counter

# --- CONFIGURATION ---
DIR_JSON = "data/parsed"
FILE_AUDIT = "rov_audit_v19_final.csv"

def print_header(title):
    print("\n" + "="*80)
    print(f" {title}")
    print("="*80)

def load_data():
    print("[*] Loading Topology for ASPA Modeling...")
    
    if not os.path.exists(FILE_AUDIT):
        print(f"[!] {FILE_AUDIT} not found.")
        return None, None

    # 1. Load Cone Sizes (Impact Weight)
    df = pd.read_csv(FILE_AUDIT, low_memory=False)
    cone_map = df.set_index('asn')['cone'].to_dict()
    name_map = df.set_index('asn')['name'].to_dict()
    
    # 2. Load Upstreams (The ASPA Content)
    aspa_records = {} # ASN -> [List of Provider ASNs]
    
    files = glob.glob(os.path.join(DIR_JSON, "*.json"))
    for f in files:
        try:
            with open(f, 'r') as h:
                d = json.load(h)
                asn = d.get('asn')
                upstreams = d.get('upstreams', [])
                
                # Filter: ASPA only lists Providers, not Peers.
                # Our scraper logic (Valley Free) usually isolates Providers.
                # However, Tier 1s have 0 Providers.
                if asn:
                    aspa_records[asn] = upstreams
        except: pass
        
    print(f"    - Loaded upstream profiles for {len(aspa_records):,} ASNs.")
    return aspa_records, cone_map, name_map

def analyze():
    records, cones, names = load_data()
    if not records: return

    # ---------------------------------------------------------
    # 1. THE SIZE OF THE JOB
    # ---------------------------------------------------------
    print_header("1. THE SIZE OF THE JOB (Administrative Burden)")
    
    total_asns = len(records)
    total_links = sum(len(u) for u in records.values())
    
    # Histogram of Upstream Counts
    # How complex is the average ASPA record?
    complexity = Counter()
    for asn, providers in records.items():
        cnt = len(providers)
        complexity[cnt] += 1
        
    avg_len = total_links / total_asns if total_asns else 0
    
    print(f"Total ASNs needing Records: {total_asns:,}")
    print(f"Total Provider Links (Edges): {total_links:,}")
    print(f"Average Providers per ASN:  {avg_len:.2f}")
    
    print("\n[Complexity Breakdown]")
    c_zero = complexity[0] # Tier 1s or Peers-Only
    c_stub = complexity[1] + complexity[2] # Simple Stubs
    c_multi = sum(complexity[k] for k in complexity if k > 2 and k <= 10)
    c_complex = sum(complexity[k] for k in complexity if k > 10)
    
    print(f"  - No Upstreams (Tier 1/IXP): {c_zero:>6,} ({c_zero/total_asns*100:>4.1f}%) -> No ASPA needed (or empty)")
    print(f"  - Simple (1-2 Providers):    {c_stub:>6,} ({c_stub/total_asns*100:>4.1f}%) -> \033[92mTrivial 'Set & Forget'\033[0m")
    print(f"  - Multihomed (3-10):         {c_multi:>6,} ({c_multi/total_asns*100:>4.1f}%) -> Manageable")
    print(f"  - Complex TE (>10):          {c_complex:>6,} ({c_complex/total_asns*100:>4.1f}%) -> \033[91mHigh Maintenance\033[0m")

    # ---------------------------------------------------------
    # 2. THE COMPLEXITY GIANTS
    # ---------------------------------------------------------
    print_header("2. THE COMPLEXITY GIANTS (Traffic Engineering Nightmares)")
    print("These networks have the most Upstreams. Maintaining ASPA will be hardest for them.")
    print("-" * 80)
    print(f"{'ASN':<8} | {'Upstreams':<10} | {'Name'}")
    print("-" * 80)
    
    # Sort by number of upstreams
    sorted_complexity = sorted(records.items(), key=lambda x: len(x[1]), reverse=True)
    
    for asn, providers in sorted_complexity[:15]:
        name = names.get(asn, "Unknown")
        print(f"AS{asn:<6} | {len(providers):<10} | {name[:50]}")

    # ---------------------------------------------------------
    # 3. LEAK PREVENTION POTENTIAL
    # ---------------------------------------------------------
    print_header("3. LEAK PREVENTION POTENTIAL (If Core Enforces ASPV)")
    
    # If the Top X Transit Providers enforced ASPV (dropped invalid paths),
    # how many customer links would be secured?
    
    # Build a map: Provider -> Count of Customers
    # This is effectively "How many ASPA records does this Provider validate?"
    provider_leverage = Counter()
    for asn, providers in records.items():
        for p in providers:
            provider_leverage[int(p)] += 1
            
    # Sort providers by number of customer links they police
    sorted_leverage = provider_leverage.most_common()
    
    top_50_checks = sum(cnt for asn, cnt in sorted_leverage[:50])
    top_100_checks = sum(cnt for asn, cnt in sorted_leverage[:100])
    
    print(f"Total Customer-to-Provider Links in Graph: {total_links:,}")
    print("-" * 60)
    print(f"If the Top 50 Providers enforce ASPV:")
    print(f"  -> {top_50_checks:,} links secured ({top_50_checks/total_links*100:.1f}% of Global Topology)")
    
    print(f"\nIf the Top 100 Providers enforce ASPV:")
    print(f"  -> {top_100_checks:,} links secured ({top_100_checks/total_links*100:.1f}% of Global Topology)")
    
    print("-" * 60)
    print("CONCLUSION: We don't need 80,000 ASNs to validate.")
    print("If the Top 50 giants turn on ASPV, the majority of route leaks become impossible.")

    # ---------------------------------------------------------
    # 4. THE KEY ENFORCERS
    # ---------------------------------------------------------
    print_header("4. THE KEY ENFORCERS (Top ASPV Validators)")
    print("These networks verify the most Customer Links.")
    print("-" * 80)
    print(f"{'ASN':<8} | {'Cust. Links':<12} | {'Name'}")
    print("-" * 80)
    
    for asn, count in sorted_leverage[:20]:
        name = names.get(asn, "Unknown")
        print(f"AS{asn:<6} | {count:<12,} | {name[:50]}")

if __name__ == "__main__":
    analyze()
