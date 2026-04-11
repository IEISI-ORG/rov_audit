import pandas as pd
import json
import os
import glob
import argparse
import requests
from collections import Counter
from io import StringIO

# --- CONFIGURATION ---
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'}
DIR_JSON = "data/parsed"
FILE_AUDIT = "rov_audit_v19_final.csv"

# URLs
URL_CDN_TAGS = "https://bgp.tools/tags/cdn.csv"

# Global Core (Validators)
KNOWN_TIER_1 = {
    3356, 1299, 174, 2914, 3257, 6762, 6939, 6453, 3491, 1239, 701, 6461, 5511, 6830, 4637,
    7018, 3320, 12956, 1273, 7922, 209, 2828, 4134, 4809, 4837, 9929, 9808
}

# Heuristics for IXPs
IXP_KEYWORDS = ["IX", "EXCHANGE", "PEERING", "NAP", "DE-CIX", "AMS-IX", "LINX", "HKIX", "JPIX", "ANYCAST", "ROUTE-SERVER"]

def is_ixp(name):
    n = name.upper()
    return any(k in n for k in IXP_KEYWORDS)

def print_header(title):
    print("\n" + "="*80)
    print(f" {title}")
    print("="*80)

def load_cdns():
    print("    - Fetching CDN List...", end=" ")
    cdn_set = set()
    try:
        resp = requests.get(URL_CDN_TAGS, headers=HEADERS)
        df = pd.read_csv(StringIO(resp.text))
        # Find ASN column
        col = next((c for c in df.columns if 'asn' in c.lower()), df.columns[0])
        # Clean 'AS' prefix
        df['x'] = df[col].astype(str).str.upper().str.replace('AS','', regex=False)
        cdn_set = set(df[df['x'].str.isnumeric()]['x'].astype(int))
        print(f"OK ({len(cdn_set)} Networks)")
    except:
        print("FAIL")
    return cdn_set

def load_data():
    print("[*] Loading Topology & Filtering Noise...")
    
    if not os.path.exists(FILE_AUDIT):
        print(f"[!] {FILE_AUDIT} not found.")
        return None, None

    # Load Metadata
    df = pd.read_csv(FILE_AUDIT, low_memory=False)
    name_map = df.set_index('asn')['name'].to_dict()
    
    # Load Exclusions
    cdn_set = load_cdns()
    
    # Load Upstreams
    aspa_records = {} 
    excluded_counts = {'tier1': 0, 'cdn': 0, 'ixp': 0}
    
    files = glob.glob(os.path.join(DIR_JSON, "*.json"))
    for f in files:
        try:
            with open(f, 'r') as h:
                d = json.load(h)
                asn = d.get('asn')
                if not asn: continue
                
                # RULE 1: Exclude Tier 1 (Validators)
                if asn in KNOWN_TIER_1:
                    excluded_counts['tier1'] += 1
                    continue
                
                # RULE 2: Exclude CDNs (Sophisticated Actors)
                if asn in cdn_set:
                    excluded_counts['cdn'] += 1
                    continue

                # RULE 3: Exclude IXPs (Infrastructure)
                my_name = name_map.get(asn, "Unknown")
                if is_ixp(my_name):
                    excluded_counts['ixp'] += 1
                    continue

                raw_upstreams = d.get('upstreams', [])
                
                # RULE 4: Filter IXPs/CDNs out of the *Upstream List* too
                # (You generally don't list RS or Peers in ASPA)
                clean_upstreams = []
                for u in raw_upstreams:
                    u_int = int(u)
                    u_name = name_map.get(u_int, "")
                    
                    # Keep only real Transit Providers
                    if not is_ixp(u_name):
                        clean_upstreams.append(u_int)
                
                aspa_records[asn] = clean_upstreams
        except: pass
        
    print(f"    - Filtered Stats: {excluded_counts}")
    print(f"    - Modeled ASPA records for {len(aspa_records):,} 'Regular' ASNs.")
    return aspa_records, name_map

def analyze():
    records, names = load_data()
    if not records: return

    # ---------------------------------------------------------
    # 1. THE REALISTIC WORKLOAD (Regular Internet)
    # ---------------------------------------------------------
    print_header("1. ASPA READINESS (Regular ISPs & Enterprise)")
    
    total_asns = len(records)
    complexity = Counter()
    
    for asn, providers in records.items():
        cnt = len(providers)
        complexity[cnt] += 1
        
    # Categories
    c_zero = complexity[0]
    c_simple = complexity[1] + complexity[2] # 1-2 Providers
    c_mod = sum(complexity[k] for k in complexity if 2 < k <= 5)
    c_complex = sum(complexity[k] for k in complexity if k > 5)
    
    print(f"Total Networks needing Records: {total_asns:,}")
    print("-" * 60)
    print(f"  - Trivial (1-2 Providers):   {c_simple:>6,}  ({c_simple/total_asns*100:>4.1f}%) -> \033[92mZero Config/Static\033[0m")
    print(f"  - Moderate (3-5 Providers):  {c_mod:>6,}  ({c_mod/total_asns*100:>4.1f}%) -> Low Maintenance")
    print(f"  - Complex (>5 Providers):    {c_complex:>6,}  ({c_complex/total_asns*100:>4.1f}%) -> Engineering Required")
    print(f"  - Peers Only / Unverified:   {c_zero:>6,}  ({c_zero/total_asns*100:>4.1f}%)")

    # ---------------------------------------------------------
    # 2. VALIDATION LEVERAGE
    # ---------------------------------------------------------
    print_header("2. IF TIER 1s VALIDATE...")
    
    total_links = sum(len(p) for p in records.values())
    
    # How many of these links point to a Tier 1?
    t1_links = 0
    provider_counts = Counter()
    
    for asn, providers in records.items():
        for p in providers:
            provider_counts[p] += 1
            if p in KNOWN_TIER_1:
                t1_links += 1
                
    print(f"Total Provider-Customer Links: {total_links:,}")
    print(f"Links Terminating at Tier 1s:  {t1_links:,} ({t1_links/total_links*100:.1f}%)")
    print("\n[CONCLUSION]")
    print(f"If just the Global Core ({len(KNOWN_TIER_1)} networks) turns on ASPV:")
    print(f"They secure {t1_links:,} edges instantly.")

    # ---------------------------------------------------------
    # 3. TRUE COMPLEXITY GIANTS (No CDNs/IXPs)
    # ---------------------------------------------------------
    print_header("3. THE REMAINING COMPLEX NETWORKS")
    print("These are standard ISPs/Enterprises with high upstream diversity.")
    print("-" * 80)
    print(f"{'ASN':<8} | {'Providers':<10} | {'Name'}")
    print("-" * 80)
    
    sorted_complexity = sorted(records.items(), key=lambda x: len(x[1]), reverse=True)
    
    for asn, providers in sorted_complexity[:20]:
        name = names.get(asn, "Unknown")
        print(f"AS{asn:<6} | {len(providers):<10} | {name[:50]}")

if __name__ == "__main__":
    analyze()
