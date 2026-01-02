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

# 1. Global Core (Validators)
KNOWN_TIER_1 = {
    3356, 1299, 174, 2914, 3257, 6762, 6939, 6453, 3491, 1239, 701, 6461, 5511, 6830, 4637,
    7018, 3320, 12956, 1273, 7922, 209, 2828, 4134, 4809, 4837, 9929, 9808
}

# 2. Infrastructure (DNS Roots, Collectors, Blackholes) - NEW
KNOWN_INFRA = {
    # Root DNS & Critical Anycast
    19836, 4, 2149, 27, 297, 3557, 30132, 5927, 5001, 29216, 26415, 25152, 20144, 7500,
    112,   # AS112 Project
    42, 3856, # Packet Clearing House (PCH)
    # Cloudflare (Specific filtering as requested)
    13335, 209242, 395747,
    # Route Collectors
    6447,  # RouteViews
    12654, # RIPE RIS
}

# 3. Keyword Heuristics
IXP_KEYWORDS = [
    "IX", "EXCHANGE", "PEERING", "NAP", "DE-CIX", "AMS-IX", "LINX", "HKIX", "JPIX", 
    "ANYCAST", "ROUTE-SERVER", "ROOT-SERVER", "DNS-ROOT", "TLD", "REGISTRY"
]

def is_infrastructure(name, asn):
    if asn in KNOWN_INFRA: return True
    n = name.upper()
    
    # Keyword check
    if any(k in n for k in IXP_KEYWORDS): return True
    
    # Specific patterns for Collectors
    if "COLLECTOR" in n or "ROUTE VIEWS" in n or "RIPE NCC RIS" in n: return True
    
    return False

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
        col = next((c for c in df.columns if 'asn' in c.lower()), df.columns[0])
        df['x'] = df[col].astype(str).str.upper().str.replace('AS','', regex=False)
        cdn_set = set(df[df['x'].str.isnumeric()]['x'].astype(int))
        print(f"OK ({len(cdn_set)} Networks)")
    except:
        print("FAIL")
    return cdn_set

def load_data():
    print("[*] Loading Topology & Cleaning Noise...")
    
    if not os.path.exists(FILE_AUDIT):
        print(f"[!] {FILE_AUDIT} not found.")
        return None, None

    # Load Metadata
    df = pd.read_csv(FILE_AUDIT, low_memory=False)
    name_map = df.set_index('asn')['name'].to_dict()
    
    # Load CDNs
    cdn_set = load_cdns()
    
    # Load Upstreams
    aspa_records = {} 
    stats = Counter()
    
    files = glob.glob(os.path.join(DIR_JSON, "*.json"))
    for f in files:
        try:
            with open(f, 'r') as h:
                d = json.load(h)
                asn = d.get('asn')
                if not asn: continue
                
                my_name = name_map.get(asn, "Unknown")

                # --- FILTERS ---
                
                # 1. Tier 1
                if asn in KNOWN_TIER_1:
                    stats['tier1'] += 1; continue
                
                # 2. CDNs
                if asn in cdn_set:
                    stats['cdn'] += 1; continue

                # 3. Infrastructure (IXPs, Roots, Collectors)
                if is_infrastructure(my_name, asn):
                    stats['infra'] += 1; continue

                # --- PROCESS RECORD ---
                raw_upstreams = d.get('upstreams', [])
                
                # Filter the Provider List itself
                # (A record shouldn't list a Route Server as a Provider)
                clean_upstreams = []
                for u in raw_upstreams:
                    u_int = int(u)
                    u_name = name_map.get(u_int, "")
                    
                    if not is_infrastructure(u_name, u_int):
                        clean_upstreams.append(u_int)
                
                aspa_records[asn] = clean_upstreams
        except: pass
        
    print(f"    - Excluded: {stats['tier1']} Tier1s, {stats['cdn']} CDNs, {stats['infra']} Infra/IXPs")
    print(f"    - Modeled:  {len(aspa_records):,} 'Regular' Networks")
    return aspa_records, name_map

def analyze():
    records, names = load_data()
    if not records: return

    # ---------------------------------------------------------
    # 1. READINESS
    # ---------------------------------------------------------
    print_header("1. ASPA READINESS (Cleaned)")
    
    total = len(records)
    complexity = Counter()
    for asn, p in records.items(): complexity[len(p)] += 1
        
    c_simple = complexity[1] + complexity[2]
    c_mod = sum(complexity[k] for k in complexity if 2 < k <= 5)
    c_complex = sum(complexity[k] for k in complexity if k > 5)
    
    print(f"Total Networks: {total:,}")
    print("-" * 60)
    print(f"  - Trivial (1-2 Providers):   {c_simple:>6,} ({c_simple/total*100:>4.1f}%)")
    print(f"  - Moderate (3-5 Providers):  {c_mod:>6,} ({c_mod/total*100:>4.1f}%)")
    print(f"  - Complex (>5 Providers):    {c_complex:>6,} ({c_complex/total*100:>4.1f}%)")

    # ---------------------------------------------------------
    # 2. REMAINING GIANTS
    # ---------------------------------------------------------
    print_header("2. TRUE COMPLEXITY GIANTS (The last 1%)")
    print("Networks with the most Upstreams (excluding CDNs/Infra).")
    print("-" * 80)
    print(f"{'ASN':<8} | {'Providers':<10} | {'Name'}")
    print("-" * 80)
    
    sorted_complexity = sorted(records.items(), key=lambda x: len(x[1]), reverse=True)
    
    for asn, providers in sorted_complexity[:25]:
        name = names.get(asn, "Unknown")
        print(f"AS{asn:<6} | {len(providers):<10} | {name[:50]}")

if __name__ == "__main__":
    analyze()
