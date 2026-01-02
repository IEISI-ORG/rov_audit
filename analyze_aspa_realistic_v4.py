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
FILE_AUDIT = "rov_audit_v20_final.csv"

# URLs
URL_CDN_TAGS = "https://bgp.tools/tags/cdn.csv"

# 1. Global Core (Validators)
KNOWN_TIER_1 = {
    3356, 1299, 174, 2914, 3257, 6762, 6939, 6453, 3491, 1239, 701, 6461, 5511, 6830, 4637,
    7018, 3320, 12956, 1273, 7922, 209, 2828, 4134, 4809, 4837, 9929, 9808
}

# 2. Infrastructure
KNOWN_INFRA = {
    19836, 4, 2149, 27, 297, 3557, 30132, 5927, 5001, 29216, 26415, 25152, 20144, 7500,
    112, 42, 3856, 13335, 209242, 395747, 6447, 12654, 14789
}

IXP_KEYWORDS = [
    "IX", "EXCHANGE", "PEERING", "NAP", "DE-CIX", "AMS-IX", "LINX", "HKIX", "JPIX", 
    "ANYCAST", "ROUTE-SERVER", "ROOT-SERVER", "DNS-ROOT", "TLD", "REGISTRY"
]

def is_infrastructure(name, asn):
    if asn in KNOWN_INFRA: return True
    n = name.upper()
    if any(k in n for k in IXP_KEYWORDS): return True
    if "COLLECTOR" in n or "ROUTE VIEWS" in n or "RIPE NCC RIS" in n: return True
    return False

def print_header(title):
    print("\n" + "="*90)
    print(f" {title}")
    print("="*90)

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
        return None, None, None

    # Load Metadata & Cone Size
    df = pd.read_csv(FILE_AUDIT, low_memory=False)
    name_map = df.set_index('asn')['name'].to_dict()
    cone_map = df.set_index('asn')['cone'].to_dict()
    
    cdn_set = load_cdns()
    
    aspa_records = {} 
    
    files = glob.glob(os.path.join(DIR_JSON, "*.json"))
    for f in files:
        try:
            with open(f, 'r') as h:
                d = json.load(h)
                asn = d.get('asn')
                if not asn: continue
                
                my_name = name_map.get(asn, "Unknown")

                # Filters
                if asn in KNOWN_TIER_1: continue
                if asn in cdn_set: continue
                if is_infrastructure(my_name, asn): continue

                raw_upstreams = d.get('upstreams', [])
                clean_upstreams = []
                for u in raw_upstreams:
                    u_int = int(u)
                    u_name = name_map.get(u_int, "")
                    if not is_infrastructure(u_name, u_int):
                        clean_upstreams.append(u_int)
                
                aspa_records[asn] = clean_upstreams
        except: pass
        
    print(f"    - Modeled:  {len(aspa_records):,} 'Regular' Networks")
    return aspa_records, name_map, cone_map

def analyze():
    records, names, cones = load_data()
    if not records: return

    # ---------------------------------------------------------
    # 1. READINESS
    # ---------------------------------------------------------
    print_header("1. ASPA READINESS (Simplicity vs Complexity)")
    
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
    print(f"  - Complex (>5 Providers):    {c_complex:>6,} ({c_complex/total*100:>4.1f}%) -> \033[93mTarget for Engineering Support\033[0m")

    # ---------------------------------------------------------
    # 2. THE ENFORCERS
    # ---------------------------------------------------------
    print_header("2. THE ASPV ENFORCERS (Top Validators)")
    print("These networks will appear most frequently in Customer ASPA records.")
    print("If they turn on ASPV, they secure these links.")
    print("-" * 90)
    print(f"{'ASN':<8} | {'Cust. Links':<12} | {'Name'}")
    print("-" * 90)
    
    provider_counts = Counter()
    for asn, providers in records.items():
        for p in providers:
            provider_counts[p] += 1
            
    total_links = sum(provider_counts.values())
    top_50_links = sum(c for a,c in provider_counts.most_common(50))
    
    for asn, count in provider_counts.most_common(50):
        name = names.get(asn, "Unknown")
        print(f"AS{asn:<6} | {count:<12,} | {name[:50]}")

    print("-" * 90)
    print(f"Top 50 Enforcers cover {top_50_links:,} / {total_links:,} links ({top_50_links/total_links*100:.1f}%)")

    # ---------------------------------------------------------
    # 3. COMPLEXITY GIANTS
    # ---------------------------------------------------------
    print_header("3. COMPLEXITY GIANTS (Traffic Engineering Heavyweights)")
    print("Networks with >5 Upstreams (Highest Maintenance Burden).")
    print("-" * 90)
    print(f"{'ASN':<8} | {'Providers':<10} | {'Cone':<8} | {'Name'}")
    print("-" * 90)
    
    # Sort by Complexity (Upstream Count), then Cone Size
    complex_list = []
    for asn, providers in records.items():
        if len(providers) > 5:
            complex_list.append({
                'asn': asn,
                'count': len(providers),
                'cone': cones.get(asn, 0),
                'name': names.get(asn, "Unknown")
            })
            
    complex_list.sort(key=lambda x: (x['count'], x['cone']), reverse=True)
    
    # Print Top 50 to screen
    for item in complex_list[:50]:
        print(f"AS{item['asn']:<6} | {item['count']:<10} | {item['cone']:<8} | {item['name'][:50]}")

    # Save Full List
    if complex_list:
        df = pd.DataFrame(complex_list)
        df.to_csv("aspa_complexity_list.csv", index=False)
        print(f"\n[+] Full list of {len(complex_list)} complex networks saved to 'aspa_complexity_list.csv'")

if __name__ == "__main__":
    analyze()
