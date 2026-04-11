import pandas as pd
import json
import os
import csv
import sys
import requests
import glob
import gzip
from collections import defaultdict, Counter
from io import StringIO, BytesIO

# --- CONFIGURATION ---
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'}

# Inputs
FILE_GO_RELATIONSHIPS = "output/relationships.csv"
DIR_APNIC = "data/apnic"

# URLs
URL_ASNS_CSV = "https://bgp.tools/asns.csv"
URL_ROV_TAGS = "https://bgp.tools/tags/rpkirov.csv"
URL_CLOUDFLARE_CSV = "https://raw.githubusercontent.com/cloudflare/isbgpsafeyet.com/master/data/operators.csv"
URL_IPTOASN = "https://iptoasn.com/data/ip2asn-v4.tsv.gz" # <--- New Geo Source

# Tier 1 Definition
TIER_1_FIREWALL = {
    3356, 1299, 174, 2914, 3257, 6762, 6939, 6453, 3491, 1239, 701, 6461, 5511, 6830, 4637,
    7018, 3320, 12956, 1273, 7922, 209, 2828, 4134, 4809, 4837, 9929, 9808
}

def fetch_csv(url, name):
    print(f"    - Fetching {name}...", end=" ")
    try:
        resp = requests.get(url, headers=HEADERS)
        resp.raise_for_status()
        print(f"OK ({len(resp.content)//1024} KB)")
        return pd.read_csv(StringIO(resp.text))
    except Exception as e:
        print(f"FAIL ({e})")
        return pd.DataFrame()

def load_metadata():
    print("[1/5] Loading Metadata & Geography...")
    meta = {}

    # A. Names from BGP.Tools
    df = fetch_csv(URL_ASNS_CSV, "BGP.Tools ASN Names")
    if not df.empty:
        df.columns = [c.strip().lower() for c in df.columns]
        for _, row in df.iterrows():
            s = str(row.get('asn','')).upper().replace('AS','')
            if s.isdigit():
                meta[int(s)] = {'name': str(row.get('name','Unknown')), 'cc': 'XX'}

    # B. Countries from IPtoASN (The Fix)
    print("    - Fetching Country Codes (IPtoASN)...", end=" ")
    try:
        resp = requests.get(URL_IPTOASN, headers=HEADERS)
        resp.raise_for_status()
        
        # Decompress GZIP
        with gzip.open(BytesIO(resp.content), 'rt') as f:
            # TSV Format: range_start, range_end, AS_number, country_code, AS_description
            # We want to find the "Main" country for each ASN
            asn_countries = defaultdict(list)
            
            for line in f:
                parts = line.split('\t')
                if len(parts) < 4: continue
                asn_str = parts[2]
                cc = parts[3]
                
                if asn_str.isdigit() and len(cc) == 2:
                    asn_countries[int(asn_str)].append(cc)
            
            # Assign Mode Country
            updates = 0
            for asn, ccs in asn_countries.items():
                if asn in meta:
                    # Most common country code for this ASN's prefixes
                    primary_cc = Counter(ccs).most_common(1)[0][0].upper()
                    meta[asn]['cc'] = primary_cc
                    updates += 1
                    
            print(f"OK (Updated {updates} ASNs)")
            
    except Exception as e:
        print(f"FAIL ({e})")

    return meta

def load_security_status():
    print("[2/5] Loading Security Data...")
    
    # 1. BGP Tools ROV Tags
    rov_set = set()
    df = fetch_csv(URL_ROV_TAGS, "ROV Tags")
    if not df.empty:
        col = next((c for c in df.columns if 'asn' in c.lower()), df.columns[0])
        df['x'] = df[col].astype(str).str.upper().str.replace('AS','', regex=False)
        rov_set = set(df[df['x'].str.isnumeric()]['x'].astype(int))

    # 2. Cloudflare Safe List
    cf_set = set()
    df_cf = fetch_csv(URL_CLOUDFLARE_CSV, "Cloudflare List")
    if not df_cf.empty:
        df_cf.columns = [c.strip().lower() for c in df_cf.columns]
        if 'asn' in df_cf.columns:
            for val in df_cf['asn']:
                if str(val).isdigit(): cf_set.add(int(val))

    # 3. APNIC Scores
    apnic_map = {}
    files = glob.glob(os.path.join(DIR_APNIC, "*.json"))
    for f in files:
        try:
            with open(f) as h:
                for k,v in json.load(h).items(): apnic_map[int(k)] = v
        except: pass
    
    print(f"    - Sources: {len(rov_set)} Tagged, {len(cf_set)} CF-Safe, {len(apnic_map)} APNIC Measured")
    return rov_set, cf_set, apnic_map

def build_topology_from_go():
    print("[3/5] Building Topology from RIS (Go Output)...")
    if not os.path.exists(FILE_GO_RELATIONSHIPS):
        print(f"[!] Error: {FILE_GO_RELATIONSHIPS} not found. Run the Go tool first!")
        sys.exit(1)

    adj = defaultdict(set)
    with open(FILE_GO_RELATIONSHIPS, 'r') as f:
        reader = csv.reader(f)
        next(reader, None)
        for row in reader:
            if len(row) < 3: continue
            as1, as2 = int(row[0]), int(row[1])
            adj[as1].add(as2)
            adj[as2].add(as1)
            
    degrees = {k: len(v) for k,v in adj.items()}
    print(f"    - Analyzed adjacency for {len(degrees)} ASNs.")

    upstream_map = defaultdict(set)
    downstream_map = defaultdict(set)
    
    with open(FILE_GO_RELATIONSHIPS, 'r') as f:
        reader = csv.reader(f)
        next(reader, None)
        seen = set()
        
        for row in reader:
            if len(row) < 3: continue
            as1, as2 = int(row[0]), int(row[1])
            pair = tuple(sorted((as1, as2)))
            if pair in seen: continue
            seen.add(pair)

            d1, d2 = degrees[as1], degrees[as2]
            RATIO = 4.0
            
            provider, customer = None, None
            if d1 > d2 * RATIO: provider, customer = as1, as2
            elif d2 > d1 * RATIO: provider, customer = as2, as1
            
            if customer in TIER_1_FIREWALL: continue
            
            if provider and customer:
                upstream_map[customer].add(provider)
                downstream_map[provider].add(customer)

    return upstream_map, downstream_map

def calculate_cones(downstream_map):
    print("[4/5] Calculating Cone Sizes (Recursive)...")
    cone_sizes = {}
    memo = {}

    def get_cone_set(asn):
        if asn in memo: return memo[asn]
        my_cone = set()
        for child in downstream_map.get(asn, []):
            my_cone.add(child)
            my_cone.update(get_cone_set(child))
        memo[asn] = my_cone
        return my_cone

    count = 0
    total = len(downstream_map)
    for asn in downstream_map.keys():
        c = get_cone_set(asn)
        cone_sizes[asn] = len(c)
        count += 1
        if count % 5000 == 0: print(f"    - Calculated {count}/{total}...", end="\r")
    print("")
    return cone_sizes

def analyze():
    meta = load_metadata()
    rov_set, cf_set, apnic_map = load_security_status()
    upstreams, downstreams = build_topology_from_go()
    cones = calculate_cones(downstreams)

    print("[5/5] Generating Audit...")
    results = []
    
    # Safe Set
    safe_asns = set()
    all_asns = set(meta.keys()) | set(cones.keys()) | set(upstreams.keys())
    
    for asn in all_asns:
        if (asn in rov_set) or (asn in cf_set) or (apnic_map.get(asn, -1) >= 95.0):
            safe_asns.add(asn)

    # Audit
    for asn in all_asns:
        name = meta.get(asn, {}).get('name', 'Unknown')
        cc = meta.get(asn, {}).get('cc', 'XX')
        cone = cones.get(asn, 0)
        parents = upstreams.get(asn, [])
        score = apnic_map.get(asn, -1)
        
        is_safe_self = asn in safe_asns
        
        verdict = "Unknown"
        dirty_ups = 0
        
        if asn in TIER_1_FIREWALL:
            verdict = "CORE: PROTECTED" if is_safe_self else "CORE: UNPROTECTED"
        elif not parents:
            if cone > 0: verdict = "Unverified (Peer/Transit?)"
            else: verdict = "Stub / Leaf"
        else:
            dirty_ups = sum(1 for p in parents if p not in safe_asns)
            total = len(parents)
            
            if dirty_ups == 0: verdict = "SECURE (Full Coverage)"
            elif is_safe_self: verdict = "SECURE (Active Local ROV)"
            elif dirty_ups < total: verdict = "PARTIAL (Mixed Feeds)"
            else: verdict = "VULNERABLE (No Coverage)"

        results.append({
            'asn': asn, 'name': name, 'cc': cc, 'cone': cone,
            'verdict': verdict, 'apnic_score': score,
            'dirty_feeds': dirty_ups, 'total_feeds': len(parents)
        })

    df = pd.DataFrame(results)
    
    # Save
    filename = "rov_audit_v15_no_scrape.csv"
    df = df[df['asn'] > 0]
    df.sort_values(by='cone', ascending=False).to_csv(filename, index=False)
    
    # Report
    print("\n" + "="*80)
    print("NO-SCRAPE AUDIT RESULTS (GEO-ENRICHED)")
    print("="*80)
    
    vuln = df[df['verdict'] == "VULNERABLE (No Coverage)"]
    print(f"Total ASNs:      {len(df):,}")
    print(f"Fully Vulnerable: {len(vuln):,}")
    
    print("\n[TOP 20 VULNERABLE NETWORKS]")
    print(f"{'ASN':<8} | {'CC':<2} | {'Cone':<8} | {'Feeds':<6} | {'Name'}")
    print("-" * 80)
    for _, r in vuln.head(20).iterrows():
        ups = f"{r['dirty_feeds']}/{r['total_feeds']}"
        print(f"AS{r['asn']:<6} | {r['cc']:<2} | {r['cone']:<8} | {ups:<6} | {r['name'][:40]}")

    print(f"\n[+] Saved to {filename}")

if __name__ == "__main__":
    analyze()
