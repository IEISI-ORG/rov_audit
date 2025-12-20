import pandas as pd
import json
import os
import csv
import sys
import requests
import glob
import gzip
import time
import re
from collections import defaultdict, Counter
from io import StringIO, BytesIO

# --- CONFIGURATION ---
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'}

# Inputs
FILE_GO_RELATIONSHIPS = "output/relationships.csv"
DIR_APNIC = "data/apnic"
os.makedirs(DIR_APNIC, exist_ok=True)

# URLs
URL_ASNS_CSV = "https://bgp.tools/asns.csv"
URL_ROV_TAGS = "https://bgp.tools/tags/rpkirov.csv"
URL_CLOUDFLARE_CSV = "https://raw.githubusercontent.com/cloudflare/isbgpsafeyet.com/master/data/operators.csv"
URL_IPTOASN = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"

# Constants
CACHE_TTL = 86400 # 24 Hours

# Tier 1 / Global Core Definition
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

# ==============================================================================
# 1. METADATA & GEO
# ==============================================================================
def load_metadata():
    print("[1/6] Loading Metadata & Geography...")
    meta = {}

    # A. Names
    df = fetch_csv(URL_ASNS_CSV, "BGP.Tools ASN Names")
    if not df.empty:
        df.columns = [c.strip().lower() for c in df.columns]
        for _, row in df.iterrows():
            s = str(row.get('asn','')).upper().replace('AS','')
            if s.isdigit():
                meta[int(s)] = {'name': str(row.get('name','Unknown')), 'cc': 'XX'}

    # B. Countries (IPtoASN)
    print("    - Fetching Country Codes (IPtoASN)...", end=" ")
    unique_ccs = set()
    try:
        resp = requests.get(URL_IPTOASN, headers=HEADERS)
        with gzip.open(BytesIO(resp.content), 'rt') as f:
            asn_countries = defaultdict(list)
            for line in f:
                parts = line.split('\t')
                if len(parts) < 4: continue
                asn_str, cc = parts[2], parts[3]
                if asn_str.isdigit() and len(cc) == 2:
                    asn_countries[int(asn_str)].append(cc)
            
            updates = 0
            for asn, ccs in asn_countries.items():
                primary_cc = Counter(ccs).most_common(1)[0][0].upper()
                unique_ccs.add(primary_cc)
                if asn in meta:
                    meta[asn]['cc'] = primary_cc
                    updates += 1
            print(f"OK (Updated {updates} ASNs)")
    except Exception as e:
        print(f"FAIL ({e})")

    return meta, unique_ccs

# ==============================================================================
# 2. APNIC SYNC
# ==============================================================================
def sync_apnic_data(countries):
    print(f"[2/6] Syncing APNIC RPKI Data ({len(countries)} Countries)...")
    pattern = re.compile(r'>AS(\d+)<.*?\{v:\s*([\d\.]+)', re.IGNORECASE)
    
    updated = 0
    cached = 0
    
    for cc in countries:
        if cc == "XX": continue
        file_path = os.path.join(DIR_APNIC, f"{cc}.json")
        
        if os.path.exists(file_path):
            age = time.time() - os.path.getmtime(file_path)
            if age < CACHE_TTL:
                cached += 1
                continue
        
        try:
            time.sleep(0.2)
            url = f"https://stats.labs.apnic.net/rpki/{cc}"
            resp = requests.get(url, headers=HEADERS, timeout=10)
            if resp.status_code == 200:
                scores = {}
                matches = pattern.findall(resp.text)
                for asn_str, val in matches: scores[int(asn_str)] = float(val)
                if scores:
                    with open(file_path, 'w') as f: json.dump(scores, f)
                    updated += 1
                    print(f"    - Updated {cc}: {len(scores)} records", end="\r")
            else:
                with open(file_path, 'w') as f: json.dump({}, f)
        except: pass
    print(f"\n    - Sync Complete: {updated} Fetched, {cached} Cached.")

def load_security_status():
    print("[3/6] Loading Security Data...")
    rov_set = set()
    df = fetch_csv(URL_ROV_TAGS, "ROV Tags")
    if not df.empty:
        col = next((c for c in df.columns if 'asn' in c.lower()), df.columns[0])
        df['x'] = df[col].astype(str).str.upper().str.replace('AS','', regex=False)
        rov_set = set(df[df['x'].str.isnumeric()]['x'].astype(int))

    cf_set = set()
    df_cf = fetch_csv(URL_CLOUDFLARE_CSV, "Cloudflare List")
    if not df_cf.empty:
        df_cf.columns = [c.strip().lower() for c in df_cf.columns]
        if 'asn' in df_cf.columns:
            for val in df_cf['asn']:
                if str(val).isdigit(): cf_set.add(int(val))

    apnic_map = {}
    files = glob.glob(os.path.join(DIR_APNIC, "*.json"))
    for f in files:
        try:
            with open(f) as h:
                for k,v in json.load(h).items(): apnic_map[int(k)] = v
        except: pass
    
    print(f"    - Loaded: {len(rov_set)} Tagged, {len(cf_set)} CF-Safe, {len(apnic_map)} APNIC Scores")
    return rov_set, cf_set, apnic_map

# ==============================================================================
# 3. TOPOLOGY
# ==============================================================================
def build_topology_from_go():
    print("[4/6] Building Topology from RIS (Go Output)...")
    if not os.path.exists(FILE_GO_RELATIONSHIPS):
        print(f"[!] Error: {FILE_GO_RELATIONSHIPS} not found.")
        sys.exit(1)

    adj = defaultdict(set)
    with open(FILE_GO_RELATIONSHIPS, 'r') as f:
        reader = csv.reader(f)
        next(reader, None)
        for row in reader:
            if len(row) < 3: continue
            adj[int(row[0])].add(int(row[1]))
            adj[int(row[1])].add(int(row[0]))
            
    degrees = {k: len(v) for k,v in adj.items()}
    
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
            provider, customer = None, None
            # 4x Ratio for Valley Free
            if d1 > d2 * 4.0: provider, customer = as1, as2
            elif d2 > d1 * 4.0: provider, customer = as2, as1
            
            if customer in TIER_1_FIREWALL: continue
            
            if provider:
                upstream_map[customer].add(provider)
                downstream_map[provider].add(customer)

    return upstream_map, downstream_map

def calculate_cones(downstream_map):
    print("[5/6] Calculating Cone Sizes...")
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

# ==============================================================================
# 4. AUDIT
# ==============================================================================
def analyze():
    meta, countries = load_metadata()
    sync_apnic_data(countries)
    rov_set, cf_set, apnic_map = load_security_status()
    upstreams, downstreams = build_topology_from_go()
    cones = calculate_cones(downstreams)

    print("[6/6] Generating Audit...")
    results = []
    
    # Universe = Metadata + Topology
    all_asns = set(meta.keys()) | set(cones.keys()) | set(upstreams.keys())
    
    # Safe Set
    safe_asns = set()
    for asn in all_asns:
        if (asn in rov_set) or (asn in cf_set) or (apnic_map.get(asn, -1) >= 95.0):
            safe_asns.add(asn)

    # Counters
    stats = {
        'stub': 0,
        'unrouted': 0
    }

    for asn in all_asns:
        name = meta.get(asn, {}).get('name', 'Unknown')
        cc = meta.get(asn, {}).get('cc', 'XX')
        cone = cones.get(asn, 0)
        parents = upstreams.get(asn, [])
        score = apnic_map.get(asn, -1)
        
        is_safe_self = asn in safe_asns
        
        verdict = "Unknown"
        dirty_ups = 0
        
        # LOGIC TREE
        if asn in TIER_1_FIREWALL:
            verdict = "CORE: PROTECTED" if is_safe_self else "CORE: UNPROTECTED"
        elif not parents:
            if cone > 0: 
                # Has children but no parents (Tier 1 candidate or peering-only)
                verdict = "Unverified (Transit/Peer)"
            else:
                # No parents, no children
                verdict = "NOT ROUTED (Visible in Registry)"
                stats['unrouted'] += 1
        else:
            # Has Parents
            if cone == 0:
                # Has parents, no children -> STUB
                stats['stub'] += 1
                # Still check security for stubs
                dirty_ups = sum(1 for p in parents if p not in safe_asns)
                total = len(parents)
                
                if dirty_ups == 0: verdict = "STUB: SECURE (Full Coverage)"
                elif is_safe_self: verdict = "STUB: SECURE (Active ROV)"
                else: verdict = "STUB: VULNERABLE"
            else:
                # Transit Provider
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
    
    # --- STATS & REPORT ---
    print("\n" + "="*80)
    print("NO-SCRAPE GLOBAL AUDIT (V17)")
    print("="*80)
    
    q_stub = stats['stub']
    q_unrouted = stats['unrouted']
    q_vuln_transit = len(df[df['verdict'] == "VULNERABLE (No Coverage)"])
    q_vuln_stub = len(df[df['verdict'] == "STUB: VULNERABLE"])
    
    print(f"Total ASNs in DB:        {len(df):,}")
    print(f"Total Not Routed:        {q_unrouted:,} (Registry only)")
    print(f"Total Active Stubs:      {q_stub:,} (End users)")
    print("-" * 40)
    print(f"Vulnerable Stubs:        {q_vuln_stub:,}")
    print(f"Vulnerable Providers:    {q_vuln_transit:,} (Transit ASNs)")

    # --- TOP 10 GIANTS FAIL ---
    print("\n[TOP 10 CORE/GIANTS NOT DOING ROV]")
    print(f"{'ASN':<8} | {'CC':<2} | {'Name'}")
    print("-" * 80)
    
    core_fail = df[df['verdict'] == "CORE: UNPROTECTED"].sort_values(by='cone', ascending=False).head(10)
    for _, r in core_fail.iterrows():
        print(f"AS{r['asn']:<6} | {r['cc']:<2} | {r['name']}")

    # --- TOP 20 VULNERABLE TRANSIT ---
    print("\n[TOP 20 VULNERABLE TRANSIT PROVIDERS (Non-Core)]")
    print(f"{'ASN':<8} | {'CC':<2} | {'Cone':<8} | {'Feeds':<6} | {'Name'}")
    print("-" * 80)
    vuln = df[df['verdict'] == "VULNERABLE (No Coverage)"].sort_values(by='cone', ascending=False)
    for _, r in vuln.head(20).iterrows():
        ups = f"{r['dirty_feeds']}/{r['total_feeds']}"
        print(f"AS{r['asn']:<6} | {r['cc']:<2} | {r['cone']:<8} | {ups:<6} | {r['name'][:40]}")

    filename = "rov_audit_v17_final.csv"
    df.sort_values(by='cone', ascending=False).to_csv(filename, index=False)
    print(f"\n[+] Saved to {filename}")

if __name__ == "__main__":
    analyze()
