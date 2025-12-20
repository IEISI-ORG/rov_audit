import pandas as pd
import json
import os
import csv
import glob
import gzip
import time
import re
from collections import defaultdict, Counter
from io import StringIO, BytesIO
import requests

# --- CONFIGURATION ---
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'}

# Directories
DIR_JSON = "data/parsed"
DIR_APNIC = "data/apnic"
DIR_ATLAS = "data/atlas"
FILE_GO_RELATIONSHIPS = "output/relationships.csv"

# URLs
URL_ASNS_CSV = "https://bgp.tools/asns.csv"
URL_ROV_TAGS = "https://bgp.tools/tags/rpkirov.csv"
URL_CLOUDFLARE_CSV = "https://raw.githubusercontent.com/cloudflare/isbgpsafeyet.com/master/data/operators.csv"
URL_IPTOASN = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"

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

# ==============================================================================
# 1. LOADERS
# ==============================================================================

def load_metadata():
    print("[1/7] Loading Metadata & Geography...")
    meta = {}
    
    # Names
    df = fetch_csv(URL_ASNS_CSV, "BGP.Tools Names")
    if not df.empty:
        df.columns = [c.strip().lower() for c in df.columns]
        for _, row in df.iterrows():
            s = str(row.get('asn','')).upper().replace('AS','')
            if s.isdigit(): meta[int(s)] = {'name': str(row.get('name','Unknown')), 'cc': 'XX'}

    # Countries (IPtoASN)
    print("    - Fetching Country Codes...", end=" ")
    try:
        resp = requests.get(URL_IPTOASN, headers=HEADERS)
        with gzip.open(BytesIO(resp.content), 'rt') as f:
            asn_countries = defaultdict(list)
            for line in f:
                p = line.split('\t')
                if len(p) < 4: continue
                if p[2].isdigit() and len(p[3]) == 2: asn_countries[int(p[2])].append(p[3])
            
            for asn, ccs in asn_countries.items():
                if asn in meta: meta[asn]['cc'] = Counter(ccs).most_common(1)[0][0].upper()
        print("OK")
    except: print("FAIL")
    return meta

def load_security_status():
    print("[2/7] Loading Security Data...")
    rov_set = set()
    df = fetch_csv(URL_ROV_TAGS, "ROV Tags")
    if not df.empty:
        col = next((c for c in df.columns if 'asn' in c.lower()), df.columns[0])
        df['x'] = df[col].astype(str).str.upper().str.replace('AS','',regex=False)
        rov_set = set(df[df['x'].str.isnumeric()]['x'].astype(int))

    cf_set = set()
    df_cf = fetch_csv(URL_CLOUDFLARE_CSV, "Cloudflare List")
    if not df_cf.empty:
        if 'asn' in df_cf.columns:
            for v in df_cf['asn']:
                if str(v).isdigit(): cf_set.add(int(v))

    return rov_set, cf_set

def load_apnic_cache():
    print("[3/7] Loading APNIC Cache...", end=" ")
    apnic_map = {}
    for f in glob.glob(os.path.join(DIR_APNIC, "*.json")):
        try:
            with open(f) as h:
                for k,v in json.load(h).items(): apnic_map[int(k)] = v
        except: pass
    print(f"OK ({len(apnic_map)} entries)")
    return apnic_map

def load_atlas_forensics():
    print("[4/7] Loading RIPE Atlas Forensics...", end=" ")
    atlas_map = {}
    files = glob.glob(os.path.join(DIR_ATLAS, "*.json"))
    
    for f in files:
        try:
            with open(f) as h:
                d = json.load(h)
                asn = d.get('asn')
                if not asn: continue
                
                # Extract extended fields if available
                verdict = d.get('verdict', 'Unknown')
                divergent = d.get('divergent', False)
                peers_cf = d.get('peers_cf', False)
                notes = d.get('notes', '')
                
                # Check for "secure" verdict in notes if main verdict is inconclusive
                if "Filtered" in notes or "Dropped" in notes:
                    if verdict == "INCONCLUSIVE": verdict = "SECURE (Trace Verified)"

                atlas_map[asn] = {
                    'verdict': verdict,
                    'divergent': divergent,
                    'peers_cf': peers_cf,
                    'notes': notes
                }
        except: pass
    
    print(f"OK ({len(atlas_map)} tests)")
    return atlas_map

def build_topology_from_go():
    print("[5/7] Building Topology (RIS)...")
    if not os.path.exists(FILE_GO_RELATIONSHIPS): return {}, {}

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
            if d1 > d2 * 4.0: provider, customer = as1, as2
            elif d2 > d1 * 4.0: provider, customer = as2, as1
            
            if customer in TIER_1_FIREWALL: continue
            if provider:
                upstream_map[customer].add(provider)
                downstream_map[provider].add(customer)

    return upstream_map, downstream_map

def calculate_cones(downstream_map):
    print("[6/7] Calculating Cone Sizes...", end=" ")
    cone_sizes = {}
    memo = {}
    def get_cone(asn):
        if asn in memo: return memo[asn]
        c = set()
        for child in downstream_map.get(asn, []):
            c.add(child)
            c.update(get_cone(child))
        memo[asn] = c
        return c
    for asn in downstream_map: cone_sizes[asn] = len(get_cone(asn))
    print("Done.")
    return cone_sizes

# ==============================================================================
# 2. AUDIT LOGIC
# ==============================================================================
def analyze():
    meta = load_metadata()
    rov_set, cf_set = load_security_status()
    apnic_map = load_apnic_cache()
    atlas_map = load_atlas_forensics()
    upstreams, downstreams = build_topology_from_go()
    cones = calculate_cones(downstreams)

    print("[7/7] Generating Final Audit...")
    results = []
    
    all_asns = set(meta.keys()) | set(cones.keys()) | set(upstreams.keys())
    
    # Safe Set (Passive)
    safe_asns = set()
    for asn in all_asns:
        if (asn in rov_set) or (asn in cf_set) or (apnic_map.get(asn, -1) >= 95.0):
            safe_asns.add(asn)

    for asn in all_asns:
        name = meta.get(asn, {}).get('name', 'Unknown')
        cc = meta.get(asn, {}).get('cc', 'XX')
        cone = cones.get(asn, 0)
        parents = upstreams.get(asn, [])
        score = apnic_map.get(asn, -1)
        
        # Atlas Data
        atlas = atlas_map.get(asn, {})
        atlas_verdict = atlas.get('verdict', '')
        is_divergent = atlas.get('divergent', False)
        
        is_safe_self = asn in safe_asns
        
        verdict = "Unknown"
        dirty_ups = 0
        total_ups = len(parents)
        
        # --- PRIORITY LOGIC ---
        
        # 1. Active Verification (Atlas Wins)
        if "SECURE" in atlas_verdict:
            verdict = "SECURE (Verified Active)"
        elif "VULNERABLE" in atlas_verdict:
            verdict = "VULNERABLE (Verified Active)"
        elif is_divergent:
            verdict = "INCONCLUSIVE (Multipath/Divergent)"
            
        # 2. Tier 1 (If not verified active)
        elif asn in TIER_1_FIREWALL:
            verdict = "CORE: PROTECTED" if is_safe_self else "CORE: UNPROTECTED"
            
        # 3. Missing Data
        elif not parents:
            if cone > 0: verdict = "Unverified (Transit/Peer?)"
            else: verdict = "Stub / Leaf (No Data)"
            
        # 4. Passive Inference (Upstream Analysis)
        else:
            dirty_ups = sum(1 for p in parents if p not in safe_asns)
            
            if dirty_ups == 0:
                verdict = "SECURE (Full Coverage)"
            elif is_safe_self:
                verdict = "SECURE (Active Local ROV)"
            elif dirty_ups < total_ups:
                verdict = "PARTIAL (Mixed Feeds)"
            else:
                verdict = "VULNERABLE (No Coverage)"

        results.append({
            'asn': asn, 'name': name, 'cc': cc, 'cone': cone,
            'verdict': verdict, 
            'apnic_score': score,
            'atlas_result': atlas_verdict,
            'peers_cf': atlas.get('peers_cf', ''),
            'divergent': is_divergent,
            'dirty_feeds': dirty_ups, 
            'total_feeds': total_ups
        })

    df = pd.DataFrame(results)
    
    # --- REPORTING ---
    print("\n" + "="*90)
    print("GLOBAL ROV AUDIT REPORT (V18 - FORENSICS INTEGRATED)")
    print("="*90)
    
    # [A] Full Coverage
    q_a = len(df[df['verdict'].str.contains("SECURE")])
    print(f"[A] TOTAL SECURE NETWORKS:         {q_a:,}")
    print(f"    (Includes Inherited, Local, and Active Verified)")

    # [B] Vulnerable
    q_b = len(df[df['verdict'].str.contains("VULNERABLE")])
    print(f"[B] TOTAL VULNERABLE NETWORKS:     {q_b:,}")

    # [C] Tier 1
    t1_fail = df[df['verdict'] == "CORE: UNPROTECTED"]
    print(f"\n[C] CORE UNPROTECTED ({len(t1_fail)}):")
    for _, r in t1_fail.iterrows(): 
        print(f"      X AS{r['asn']:<6} ({r['cc']}) - {r['name']}")

    # [D] Top 50 Vulnerable
    print("\n" + "="*90)
    print("TOP 50 VULNERABLE NETWORKS (Verified or Inferred)")
    print("="*90)
    print(f"{'ASN':<8} | {'CC':<2} | {'Cone':<8} | {'Feeds':<6} | {'Atlas':<10} | {'Name'}")
    print("-" * 90)
    
    vuln_df = df[df['verdict'].str.contains("VULNERABLE")].sort_values(by='cone', ascending=False).head(50)
    for _, r in vuln_df.iterrows():
        ups = f"{r['dirty_feeds']}/{r['total_feeds']}"
        av = r['atlas_result'][:10] if r['atlas_result'] else "-"
        print(f"AS{r['asn']:<6} | {r['cc']:<2} | {r['cone']:<8} | {ups:<6} | {av:<10} | {r['name'][:35]}")

    filename = "rov_audit_v18_final.csv"
    df.sort_values(by='cone', ascending=False).to_csv(filename, index=False)
    print(f"\n[+] Saved to {filename}")

if __name__ == "__main__":
    analyze()
