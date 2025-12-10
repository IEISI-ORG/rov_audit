import pandas as pd
import json
import os
import glob
import requests
from io import StringIO

# --- CONFIGURATION ---
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'}
DIR_JSON = "data/parsed"
DIR_APNIC = "data/apnic"

# Data Sources
URL_ASNS_CSV = "https://bgp.tools/asns.csv"
URL_ROV_TAGS = "https://bgp.tools/tags/rpkirov.csv"
URL_CLOUDFLARE_CSV = "https://raw.githubusercontent.com/cloudflare/isbgpsafeyet.com/master/data/operators.csv"

# Global Core Definition
KNOWN_TIER_1 = {
    3356, 1299, 174, 2914, 3257, 6762, 6939, 6453, 3491, 1239, 701, 6461, 5511, 6830, 4637,
    7018, 3320, 12956, 1273, 7922, 209, 2828, 4134, 4809, 4837, 9929, 9808
}

def load_all_data():
    print("[*] Loading Data Sources...")

    # 1. ASN Metadata
    print("    - [1/5] ASN Metadata...", end=" ")
    meta_map = {}
    try:
        resp = requests.get(URL_ASNS_CSV, headers=HEADERS)
        meta_df = pd.read_csv(StringIO(resp.text))
        meta_df.columns = [c.strip().lower() for c in meta_df.columns]
        for _, row in meta_df.iterrows():
            s = str(row.get('asn','')).upper().replace('AS','')
            if s.isdigit():
                meta_map[int(s)] = {'name': str(row.get('name','Unknown')), 'cc': str(row.get('country','XX')).upper()}
        print(f"OK ({len(meta_map)})")
    except Exception as e:
        print(f"FAIL ({e})")
        return None

    # 2. BGP.Tools Tags
    print("    - [2/5] BGP.Tools Tags...", end=" ")
    bgp_tools_set = set()
    try:
        resp = requests.get(URL_ROV_TAGS, headers=HEADERS)
        tag_df = pd.read_csv(StringIO(resp.text))
        col = next((c for c in tag_df.columns if 'asn' in c.lower()), tag_df.columns[0])
        tag_df['x'] = tag_df[col].astype(str).str.upper().str.replace('AS','',regex=False)
        bgp_tools_set = set(tag_df[tag_df['x'].str.isnumeric()]['x'].astype(int))
        print(f"OK ({len(bgp_tools_set)})")
    except: print("FAIL")

    # 3. Cloudflare Data
    print("    - [3/5] Cloudflare List...", end=" ")
    cf_set = set()
    try:
        resp = requests.get(URL_CLOUDFLARE_CSV, headers=HEADERS)
        cf_df = pd.read_csv(StringIO(resp.text))
        if 'asn' in cf_df.columns:
            for _, row in cf_df.iterrows():
                val = str(row['asn'])
                if val.isdigit(): cf_set.add(int(val))
        print(f"OK ({len(cf_set)})")
    except: print("FAIL")

    # 4. APNIC Cache
    print("    - [4/5] APNIC Cache...", end=" ")
    apnic_map = {}
    for f in glob.glob(os.path.join(DIR_APNIC, "*.json")):
        try:
            with open(f, 'r') as h:
                d = json.load(h)
                for k,v in d.items(): apnic_map[int(k)] = v
        except: pass
    print(f"OK ({len(apnic_map)})")

    # 5. Connectivity
    print("    - [5/5] Connectivity Cache...", end=" ")
    conn_map = {}
    files = glob.glob(os.path.join(DIR_JSON, "*.json"))
    for f in files:
        try:
            with open(f, 'r') as h:
                d = json.load(h)
                asn = d.get('asn')
                if asn:
                    asn = int(asn)
                    conn_map[asn] = {
                        'upstreams': d.get('upstreams', []),
                        'cone': d.get('cone_size', 0),
                        'is_tier1': d.get('is_tier1', False)
                    }
                    local_cc = d.get('cc')
                    if local_cc and asn in meta_map:
                        if meta_map[asn]['cc'] == 'XX': meta_map[asn]['cc'] = local_cc
        except: pass
    print(f"OK ({len(conn_map)})")

    return meta_map, bgp_tools_set, cf_set, apnic_map, conn_map

def analyze():
    data = load_all_data()
    if not data: return
    meta_map, bgp_tools_set, cf_set, apnic_map, conn_map = data

    # STEP 1: DEFINE SAFE SET
    safe_asns = set()
    for asn in meta_map.keys():
        src_bgp = asn in bgp_tools_set
        src_cf  = asn in cf_set
        src_apnic = apnic_map.get(asn, -1) >= 95.0
        if src_bgp or src_cf or src_apnic: safe_asns.add(asn)

    # STEP 2: AUDIT
    results = []
    print(f"[*] Auditing {len(meta_map)} ASNs...")

    for asn, meta in meta_map.items():
        conn = conn_map.get(asn)
        score = apnic_map.get(asn, -1)
        
        is_safe_self = (asn in safe_asns)
        
        verdict = "Unknown"
        dirty_ups = 0
        total_ups = 0
        cone_size = conn['cone'] if conn else 0
        
        if asn in KNOWN_TIER_1 or (conn and conn['is_tier1']):
            if is_safe_self: verdict = "CORE: PROTECTED"
            else: verdict = "CORE: UNPROTECTED"
            
        elif not conn:
            # MISSING GRAPH DATA
            if is_safe_self: verdict = "Safe (Unknown Upstreams)"
            else: verdict = "Unverified (Unknown Upstreams)"
            
        else:
            total_ups = len(conn['upstreams'])
            if total_ups == 0:
                verdict = "IXP / Peer / Stub"
            else:
                for u in conn['upstreams']:
                    if u not in safe_asns: dirty_ups += 1
                
                if dirty_ups == 0:
                    verdict = "SECURE (Full Coverage)"
                elif is_safe_self:
                    verdict = "SECURE (Active Local ROV)"
                elif (total_ups - dirty_ups) > 0:
                    verdict = "PARTIAL (Mixed Feeds)"
                else:
                    verdict = "VULNERABLE (No Coverage)"

        results.append({
            'asn': asn,
            'name': meta['name'],
            'cc': meta['cc'],
            'cone': cone_size,
            'verdict': verdict,
            'apnic_score': score,
            'dirty_feeds': dirty_ups,
            'total_feeds': total_ups
        })

    df = pd.DataFrame(results)
    
    # --- REPORTING ---
    print("\n" + "="*80)
    print("GLOBAL ROV AUDIT REPORT (FINAL)")
    print("="*80)

    # [A] Full Coverage
    q_a = len(df[df['verdict'] == "SECURE (Full Coverage)"])
    print(f"[A] FULLY SECURE (Inherited Protection): {q_a:,}")

    # [B] No Coverage
    q_b = len(df[df['verdict'] == "VULNERABLE (No Coverage)"])
    print(f"[B] FULLY VULNERABLE (Dirty Feeds):      {q_b:,}")

    # [C] Tier 1 Analysis
    print(f"\n[C] TIER 1 / GLOBAL CORE STATUS")
    t1_fail = df[df['verdict'] == "CORE: UNPROTECTED"]
    print(f"    FAILING ({len(t1_fail)}):")
    for _, row in t1_fail.iterrows():
        print(f"      X AS{row['asn']:<6} ({row['cc']}) - {row['name']}")

    # [D] Top 50 Vulnerable
    print("\n" + "="*80)
    print("TOP 50 VULNERABLE NETWORKS (Known Graph, No Protection)")
    print("="*80)
    print(f"{'ASN':<8} | {'CC':<2} | {'Cone':<8} | {'Feeds':<6} | {'Name'}")
    print("-" * 80)
    
    vuln_df = df[df['verdict'] == "VULNERABLE (No Coverage)"].sort_values(by='cone', ascending=False).head(50)
    for _, row in vuln_df.iterrows():
        ups = f"{row['dirty_feeds']}/{row['total_feeds']}"
        print(f"AS{row['asn']:<6} | {row['cc']:<2} | {row['cone']:<8} | {ups:<6} | {row['name'][:45]}")

    # [E] Top 50 Known Unknowns
    print("\n" + "="*80)
    print("TOP 50 KNOWN UNKNOWNS (Missing Graph Data - High Priority Targets)")
    print("="*80)
    # Logic: Unverified status, sorted by Cone Size
    unknown_df = df[df['verdict'] == "Unverified (Unknown Upstreams)"].sort_values(by='cone', ascending=False)
    
    for _, row in unknown_df.head(50).iterrows():
        print(f"AS{row['asn']:<6} | {row['cc']:<2} | {row['cone']:<8} | {'?/?':<6} | {row['name'][:45]}")

    # [F] Unknown Unknowns (Stubs)
    # Logic: Unverified status AND Cone Size <= 5 (meaning they are stubs)
    stub_unknowns = len(unknown_df[unknown_df['cone'] <= 5])
    
    print("\n" + "="*80)
    print(f"UNKNOWN UNKNOWNS (The Long Tail)")
    print("="*80)
    print(f"Total Stub ASNs with NO DATA (Connectivity or ROV): {stub_unknowns:,}")
    print(f"(These are small networks where we have not scraped Upstreams and APNIC has no score)")

    # Save
    filename = "rov_audit_final_v6.csv"
    df.sort_values(by='cone', ascending=False).to_csv(filename, index=False)
    print(f"\n[+] Complete dataset saved to {filename}")

if __name__ == "__main__":
    analyze()
