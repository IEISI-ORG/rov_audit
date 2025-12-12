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
DIR_ATLAS = "data/atlas"
FILE_ASNS_CSV = "data/asns.csv"

# Global Core Definition
KNOWN_TIER_1 = {
    3356, 1299, 174, 2914, 3257, 6762, 6939, 6453, 3491, 1239, 701, 6461, 5511, 6830, 4637,
    7018, 3320, 12956, 1273, 7922, 209, 2828, 4134, 4809, 4837, 9929, 9808
}

CLOUDFLARE_ASN = 13335

def load_atlas_data():
    """
    Loads RIPE Atlas results.
    Returns: Dict { ASN: {'verdict': '...', 'peers_cf': Bool/None} }
    """
    print("    - [6/6] RIPE Atlas Results...", end=" ")
    atlas_map = {}
    
    files = glob.glob(os.path.join(DIR_ATLAS, "*.json"))
    for f in files:
        try:
            with open(f, 'r') as h:
                data = json.load(h)
                target_asn = data.get('asn')
                if not target_asn: continue
                
                # 1. Verdict
                verdict = data.get('verdict', 'Unknown')
                
                # 2. Peering Check (Did we see Target -> Cloudflare directly?)
                peers_cf = "No Trace"
                
                # Check if we have path data (from verify_path_and_rov.py)
                path = data.get('valid_path') # List of ASNs e.g. [6453, 13335]
                
                if path:
                    peers_cf = "False" # Default if we have a trace but no peering
                    # Logic: Find Target in path, check if next hop is CF
                    if target_asn in path:
                        idx = path.index(target_asn)
                        # Check if next hop exists and is Cloudflare
                        if idx + 1 < len(path) and path[idx+1] == CLOUDFLARE_ASN:
                            peers_cf = "True"
                    
                    # Edge Case: If the Target IS the probe host, check if index 0 is CF?
                    # Usually trace starts with upstream.
                
                atlas_map[target_asn] = {
                    'verdict': verdict,
                    'peers_cf': peers_cf
                }
        except: pass
        
    print(f"OK ({len(atlas_map)} Tests)")
    return atlas_map

def load_data():
    print("[*] Loading Data...")
    
    # 1. Metadata
    meta_map = {}
    if os.path.exists(FILE_ASNS_CSV):
        try:
            df = pd.read_csv(FILE_ASNS_CSV)
            df.columns = [c.strip().lower() for c in df.columns]
            for _, row in df.iterrows():
                # Strict Validation
                raw = row.get('asn')
                if pd.isna(raw): continue
                s = str(raw).upper().replace('AS','')
                if not s.isdigit(): continue
                
                meta_map[int(s)] = {'name': str(row.get('name','Unknown')), 'cc': str(row.get('country','XX')).upper()}
        except: pass
    
    # 2. ROV Tags
    rov_set = set()
    try:
        r = requests.get("https://bgp.tools/tags/rpkirov.csv", headers=HEADERS)
        df = pd.read_csv(StringIO(r.text))
        col = next(c for c in df.columns if 'asn' in c.lower())
        df['x'] = df[col].astype(str).str.upper().str.replace('AS','', regex=False)
        rov_set = set(df[df['x'].str.isnumeric()]['x'].astype(int))
    except: pass

    # 3. APNIC
    apnic_map = {}
    for f in glob.glob(os.path.join(DIR_APNIC, "*.json")):
        try:
            with open(f) as h:
                for k,v in json.load(h).items(): apnic_map[int(k)] = v
        except: pass

    # 4. Connectivity
    conn_map = {}
    files = glob.glob(os.path.join(DIR_JSON, "*.json"))
    for f in files:
        try:
            with open(f) as h:
                d = json.load(h)
                asn = d.get('asn')
                if asn:
                    asn = int(asn)
                    conn_map[asn] = {
                        'upstreams': d.get('upstreams', []),
                        'cone': d.get('cone_size', 0),
                        'is_tier1': d.get('is_tier1', False),
                        'is_dead': d.get('is_dead', False)
                    }
                    if d.get('cc') and asn in meta_map:
                         if meta_map[asn]['cc'] == 'XX': meta_map[asn]['cc'] = d.get('cc')
        except: pass

    # 5. Atlas
    atlas_map = load_atlas_data()

    return meta_map, rov_set, apnic_map, conn_map, atlas_map

def analyze():
    meta_map, rov_set, apnic_map, conn_map, atlas_map = load_data()
    
    safe_asns = set()
    for asn in meta_map:
        if (asn in rov_set) or (apnic_map.get(asn, -1) >= 95.0):
            safe_asns.add(asn)

    results = []
    print(f"[*] Auditing {len(meta_map)} ASNs...")

    for asn, meta in meta_map.items():
        conn = conn_map.get(asn)
        score = apnic_map.get(asn, -1)
        atlas = atlas_map.get(asn, {'verdict': '', 'peers_cf': ''})
        
        is_safe = asn in safe_asns
        
        verdict = "Unknown"
        dirty_ups = 0
        total_ups = 0
        cone = conn['cone'] if conn else 0
        
        if conn and (conn.get('is_dead') or (conn['cone']==0 and len(conn['upstreams'])==0 and meta['cc']=='XX')):
            verdict = "DEAD / INACTIVE"
        elif asn in KNOWN_TIER_1 or (conn and conn['is_tier1']):
            verdict = "CORE: PROTECTED" if is_safe else "CORE: UNPROTECTED"
        elif not conn:
            verdict = "Safe (Missing Data)" if is_safe else "Unverified (Missing Data)"
        else:
            total_ups = len(conn['upstreams'])
            if total_ups == 0:
                verdict = "IXP / Peer / Stub"
            else:
                dirty_ups = sum(1 for u in conn['upstreams'] if u not in safe_asns)
                if dirty_ups == 0: verdict = "SECURE (Full Coverage)"
                elif is_safe:      verdict = "SECURE (Active Local ROV)"
                elif (total_ups - dirty_ups) > 0: verdict = "PARTIAL (Mixed Feeds)"
                else: verdict = "VULNERABLE (No Coverage)"

        results.append({
            'asn': asn, 'name': meta['name'], 'cc': meta['cc'], 'cone': cone,
            'verdict': verdict, 'apnic_score': score,
            'dirty': dirty_ups, 'total': total_ups,
            'atlas_verdict': atlas['verdict'],
            'peers_cloudflare': atlas['peers_cf']
        })

    df = pd.DataFrame(results)
    
    # --- SANITIZATION ---
    df = df[df['asn'] > 0]
    mask_corrupt = (df['name'].str.len() == 2) & df['name'].str.isupper() & (~df['cc'].str.isalpha())
    if mask_corrupt.any(): df = df[~mask_corrupt]

    # --- REPORT ---
    print("\n" + "="*80)
    print("GLOBAL ROV AUDIT REPORT (V12 - ATLAS INTEGRATED)")
    print("="*80)
    
    # [A] Full Coverage
    q_a = len(df[df['verdict'] == "SECURE (Full Coverage)"])
    print(f"[A] FULLY SECURE (Inherited): {q_a:,}")

    # [B] No Coverage
    q_b = len(df[df['verdict'] == "VULNERABLE (No Coverage)"])
    print(f"[B] FULLY VULNERABLE (Dirty): {q_b:,}")

    # [C] Tier 1
    t1_fail = df[df['verdict'] == "CORE: UNPROTECTED"]
    print(f"\n[C] CORE UNPROTECTED ({len(t1_fail)}):")
    for _, r in t1_fail.iterrows(): print(f"      X AS{r['asn']:<6} ({r['cc']}) - {r['name']}")

    # Atlas Highlights
    print("\n[ATLAS VERIFICATION HIGHLIGHTS]")
    atlas_hits = df[df['atlas_verdict'] != ""]
    if not atlas_hits.empty:
        # Show top 5 largest cones verified via Atlas
        for _, r in atlas_hits.sort_values(by='cone', ascending=False).head(5).iterrows():
            print(f"  AS{r['asn']} ({r['cc']}) -> {r['atlas_verdict']} (Peers CF: {r['peers_cloudflare']})")
    else:
        print("  (No Atlas results found in data/atlas/)")

    # Top 50 Vulnerable
    print("\n" + "="*80)
    print("TOP 50 VULNERABLE NETWORKS")
    print(f"{'ASN':<8} | {'CC':<2} | {'Cone':<8} | {'Atlas':<10} | {'Name'}")
    print("-" * 80)
    
    vuln_df = df[df['verdict'] == "VULNERABLE (No Coverage)"].sort_values(by='cone', ascending=False).head(50)
    for _, row in vuln_df.iterrows():
        av = row['atlas_verdict'][:10] if row['atlas_verdict'] else "-"
        print(f"AS{row['asn']:<6} | {row['cc']:<2} | {row['cone']:<8} | {av:<10} | {row['name'][:40]}")

    # Unknown Unknowns
    unknown_df = df[df['verdict'] == "Unverified (Missing Data)"]
    stub_unknowns = len(unknown_df[unknown_df['cone'] <= 5])
    print("\n" + "="*80)
    print(f"UNKNOWN UNKNOWNS: {stub_unknowns:,} (Active Stubs with no Data)")

    filename = "rov_audit_v12.csv"
    df.sort_values(by='cone', ascending=False).to_csv(filename, index=False)
    print(f"\n[+] Saved to {filename}")

if __name__ == "__main__":
    analyze()
