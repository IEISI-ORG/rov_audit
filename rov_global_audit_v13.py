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

# File Paths
FILE_ASNS_CSV = "data/asns.csv"
FILE_GO_TOPOLOGY = "final_as_rank.csv" 

# Global Core Definition
KNOWN_TIER_1 = {
    3356, 1299, 174, 2914, 3257, 6762, 6939, 6453, 3491, 1239, 701, 6461, 5511, 6830, 4637,
    7018, 3320, 12956, 1273, 7922, 209, 2828, 4134, 4809, 4837, 9929, 9808
}

def load_data():
    print("[*] Loading Data Sources...")
    
    # 1. GO TOPOLOGY (The Source of Truth for Size)
    topo_map = {}
    if os.path.exists(FILE_GO_TOPOLOGY):
        print(f"    - [1/6] Go Topology ({FILE_GO_TOPOLOGY})...", end=" ")
        try:
            # Go CSV Format: Rank, ASN, Cone_Size, Node_Degree, Direct_Customers
            df_topo = pd.read_csv(FILE_GO_TOPOLOGY)
            # Normalize column names just in case
            df_topo.columns = [c.strip().lower() for c in df_topo.columns]
            
            # Find columns dynamically
            col_asn = next(c for c in df_topo.columns if 'asn' in c)
            col_cone = next(c for c in df_topo.columns if 'cone' in c)
            col_deg = next((c for c in df_topo.columns if 'degree' in c), None)
            
            for _, row in df_topo.iterrows():
                asn_str = str(row[col_asn]).upper().replace('AS', '')
                if asn_str.isdigit():
                    topo_map[int(asn_str)] = {
                        'cone': int(row[col_cone]),
                        'degree': int(row[col_deg]) if col_deg else 0
                    }
            print(f"OK ({len(topo_map)} entries)")
        except Exception as e:
            print(f"FAIL ({e})")
    else:
        print(f"    - [!] {FILE_GO_TOPOLOGY} not found. Using legacy scraped sizes.")

    # 2. Metadata (Names/Country)
    print("    - [2/6] Metadata...", end=" ")
    meta_map = {}
    if os.path.exists(FILE_ASNS_CSV):
        try:
            df = pd.read_csv(FILE_ASNS_CSV)
            df.columns = [c.strip().lower() for c in df.columns]
            for _, row in df.iterrows():
                s = str(row.get('asn','')).upper().replace('AS','')
                if s.isdigit():
                    meta_map[int(s)] = {'name': str(row.get('name','Unknown')), 'cc': str(row.get('country','XX')).upper()}
        except: pass
    print(f"OK")

    # 3. ROV Tags
    print("    - [3/6] BGP.Tools Tags...", end=" ")
    rov_set = set()
    try:
        r = requests.get("https://bgp.tools/tags/rpkirov.csv", headers=HEADERS)
        df = pd.read_csv(StringIO(r.text))
        col = next(c for c in df.columns if 'asn' in c.lower())
        df['x'] = df[col].astype(str).str.upper().str.replace('AS','', regex=False)
        rov_set = set(df[df['x'].str.isnumeric()]['x'].astype(int))
    except: pass
    print("OK")

    # 4. APNIC
    print("    - [4/6] APNIC Cache...", end=" ")
    apnic_map = {}
    for f in glob.glob(os.path.join(DIR_APNIC, "*.json")):
        try:
            with open(f) as h:
                for k,v in json.load(h).items(): apnic_map[int(k)] = v
        except: pass
    print("OK")

    # 5. Connectivity + Local Repair
    print("    - [5/6] Connectivity Cache...", end=" ")
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
                        'scraped_cone': d.get('cone_size', 0), # Fallback
                        'is_tier1': d.get('is_tier1', False),
                        'is_dead': d.get('is_dead', False)
                    }
                    if d.get('cc') and asn in meta_map:
                         if meta_map[asn]['cc'] == 'XX': meta_map[asn]['cc'] = d.get('cc')
        except: pass
    print("OK")

    # 6. Atlas Results
    print("    - [6/6] Atlas Results...", end=" ")
    atlas_map = {}
    for f in glob.glob(os.path.join(DIR_ATLAS, "*.json")):
        try:
            with open(f) as h:
                d = json.load(h)
                if 'asn' in d and 'verdict' in d:
                    peers_cf = False
                    path = d.get('valid_path', [])
                    if path and 13335 in path:
                        peers_cf = True 
                    
                    atlas_map[d['asn']] = {
                        'verdict': d['verdict'],
                        'peers_cf': peers_cf
                    }
        except: pass
    print("OK")

    return meta_map, rov_set, apnic_map, conn_map, topo_map, atlas_map

def analyze():
    meta_map, rov_set, apnic_map, conn_map, topo_map, atlas_map = load_data()
    
    # Define Safe Set
    safe_asns = set()
    for asn in meta_map:
        if (asn in rov_set) or (apnic_map.get(asn, -1) >= 95.0):
            safe_asns.add(asn)

    results = []
    print(f"[*] Auditing {len(meta_map)} ASNs...")

    for asn, meta in meta_map.items():
        conn = conn_map.get(asn)
        score = apnic_map.get(asn, -1)
        topo = topo_map.get(asn, {})
        atlas = atlas_map.get(asn, {})
        
        is_safe = asn in safe_asns
        verdict = "Unknown"
        
        # Data Merge
        cone_size = topo.get('cone', conn.get('scraped_cone', 0) if conn else 0)
        degree = topo.get('degree', 0)
        
        # --- LOGIC TREE ---
        # FIX: The variable typo is fixed here (cone -> cone_size)
        if conn and (conn.get('is_dead') or (cone_size==0 and not conn['upstreams'] and meta['cc']=='XX')):
            verdict = "DEAD / INACTIVE"
        elif asn in KNOWN_TIER_1:
            verdict = "CORE: PROTECTED" if is_safe else "CORE: UNPROTECTED"
        elif not conn:
            verdict = "Safe (Missing Data)" if is_safe else "Unverified (Missing Data)"
        else:
            total = len(conn['upstreams'])
            if total == 0:
                verdict = "IXP / Peer / Stub"
            else:
                dirty = sum(1 for u in conn['upstreams'] if u not in safe_asns)
                if dirty == 0: verdict = "SECURE (Full Coverage)"
                elif is_safe:  verdict = "SECURE (Active Local ROV)"
                elif dirty < total: verdict = "PARTIAL (Mixed Feeds)"
                else: verdict = "VULNERABLE (No Coverage)"

        # Prepare Row
        dirty_cnt = sum(1 for u in conn['upstreams'] if u not in safe_asns) if conn else 0
        total_cnt = len(conn['upstreams']) if conn else 0
        
        results.append({
            'asn': asn,
            'name': meta['name'],
            'cc': meta['cc'],
            'cone': cone_size,
            'degree': degree,
            'verdict': verdict,
            'apnic_score': score,
            'atlas_result': atlas.get('verdict', ''),
            'peers_cf': atlas.get('peers_cf', ''),
            'dirty_feeds': dirty_cnt,
            'total_feeds': total_cnt
        })

    df = pd.DataFrame(results)
    
    # --- SANITIZATION ---
    df = df[df['asn'] > 0]
    
    # --- REPORTING ---
    print("\n" + "="*90)
    print("GLOBAL ROV AUDIT REPORT (V13 - FIXED)")
    print("="*90)
    
    q_a = len(df[df['verdict'] == "SECURE (Full Coverage)"])
    q_b = len(df[df['verdict'] == "VULNERABLE (No Coverage)"])
    
    print(f"[A] FULLY SECURE (Inherited): {q_a:,}")
    print(f"[B] FULLY VULNERABLE (Dirty): {q_b:,}")

    # Tier 1
    t1_fail = df[df['verdict'] == "CORE: UNPROTECTED"]
    print(f"\n[C] CORE UNPROTECTED ({len(t1_fail)}):")
    for _, r in t1_fail.iterrows(): 
        print(f"      X AS{r['asn']:<6} ({r['cc']}) - {r['name']}")

    # Top 50 Vulnerable
    print("\n" + "="*90)
    print("TOP 50 VULNERABLE NETWORKS (Sorted by Calculated Cone Size)")
    print("="*90)
    print(f"{'ASN':<8} | {'CC':<2} | {'Cone':<8} | {'Deg':<5} | {'Feeds':<6} | {'Name'}")
    print("-" * 90)
    
    vuln_df = df[df['verdict'] == "VULNERABLE (No Coverage)"].sort_values(by='cone', ascending=False).head(50)
    for _, r in vuln_df.iterrows():
        ups = f"{r['dirty_feeds']}/{r['total_feeds']}"
        print(f"AS{r['asn']:<6} | {r['cc']:<2} | {r['cone']:<8} | {r['degree']:<5} | {ups:<6} | {r['name'][:40]}")

    filename = "rov_audit_v13_final.csv"
    df.sort_values(by='cone', ascending=False).to_csv(filename, index=False)
    print(f"\n[+] Saved to {filename}")

if __name__ == "__main__":
    analyze()
