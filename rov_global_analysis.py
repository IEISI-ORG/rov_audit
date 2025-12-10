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
FILE_ASNS_CSV = "data/asns.csv"

# Global Core Definition
KNOWN_TIER_1 = {
    3356, 1299, 174, 2914, 3257, 6762, 6939, 6453, 3491, 1239, 701, 6461, 5511, 6830, 4637,
    7018, 3320, 12956, 1273, 7922, 209, 2828, 4134, 4809, 4837, 9929, 9808
}

def load_data():
    print("[*] Loading Data...")
    
    # 1. Metadata (From Local CSV Cache first, fallback to Web)
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

    # 4. Connectivity + Dead Check
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
                    # Repair CC
                    if d.get('cc') and asn in meta_map:
                         if meta_map[asn]['cc'] == 'XX': meta_map[asn]['cc'] = d.get('cc')
        except: pass

    return meta_map, rov_set, apnic_map, conn_map

def analyze():
    meta_map, rov_set, apnic_map, conn_map = load_data()
    
    # Safe Set
    safe_asns = set()
    for asn in meta_map:
        if (asn in rov_set) or (apnic_map.get(asn, -1) >= 95.0):
            safe_asns.add(asn)

    results = []
    print(f"[*] Auditing {len(meta_map)} ASNs...")

    for asn, meta in meta_map.items():
        conn = conn_map.get(asn)
        score = apnic_map.get(asn, -1)
        is_safe = asn in safe_asns
        
        verdict = "Unknown"
        dirty_ups = 0
        total_ups = 0
        cone = conn['cone'] if conn else 0
        
        # --- LOGIC TREE ---
        
        # 1. Dead Check
        if conn and (conn.get('is_dead') or (conn['cone']==0 and len(conn['upstreams'])==0 and meta['cc']=='XX')):
            verdict = "DEAD / INACTIVE"
        
        # 2. Tier 1
        elif asn in KNOWN_TIER_1 or (conn and conn['is_tier1']):
            verdict = "CORE: PROTECTED" if is_safe else "CORE: UNPROTECTED"
            
        # 3. Missing Data
        elif not conn:
            verdict = "Safe (Missing Data)" if is_safe else "Unverified (Missing Data)"
            
        # 4. Active Analysis
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
            'dirty': dirty_ups, 'total': total_ups
        })

    df = pd.DataFrame(results)
    
    # --- REPORT ---
    print("\n" + "="*80)
    print("GLOBAL ROV AUDIT REPORT (V10 - FULL LISTS)")
    print("="*80)
    
    # [A] Full Coverage
    q_a = len(df[df['verdict'] == "SECURE (Full Coverage)"])
    print(f"[A] FULLY SECURE (Inherited Protection): {q_a:,}")

    # [B] No Coverage
    q_b = len(df[df['verdict'] == "VULNERABLE (No Coverage)"])
    print(f"[B] FULLY VULNERABLE (Dirty Feeds):      {q_b:,}")

    # [C] Tier 1
    t1_fail = df[df['verdict'] == "CORE: UNPROTECTED"]
    print(f"\n[C] CORE UNPROTECTED ({len(t1_fail)}):")
    for _, r in t1_fail.iterrows(): print(f"      X AS{r['asn']:<6} ({r['cc']}) - {r['name']}")

    # [D] Top 50 Vulnerable
    print("\n" + "="*80)
    print("TOP 250 VULNERABLE NETWORKS (Known Graph, No Protection)")
    print("="*80)
    print(f"{'ASN':<8} | {'CC':<2} | {'Cone':<8} | {'Feeds':<6} | {'Name'}")
    print("-" * 80)
    
    vuln_df = df[df['verdict'] == "VULNERABLE (No Coverage)"].sort_values(by='cone', ascending=False).head(250)
    for _, row in vuln_df.iterrows():
        ups = f"{row['dirty']}/{row['total']}"
        print(f"AS{row['asn']:<6} | {row['cc']:<2} | {row['cone']:<8} | {ups:<6} | {row['name'][:45]}")

    # [E] Top 50 Known Unknowns
    print("\n" + "="*80)
    print("TOP 500 KNOWN UNKNOWNS (Missing Graph Data - High Priority Targets)")
    print("="*80)
    print(f"{'ASN':<8} | {'CC':<2} | {'Cone':<8} | {'Score':<6} | {'Name'}")
    print("-" * 80)

    unknown_df = df[df['verdict'] == "Unverified (Missing Data)"].sort_values(by='cone', ascending=False)
    for _, row in unknown_df.head(500).iterrows():
        print(f"AS{row['asn']:<6} | {row['cc']:<2} | {row['cone']:<8} | {'?/?':<6} | {row['name'][:45]}")

    # [F] Unknown Unknowns
    stub_unknowns = len(unknown_df[unknown_df['cone'] <= 5])
    print("\n" + "="*80)
    print(f"UNKNOWN UNKNOWNS (The Long Tail)")
    print("="*80)
    print(f"Total Stub ASNs with NO DATA: {stub_unknowns:,}")
    print(f"(Small networks: No scrape data, no APNIC score)")

    filename = "rov_audit_v10.csv"
    df.sort_values(by='cone', ascending=False).to_csv(filename, index=False)
    print(f"\n[+] Saved to {filename}")

if __name__ == "__main__":
    analyze()
