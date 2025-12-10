import requests
import pandas as pd
import json
import os
import re
import glob
import time
from io import StringIO
from bs4 import BeautifulSoup

# --- CONFIGURATION ---
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

DIR_HTML = "data/html"
DIR_JSON = "data/parsed"
DIR_APNIC = "data/apnic"
os.makedirs(DIR_APNIC, exist_ok=True)

# BGP.Tools Official Data Dumps
URL_ASNS_CSV = "https://bgp.tools/asns.csv"
URL_ROV_TAGS = "https://bgp.tools/tags/rpkirov.csv"

# ==============================================================================
# 1. METADATA ENGINE (Hybrid: CSV + Local Cache)
# ==============================================================================

def load_bgptools_metadata():
    print("[*] Fetching Official ASN Metadata (asns.csv)...")
    meta = {}
    
    # 1. Try Online CSV
    try:
        resp = requests.get(URL_ASNS_CSV, headers=HEADERS)
        if resp.status_code == 200:
            df = pd.read_csv(StringIO(resp.text))
            
            # Print columns for debug
            # print(f"    DEBUG: CSV Columns found: {list(df.columns)}")
            
            # Normalize columns
            df.columns = [c.strip().lower() for c in df.columns]
            
            for _, row in df.iterrows():
                # Extract ASN safely
                raw_asn = str(row.get('asn', ''))
                asn_str = raw_asn.upper().replace('AS', '')
                
                if asn_str.isdigit():
                    asn = int(asn_str)
                    meta[asn] = {
                        'name': str(row.get('name', 'Unknown')),
                        'cc': str(row.get('country', 'XX')).upper()
                    }
            print(f"    - Loaded metadata for {len(meta)} ASNs from Web.")
    except Exception as e:
        print(f"[-] CSV Fetch Error: {e}")

    # 2. Augment with Local Cache (Fallback)
    # If CSV missed something, or failed, we use our scraped JSONs
    local_files = glob.glob(os.path.join(DIR_JSON, "*.json"))
    print(f"[*] Augmenting with {len(local_files)} local cached files...")
    
    for fpath in local_files:
        try:
            with open(fpath, 'r') as f:
                data = json.load(f)
                asn = data.get('asn')
                if asn:
                    asn = int(asn)
                    # If this ASN isn't in meta, OR meta has 'XX' but local has real CC
                    if asn not in meta:
                        meta[asn] = {'name': 'Unknown', 'cc': 'XX'}
                    
                    local_cc = data.get('cc')
                    if local_cc and meta[asn]['cc'] == 'XX':
                        meta[asn]['cc'] = local_cc.upper()
        except: pass

    return meta

# ==============================================================================
# 2. APNIC ENGINE (Robust Regex)
# ==============================================================================

def get_apnic_score(asn, cc):
    if not cc or cc == 'XX': return -1
    
    cache_file = os.path.join(DIR_APNIC, f"{cc}.json")
    
    # We rely on the cache being populated. 
    # If it's missing, we try one last-ditch download.
    if not os.path.exists(cache_file):
        try:
            # print(f"    [APNIC] Late fetch for {cc}...")
            url = f"https://stats.labs.apnic.net/rpki/{cc}"
            resp = requests.get(url, headers=HEADERS)
            if resp.status_code == 200:
                scores = {}
                # Regex for: >AS1234< ... {v: 99.81
                pattern = re.compile(r'>AS(\d+)<.*?\{v:\s*([\d\.]+)', re.IGNORECASE)
                matches = pattern.findall(resp.text)
                for a, s in matches: scores[int(a)] = float(s)
                with open(cache_file, 'w') as f: json.dump(scores, f)
        except: pass

    try:
        with open(cache_file, 'r') as f:
            data = json.load(f)
            return data.get(str(asn), -1)
    except:
        return -1

# ==============================================================================
# 3. CONNECTIVITY ENGINE (From Local JSON Cache)
# ==============================================================================

def get_connectivity(asn):
    # We prefer the JSON cache because it's already parsed
    json_path = os.path.join(DIR_JSON, f"as_{asn}.json")
    
    if os.path.exists(json_path):
        try:
            with open(json_path, 'r') as f:
                data = json.load(f)
                return {
                    'is_tier1': data.get('is_tier1', False),
                    'cone': data.get('cone_size', 0),
                    'upstreams': data.get('upstreams', []),
                    'signed_pct': data.get('roa_signed_pct', 0)
                }
        except: pass
        
    return {'is_tier1': False, 'cone': 0, 'upstreams': [], 'signed_pct': 0}

# ==============================================================================
# 4. MAIN LOGIC
# ==============================================================================

def analyze():
    # 1. Metadata
    meta_db = load_bgptools_metadata()

    # 2. Target List
    print("[*] Fetching ROV Target List...")
    try:
        resp = requests.get(URL_ROV_TAGS, headers=HEADERS)
        rov_df = pd.read_csv(StringIO(resp.text))
        
        # Find ASN column safely
        cols = [c for c in rov_df.columns if 'asn' in str(c).lower()]
        asn_col = cols[0] if cols else rov_df.columns[0]
        
        rov_df['asn_int'] = rov_df[asn_col].astype(str).str.upper().str.replace('AS', '', regex=False)
        rov_df = rov_df[rov_df['asn_int'].str.isnumeric()]
        rov_df['asn_int'] = rov_df['asn_int'].astype(int)
        
        rov_set = set(rov_df['asn_int'].tolist())
    except Exception as e:
        print(f"[-] Error loading target list: {e}")
        return

    results = []
    
    print(f"[*] Triangulating Data for {len(rov_set)} ASNs...")
    
    for i, asn in enumerate(rov_set):
        if i % 50 == 0: print(f"    Processing {i}/{len(rov_set)}...", end="\r")

        # Get Info
        info = meta_db.get(asn, {'name': 'Unknown', 'cc': 'XX'})
        conn = get_connectivity(asn)
        score = get_apnic_score(asn, info['cc'])

        # Logic
        dirty_upstreams = [u for u in conn['upstreams'] if u not in rov_set]
        dirty_count = len(dirty_upstreams)
        
        verdict = "Unknown"
        net_type = "Transit" if conn['cone'] > 5 else "Stub"
        
        if conn['is_tier1']:
            verdict = "CORE PROTECTOR (Tier 1)"
        elif len(conn['upstreams']) == 0:
            verdict = "IXP / Peer / Stub"
        else:
            if score >= 98.0:
                if dirty_count > 0:
                    verdict = f"{net_type}: ACTIVE LOCAL ROV"
                else:
                    verdict = f"{net_type}: SECURE (Clean Pipe)"
            elif score > -1 and score < 20.0:
                verdict = f"{net_type}: LEAKING"
            else:
                if dirty_count > 0:
                    verdict = f"{net_type}: UNVERIFIED (Dirty Feed)"
                else:
                    verdict = f"{net_type}: INHERITED (Clean Pipe)"
        
        results.append({
            'asn': asn,
            'cc': info['cc'],
            'name': info['name'],
            'verdict': verdict,
            'apnic_score': score,
            'cone': conn['cone'],
            'dirty_feeds': dirty_count,
            'total_feeds': len(conn['upstreams'])
        })

    # Output
    df = pd.DataFrame(results)
    
    # Sort: Active first, then Tier 1, then Leaking
    def get_prio(v):
        if "ACTIVE" in v: return 0
        if "Tier 1" in v: return 1
        if "LEAKING" in v: return 2
        return 99

    df['prio'] = df['verdict'].apply(get_prio)
    df = df.sort_values(by=['prio', 'cone'], ascending=[True, False])
    
    print("\n" + "="*145)
    # Fixed widths for clean alignment
    print(f"{'ASN':<8} | {'CC':<2} | {'VERDICT':<30} | {'APNIC':<6} | {'Dirty/Total':<11} | {'Name'}")
    print("-" * 145)
    
    for _, row in df.head(50).iterrows():
        v = row['verdict']
        # Hard truncate name to 40 chars
        d_name = row['name'][:40]
        score = f"{int(row['apnic_score'])}%" if row['apnic_score'] > -1 else "-"
        
        if "ACTIVE" in v: color = "\033[92m" 
        elif "Tier 1" in v: color = "\033[94m" 
        elif "LEAKING" in v: color = "\033[91m" 
        else: color = "\033[90m" 
        reset = "\033[0m"
        
        ups = f"{row['dirty_feeds']}/{row['total_feeds']}"
        print(f"AS{row['asn']:<6} | {row['cc']:<2} | {color}{v:<30}{reset} | {score:<6} | {ups:<11} | {d_name}")
        
    df.drop(columns=['prio']).to_csv("rov_ultimate_analysis.csv", index=False)
    print("\n[+] Saved to rov_ultimate_analysis.csv")

if __name__ == "__main__":
    analyze()

