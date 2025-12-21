import json
import os
import requests
import time
import pandas as pd
from datetime import datetime, timezone

# --- CONFIGURATION ---
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'application/json',
}
DIR_JSON = "data/parsed"
FILE_AUDIT = "rov_audit_v18_final.csv"

def get_targets():
    print("[*] identifying 'Glass Houses' (Big Cone + 0% Signed)...")
    
    # 1. Load Audit for Cone Size
    if not os.path.exists(FILE_AUDIT): return []
    df = pd.read_csv(FILE_AUDIT, usecols=['asn', 'cone'], low_memory=False)
    
    targets = []
    
    # 2. Check JSON files for 0% signed
    # We only care about networks with Cone > 100 (Impactful networks)
    big_asns = set(df[df['cone'] > 100]['asn'].astype(int))
    
    print(f"    - Checking {len(big_asns)} significant networks for bad data...")
    
    for asn in big_asns:
        json_path = os.path.join(DIR_JSON, f"as_{asn}.json")
        if os.path.exists(json_path):
            try:
                with open(json_path, 'r') as f:
                    data = json.load(f)
                    
                # If Signed % is missing OR is exactly 0.0, we mark for repair
                pct = data.get('roa_signed_pct', 0.0)
                if pct == 0.0:
                    targets.append(asn)
            except: pass
            
    # Sort by size (importance)
    # We need to map back to cone size for sorting
    # Quick lookup dict
    cone_map = df.set_index('asn')['cone'].to_dict()
    targets.sort(key=lambda x: cone_map.get(x, 0), reverse=True)
    
    return targets

def fetch_and_repair(asn):
    url = f"https://stats.labs.apnic.net/roa/AS{asn}?hf=1"
    json_path = os.path.join(DIR_JSON, f"as_{asn}.json")
    
    try:
        resp = requests.get(url, headers=HEADERS, timeout=10)
        if resp.status_code != 200: return False
        
        # Parse JSON
        data_obj = resp.json()
        series = data_obj.get('data', [])
        if not series: return False
        
        # Get Latest
        latest = series[-1]
        
        # Parse (Dict or List support)
        valid = 0
        total = 0
        
        if isinstance(latest, dict):
            total = latest.get('ras_v4_robjs', 0)
            valid = latest.get('ras_v4_val_robjs', 0)
        elif isinstance(latest, list) and len(latest) > 2:
            total = latest[1]
            valid = latest[2]
            
        pct = (valid / total * 100.0) if total > 0 else 0.0
        
        # Save
        file_data = {}
        if os.path.exists(json_path):
            with open(json_path, 'r') as f: file_data = json.load(f)
        
        file_data['asn'] = asn
        file_data['roa_signed_pct'] = round(pct, 1)
        file_data['roa_last_check'] = datetime.now(timezone.utc).isoformat()
        
        with open(json_path, 'w') as f:
            json.dump(file_data, f, indent=2)
            
        return pct # Return new score for display

    except: return False

def main():
    targets = get_targets()
    print(f"[*] Found {len(targets)} Giants with 0% Signed. Forcing repair...")
    
    repaired = 0
    
    for i, asn in enumerate(targets):
        res = fetch_and_repair(asn)
        
        status = "FAIL"
        if res is not False:
            status = f"\033[92mFIXED ({res}%)\033[0m"
            repaired += 1
        else:
            status = "\033[91mFAILED\033[0m"
            
        print(f"    [{i+1}/{len(targets)}] AS{asn:<6} -> {status}")
        
        # Polite sleep
        time.sleep(0.1)

    print("\n" + "="*50)
    print(f"REPAIR COMPLETE: {repaired} / {len(targets)} fixed.")
    print("Run 'python3 analyze_roa_signing.py' now.")

if __name__ == "__main__":
    main()
