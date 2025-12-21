import json
import os
import requests
import time
import pandas as pd
from datetime import datetime, timezone

# --- CONFIGURATION ---
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'}
DIR_JSON = "data/parsed"
FILE_AUDIT = "rov_audit_v18_final.csv"

# RIPEstat Endpoints
URL_PREFIXES = "https://stat.ripe.net/data/announced-prefixes/data.json?resource="
URL_ROAS = "https://stat.ripe.net/data/rpki-roas/data.json?resource="

def get_targets():
    print("[*] Identifying 'Glass Houses' (Big Cone + 0% Signed)...")
    if not os.path.exists(FILE_AUDIT): return []
    df = pd.read_csv(FILE_AUDIT, usecols=['asn', 'cone', 'name'], low_memory=False)
    
    targets = []
    
    # Check for 0% signed in local cache
    # We prioritize BIG networks (Cone > 100) to save API calls
    big_asns = df[df['cone'] > 100]['asn'].astype(int).tolist()
    
    print(f"    - Scanning {len(big_asns)} networks for bad data...")
    
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
            
    print(f"    - Found {len(targets)} candidates for RIPE repair.")
    return targets

def fetch_ripe_data(asn):
    try:
        # 1. Get Total Announced Prefixes
        r_pfx = requests.get(f"{URL_PREFIXES}AS{asn}", headers=HEADERS, timeout=10)
        if r_pfx.status_code != 200: return None
        
        # RIPEstat returns ipv4/ipv6 lists. We sum them.
        p_data = r_pfx.json().get('data', {})
        v4_cnt = len(p_data.get('prefixes', []))
        # Note: 'prefixes' usually contains v4 and v6 combined in this endpoint, 
        # but let's assume length of the list is the total count.
        total_routes = v4_cnt
        
        if total_routes == 0: return 0.0 # No routes = 0% signed technically

        # 2. Get ROA Count
        r_roa = requests.get(f"{URL_ROAS}AS{asn}", headers=HEADERS, timeout=10)
        if r_roa.status_code != 200: return None
        
        roa_data = r_roa.json().get('data', {})
        roa_cnt = len(roa_data.get('roas', []))
        
        # 3. Calculate
        # Cap at 100% (sometimes multiple ROAs cover one prefix or aggregation differs)
        pct = (roa_cnt / total_routes) * 100.0
        if pct > 100.0: pct = 100.0
        
        return pct

    except Exception as e:
        print(f"    [!] Error fetching AS{asn}: {e}")
        return None

def update_cache(asn, pct):
    json_path = os.path.join(DIR_JSON, f"as_{asn}.json")
    if not os.path.exists(json_path): return

    try:
        with open(json_path, 'r') as f:
            data = json.load(f)
        
        data['roa_signed_pct'] = round(pct, 1)
        data['roa_source'] = "RIPEstat" # Audit trail
        data['roa_last_check'] = datetime.now(timezone.utc).isoformat()
        
        with open(json_path, 'w') as f:
            json.dump(data, f, indent=2)
            
    except: pass

def main():
    targets = get_targets()
    
    print(f"[*] Starting RIPEstat Repair for {len(targets)} ASNs...")
    
    repaired = 0
    failed = 0
    
    for i, asn in enumerate(targets):
        pct = fetch_ripe_data(asn)
        
        status_msg = ""
        if pct is not None:
            update_cache(asn, pct)
            if pct > 1.0:
                status_msg = f"\033[92mFIXED ({pct:.1f}%)\033[0m"
                repaired += 1
            else:
                status_msg = f"\033[93mCONFIRMED 0%\033[0m"
        else:
            status_msg = "\033[91mAPI FAIL\033[0m"
            failed += 1
            
        print(f"    [{i+1}/{len(targets)}] AS{asn:<6} -> {status_msg}")
        
        # RIPEstat has rate limits, be polite
        time.sleep(0.3)

    print("\n" + "="*60)
    print("REPAIR COMPLETE")
    print(f"Repaired (Found Data): {repaired}")
    print(f"Confirmed Empty:       {len(targets) - repaired - failed}")
    print(f"API Failures:          {failed}")
    print("[*] Run 'python3 analyze_roa_signing.py' to see the corrected report.")

if __name__ == "__main__":
    main()
