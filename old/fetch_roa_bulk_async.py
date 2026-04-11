import json
import os
import requests
import argparse
import pandas as pd
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# --- CONFIGURATION ---
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'}
DIR_JSON = "data/parsed"
FILE_AUDIT = "rov_audit_v18_final.csv"

# Max threads (Don't go too high or APNIC might block you)
MAX_WORKERS = 10 

def load_targets():
    print(f"[*] Loading Target List from {FILE_AUDIT}...")
    if not os.path.exists(FILE_AUDIT):
        print(f"[!] {FILE_AUDIT} not found.")
        return []

    df = pd.read_csv(FILE_AUDIT, usecols=['asn', 'cone', 'verdict'], low_memory=False)
    
    # Filter: Only scan active networks (Cone > 0) or specific verdicts?
    # User said "All 88,000". Let's filter out "DEAD" to save time.
    df = df[~df['verdict'].str.contains("DEAD")]
    
    # Sort by Cone Size (Get the big data first)
    df = df.sort_values(by='cone', ascending=False)
    
    return df['asn'].astype(int).tolist()

def fetch_and_update(asn):
    url = f"https://stats.labs.apnic.net/roa/AS{asn}?hf=1"
    json_path = os.path.join(DIR_JSON, f"as_{asn}.json")
    
    try:
        # 1. Fetch
        resp = requests.get(url, headers=HEADERS, timeout=10)
        if resp.status_code != 200:
            return None # Fail
            
        # 2. Parse JSON
        # The response is usually { "data": [ [date, total, valid, invalid, unknown, ...], ... ] }
        # We want the LAST entry (Most Recent)
        data_obj = resp.json()
        series = data_obj.get('data', [])
        
        if not series: return None
        
        latest = series[-1]
        
        # APNIC ROA Series Format typically:
        # [Date, Total_Pfx, Valid_Pfx, Invalid_Pfx, Unknown_Pfx, Coverage_V4_Pct, Coverage_V6_Pct...]
        # We want index 5 (Coverage V4 Pct) usually.
        # Let's verify by calculating: valid / total * 100
        
        # Safe extraction
        total = latest[1]
        valid = latest[2]
        
        if total > 0:
            pct = (valid / total) * 100.0
        else:
            pct = 0.0
            
        # 3. Update Local Cache
        # We read-modify-write the existing JSON file
        file_data = {}
        if os.path.exists(json_path):
            with open(json_path, 'r') as f:
                file_data = json.load(f)
        else:
            file_data = {'asn': asn}
            
        file_data['roa_signed_pct'] = round(pct, 1)
        file_data['roa_last_check'] = datetime.utcnow().isoformat()
        
        with open(json_path, 'w') as f:
            json.dump(file_data, f, indent=2)
            
        return pct

    except Exception as e:
        return None

def main():
    targets = load_targets()
    total = len(targets)
    print(f"[*] Starting Bulk Fetch for {total:,} ASNs with {MAX_WORKERS} workers...")
    print(f"    (Estimated time: {int(total/MAX_WORKERS/2/60)} minutes)")
    
    success = 0
    errors = 0
    
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # Submit all tasks
        future_to_asn = {executor.submit(fetch_and_update, asn): asn for asn in targets}
        
        # Process as they complete
        for i, future in enumerate(as_completed(future_to_asn)):
            asn = future_to_asn[future]
            try:
                res = future.result()
                if res is not None:
                    success += 1
                else:
                    errors += 1
            except Exception:
                errors += 1
            
            # Progress Bar
            if i % 100 == 0:
                elapsed = time.time() - start_time
                rate = (i+1) / elapsed
                print(f"    - Progress: {i+1}/{total} ({((i+1)/total)*100:.1f}%) | Rate: {rate:.1f}/s | OK: {success} | Fail: {errors}", end="\r")

    print("\n" + "="*60)
    print("BULK UPDATE COMPLETE")
    print("="*60)
    print(f"Total Processed: {total}")
    print(f"Success Updated: {success}")
    print(f"Failed/No Data:  {errors}")
    print("[*] Now run 'python3 analyze_roa_signing.py' to see the corrected stats.")

if __name__ == "__main__":
    main()
