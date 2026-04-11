import json
import os
import requests
import pandas as pd
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

# --- CONFIGURATION ---
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'application/json',
}

DIR_JSON = "data/parsed"
FILE_AUDIT = "rov_audit_v18_final.csv"

MAX_WORKERS = 20
CACHE_TTL_DAYS = 30

def load_targets():
    if not os.path.exists(FILE_AUDIT): return []
    df = pd.read_csv(FILE_AUDIT, usecols=['asn', 'cone', 'verdict'], low_memory=False)
    df = df[~df['verdict'].str.contains("DEAD")]
    df = df.sort_values(by='cone', ascending=False)
    return df['asn'].astype(int).tolist()

def aggregate_apnic_data(series):
    """
    Aggregates data across all Country Codes for the most recent date.
    """
    if not series: return 0, 0
    
    # 1. Determine the latest date in the dataset
    # entries look like: {'ras_dt': '2023-01-01', 'ras_cc': 'US', ...}
    latest_date = ""
    
    # Scan for max date
    for item in series:
        if isinstance(item, dict):
            dt = item.get('ras_dt', '')
            if dt > latest_date:
                latest_date = dt
    
    if not latest_date: return 0, 0

    # 2. Sum values for that date
    total_global = 0
    valid_global = 0
    
    for item in series:
        if isinstance(item, dict) and item.get('ras_dt') == latest_date:
            total_global += item.get('ras_v4_robjs', 0)
            valid_global += item.get('ras_v4_val_robjs', 0)
            
    return valid_global, total_global

def fetch_and_update(asn):
    json_path = os.path.join(DIR_JSON, f"as_{asn}.json")
    
    # 1. Cache Check
    file_data = {}
    if os.path.exists(json_path):
        try:
            with open(json_path, 'r') as f: file_data = json.load(f)
            last = file_data.get('roa_last_check')
            if last:
                try:
                    age = datetime.now(timezone.utc) - datetime.fromisoformat(last).replace(tzinfo=timezone.utc)
                    if age.days < CACHE_TTL_DAYS: return "SKIPPED", None
                except: pass
        except: pass

    # 2. Fetch
    url = f"https://stats.labs.apnic.net/roa/AS{asn}?hf=1"
    try:
        time.sleep(0.05)
        resp = requests.get(url, headers=HEADERS, timeout=15)
        if resp.status_code != 200: return "FAIL", f"HTTP {resp.status_code}"

        data_obj = resp.json()
        series = data_obj.get('data', [])
        if not series: return "FAIL", "Empty Data"

        # 3. Aggregate (The Fix)
        valid, total = aggregate_apnic_data(series)
        
        pct = (valid / total * 100.0) if total > 0 else 0.0
        
        # 4. Save
        if 'asn' not in file_data: file_data['asn'] = asn
        file_data['roa_signed_pct'] = round(pct, 1)
        file_data['roa_raw_stats'] = {'valid': valid, 'total': total} # Audit trail
        file_data['roa_last_check'] = datetime.now(timezone.utc).isoformat()
        
        with open(json_path, 'w') as f:
            json.dump(file_data, f, indent=2)
            
        return "UPDATED", None

    except Exception as e:
        return "FAIL", str(e)

def main():
    targets = load_targets()
    print(f"[*] Starting Aggregated Bulk Fetch for {len(targets)} ASNs...")
    
    stats = {'updated': 0, 'skipped': 0, 'failed': 0}
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_asn = {executor.submit(fetch_and_update, asn): asn for asn in targets}
        
        for i, future in enumerate(as_completed(future_to_asn)):
            try:
                res, err = future.result()
                if res == "UPDATED": stats['updated'] += 1
                elif res == "SKIPPED": stats['skipped'] += 1
                else: stats['failed'] += 1
            except: stats['failed'] += 1
            
            if i % 50 == 0:
                print(f"    - {i+1}/{len(targets)} | Upd: {stats['updated']} | Skip: {stats['skipped']} | Fail: {stats['failed']}", end="\r")

    print(f"\n[*] Done. Updated: {stats['updated']}. Run 'python3 analyze_roa_signing.py' now.")

if __name__ == "__main__":
    main()
