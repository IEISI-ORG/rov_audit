import json
import os
import requests
import pandas as pd
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

# --- CONFIGURATION ---
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'application/json',
}

DIR_JSON = "data/parsed"
FILE_AUDIT = "rov_audit_v18_final.csv"

# Threads (Adjust based on your connection)
MAX_WORKERS = 20
CACHE_TTL_DAYS = 30

def load_targets():
    if not os.path.exists(FILE_AUDIT): return []
    df = pd.read_csv(FILE_AUDIT, usecols=['asn', 'cone', 'verdict'], low_memory=False)
    # Filter out DEAD networks
    df = df[~df['verdict'].str.contains("DEAD")]
    # Sort by Cone Size
    df = df.sort_values(by='cone', ascending=False)
    return df['asn'].astype(int).tolist()

def parse_apnic_record(record):
    """Extracts Valid/Total from a single history point (Dict or List)."""
    valid = 0
    total = 0
    
    # Format A: Dictionary (Seen in your screenshot)
    if isinstance(record, dict):
        total = record.get('ras_v4_robjs', 0)
        valid = record.get('ras_v4_val_robjs', 0)
        
    # Format B: List (Legacy/Country view)
    elif isinstance(record, list):
        # [Date, Total, Valid, Invalid, ...]
        if len(record) > 2:
            total = record[1]
            valid = record[2]
            
    return valid, total

def fetch_and_update(asn):
    json_path = os.path.join(DIR_JSON, f"as_{asn}.json")
    
    # 1. Cache Check
    file_data = {}
    if os.path.exists(json_path):
        try:
            with open(json_path, 'r') as f:
                file_data = json.load(f)
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
        # Jitter
        time.sleep(0.05)
        resp = requests.get(url, headers=HEADERS, timeout=15)
        
        if resp.status_code != 200:
            return "FAIL", f"HTTP {resp.status_code}"

        # 3. Parse JSON
        try:
            data_obj = resp.json()
            series = data_obj.get('data', [])
        except json.JSONDecodeError:
            return "FAIL", "Invalid JSON"

        if not series:
            return "FAIL", "Empty Data"

        # 4. Get Latest Data Point
        # The API usually returns chronological, but let's be safe and grab the last one.
        latest = series[-1]
        
        valid, total = parse_apnic_record(latest)
        
        pct = (valid / total * 100.0) if total > 0 else 0.0
        
        # 5. Save
        if 'asn' not in file_data: file_data['asn'] = asn
        file_data['roa_signed_pct'] = round(pct, 1)
        file_data['roa_stats'] = {'valid': valid, 'total': total} # Store raw counts too
        file_data['roa_last_check'] = datetime.now(timezone.utc).isoformat()
        
        with open(json_path, 'w') as f:
            json.dump(file_data, f, indent=2)
            
        return "UPDATED", None

    except Exception as e:
        return "FAIL", str(e)

def main():
    targets = load_targets()
    print(f"[*] Starting Bulk Fetch for {len(targets)} ASNs with {MAX_WORKERS} workers...")
    
    stats = {'updated': 0, 'skipped': 0, 'failed': 0}
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_asn = {executor.submit(fetch_and_update, asn): asn for asn in targets}
        
        for i, future in enumerate(as_completed(future_to_asn)):
            asn = future_to_asn[future]
            try:
                status, err = future.result()
                if status == "UPDATED": stats['updated'] += 1
                elif status == "SKIPPED": stats['skipped'] += 1
                else: 
                    stats['failed'] += 1
                    # print(f"    [!] AS{asn} Failed: {err}") # Uncomment to see errors
            except Exception:
                stats['failed'] += 1
            
            if i % 50 == 0:
                elapsed = time.time() - start_time
                rate = (i+1) / elapsed if elapsed > 0 else 0
                print(f"    - {i+1}/{len(targets)} | Upd: {stats['updated']} | Skip: {stats['skipped']} | Fail: {stats['failed']} | {rate:.1f}/s", end="\r")

    print("\n" + "="*60)
    print("COMPLETE")
    print(f"Updated: {stats['updated']}")
    print(f"Skipped: {stats['skipped']}")
    print(f"Failed:  {stats['failed']}")
    print("[*] Now run 'python3 analyze_roa_signing.py' to see correct stats.")

if __name__ == "__main__":
    main()
