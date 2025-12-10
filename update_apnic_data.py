import argparse
import pandas as pd
import requests
import os
import time
import json
import re
import sys

# --- CONFIGURATION ---
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}
DIR_APNIC = "data/apnic"
CACHE_TTL_SECONDS = 86400  # 24 Hours

# Ensure cache dir exists
os.makedirs(DIR_APNIC, exist_ok=True)

# ==============================================================================
# 1. PARSER ENGINE (Regex for Google Viz JS)
# ==============================================================================
def parse_apnic_js(html_content):
    scores = {}
    # Matches: >AS1234< ... {v: 99.81
    pattern = re.compile(r'>AS(\d+)<.*?\{v:\s*([\d\.]+)', re.IGNORECASE)
    matches = pattern.findall(html_content)
    for asn_str, score_str in matches:
        try: scores[asn_str] = float(score_str)
        except: continue
    return scores

# ==============================================================================
# 2. UPDATE LOGIC
# ==============================================================================
def check_and_update_cc(cc):
    cc = str(cc).upper().strip()
    
    # Skip invalid codes
    if not cc or len(cc) != 2 or cc == "XX":
        return "Skipped (Invalid CC)"

    cache_file = os.path.join(DIR_APNIC, f"{cc}.json")
    
    # Check Age
    if os.path.exists(cache_file):
        age = time.time() - os.path.getmtime(cache_file)
        if age < CACHE_TTL_SECONDS:
            return f"Skipped (Fresh, {int(age/3600)}h old)"
    
    # Download
    print(f"    - Fetching fresh data for [{cc}]...", end=" ")
    try:
        url = f"https://stats.labs.apnic.net/rpki/{cc}"
        resp = requests.get(url, headers=HEADERS, timeout=15)
        
        if resp.status_code == 200:
            scores = parse_apnic_js(resp.text)
            if scores:
                with open(cache_file, 'w') as f:
                    json.dump(scores, f)
                return f"UPDATED ({len(scores)} ASNs)"
            else:
                # Save empty to prevent retry loops on countries with no data
                with open(cache_file, 'w') as f: json.dump({}, f)
                return "Failed (Parse Error / No Data)"
        elif resp.status_code == 404:
            return "Failed (404 Not Found)"
        else:
            return f"Failed (HTTP {resp.status_code})"
            
        time.sleep(0.5) # Polite delay between requests
        
    except Exception as e:
        return f"Error: {str(e)}"

# ==============================================================================
# 3. MAIN LOOP
# ==============================================================================
def main():
    parser = argparse.ArgumentParser(description="Refresh stale APNIC RPKI data based on a CSV file.")
    parser.add_argument("csv_file", help="Path to the audit CSV (e.g., rov_audit_v10.csv)")
    parser.add_argument("--force", action="store_true", help="Ignore 24h timer and force update all")
    args = parser.parse_args()

    if not os.path.exists(args.csv_file):
        print(f"[!] Error: File not found: {args.csv_file}")
        sys.exit(1)

    # Load CSV
    print(f"[*] Reading {args.csv_file}...")
    try:
        df = pd.read_csv(args.csv_file)
        # Handle column names case-insensitively
        df.columns = [c.strip().lower() for c in df.columns]
        
        if 'cc' not in df.columns:
            print("[!] Error: CSV must contain a 'cc' or 'CC' column.")
            sys.exit(1)
            
        # Get Unique Countries
        unique_ccs = sorted(df['cc'].dropna().unique())
        print(f"[*] Found {len(unique_ccs)} unique countries to check.")
        
    except Exception as e:
        print(f"[!] Error parsing CSV: {e}")
        sys.exit(1)

    # Process
    if args.force:
        global CACHE_TTL_SECONDS
        CACHE_TTL_SECONDS = 0 # Force update
        print("[!] FORCE MODE: Updating all files regardless of age.")

    print("="*60)
    for i, cc in enumerate(unique_ccs):
        status = check_and_update_cc(cc)
        # Only print updates or errors to keep output clean, unless forced
        if "UPDATED" in status or "Failed" in status or args.force:
            print(f"[{i+1}/{len(unique_ccs)}] {cc}: {status}")
        else:
            # Optional: Dynamic progress line for skips
            print(f"[{i+1}/{len(unique_ccs)}] Checking {cc}...\r", end="")
            
    print("\n" + "="*60)
    print("[*] Update Complete.")

if __name__ == "__main__":
    main()
