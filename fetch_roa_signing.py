import pandas as pd
import requests
import os
import time
import json
import re
import glob
from collections import defaultdict

# --- CONFIGURATION ---
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'}
DIR_JSON = "data/parsed"
DIR_ROA_CACHE = "data/apnic_roa"
INPUT_CSV = "rov_audit_v18_final.csv"

os.makedirs(DIR_JSON, exist_ok=True)
os.makedirs(DIR_ROA_CACHE, exist_ok=True)

def get_targets():
    print(f"[*] Reading Country Codes from {INPUT_CSV}...")
    if not os.path.exists(INPUT_CSV):
        print("    [!] CSV not found. Run rov_global_audit_v18.py first.")
        return []
    
    df = pd.read_csv(INPUT_CSV, usecols=['asn', 'cc'], low_memory=False)
    # Filter valid countries
    countries = df['cc'].dropna().unique()
    countries = [c for c in countries if len(str(c)) == 2 and c != 'XX']
    return sorted(countries)

def fetch_country_roa(cc):
    url = f"https://stats.labs.apnic.net/roa/{cc}"
    cache_file = os.path.join(DIR_ROA_CACHE, f"{cc}.html")
    
    # Cache Check (24h)
    if os.path.exists(cache_file):
        if (time.time() - os.path.getmtime(cache_file)) < 86400:
            with open(cache_file, 'r', encoding='utf-8') as f:
                return f.read()

    # Download
    try:
        time.sleep(0.5)
        resp = requests.get(url, headers=HEADERS, timeout=15)
        if resp.status_code == 200:
            with open(cache_file, 'w', encoding='utf-8') as f:
                f.write(resp.text)
            return resp.text
    except: pass
    return None

def parse_roa_data(html):
    """
    Parses APNIC ROA JS.
    Format is loose: look for ASN link, then grab the percentages/counts that follow.
    We specifically want the "% Signed" which is usually the last percentage in the row.
    """
    results = {}
    
    # Robust Regex:
    # 1. Matches AS link: >AS(\d+)<
    # 2. Matches ANY sequence of numbers/percentages afterwards
    # APNIC ROA table cols: ASN, Name, Total, Valid, Invalid, Unknown, %Signed
    
    for line in html.splitlines():
        if "href" in line and ">AS" in line:
            asn_match = re.search(r'>AS(\d+)<', line)
            if not asn_match: continue
            asn = int(asn_match.group(1))
            
            # Extract all numbers (integers or floats)
            # We look for patterns like "100" or "95.5"
            nums = re.findall(r'(\d+(?:\.\d+)?)', line)
            
            # The ASN itself is in nums, removing it.
            # Typical row numbers: [ASN, Total, Valid, Invalid, Unknown, Pct_Signed]
            # We want the LAST number usually, or calculate it.
            
            # Let's be safer: Calculate from counts.
            # We need to find the sequence of counts.
            # They usually appear after the Name string.
            
            # Skip the ASN and Name, look for the big integers
            # Heuristic: Find the largest integer? No.
            # Heuristic: Find 3 integers that sum to a 4th?
            
            # Let's try parsing the specific data.addRows structure if possible, 
            # but line scanning is often easier if we find the Total/Valid/Invalid block.
            
            # Alternative: Look for the % char.
            # The % Signed is usually explicitly listed.
            pct_match = re.findall(r'(\d+(?:\.\d+)?)%', line)
            if pct_match:
                # The first % is usually the "coverage" or "signed" metric
                try:
                    score = float(pct_match[0])
                    results[asn] = score
                except: pass
    return results

def update_database(results):
    print(f"[*] Updating Local Database with {len(results)} ROA Records...")
    count = 0
    for asn, score in results.items():
        json_path = os.path.join(DIR_JSON, f"as_{asn}.json")
        
        data = {}
        # Load existing or create new
        if os.path.exists(json_path):
            try:
                with open(json_path, 'r') as f: data = json.load(f)
            except: pass
        else:
            data = {'asn': asn}
            
        # Update Score
        data['roa_signed_pct'] = score
        
        try:
            with open(json_path, 'w') as f:
                json.dump(data, f, indent=2)
            count += 1
        except: pass
        
        if count % 1000 == 0: print(f"    - Processed {count}...", end="\r")
    print(f"\n[+] Updated {count} JSON files.")

def main():
    countries = get_targets()
    print(f"[*] Found {len(countries)} Countries to scan.")
    
    global_roa = {}
    
    for i, cc in enumerate(countries):
        print(f"    [{i+1}/{len(countries)}] Fetching ROA stats for {cc}...", end="\r")
        html = fetch_country_roa(cc)
        if html:
            data = parse_roa_data(html)
            global_roa.update(data)
            
    print(f"\n[*] Extracted ROA Signing data for {len(global_roa)} ASNs.")
    update_database(global_roa)
    
    print("\n[SUCCESS] Data refreshed. Now run 'python3 analyze_roa_signing.py' again.")

if __name__ == "__main__":
    main()
