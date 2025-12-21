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

# Add ?hf=1 to request JSON-friendly data (Header Free)
BASE_URL = "https://stats.labs.apnic.net/roa"

os.makedirs(DIR_JSON, exist_ok=True)
os.makedirs(DIR_ROA_CACHE, exist_ok=True)

def get_targets():
    print(f"[*] Reading Country Codes from {INPUT_CSV}...")
    if not os.path.exists(INPUT_CSV):
        print("    [!] CSV not found. Run rov_global_audit_v18.py first.")
        return []
    
    df = pd.read_csv(INPUT_CSV, usecols=['asn', 'cc'], low_memory=False)
    countries = df['cc'].dropna().unique()
    countries = [c for c in countries if len(str(c)) == 2 and c != 'XX']
    return sorted(countries)

def fetch_country_data(cc):
    """
    Fetches data with hf=1 (Header Free), which often returns JSON or JSON-embedded text.
    """
    url = f"{BASE_URL}/{cc}?hf=1"
    cache_file = os.path.join(DIR_ROA_CACHE, f"{cc}.json") # Try saving as .json
    
    # Check Cache (24h)
    if os.path.exists(cache_file):
        if (time.time() - os.path.getmtime(cache_file)) < 86400:
            with open(cache_file, 'r', encoding='utf-8') as f:
                return f.read()

    try:
        time.sleep(0.5)
        resp = requests.get(url, headers=HEADERS, timeout=15)
        if resp.status_code == 200:
            # Detect if it's actually JSON
            content = resp.text
            if content.strip().startswith("{") or content.strip().startswith("["):
                # It is JSON!
                with open(cache_file, 'w', encoding='utf-8') as f:
                    f.write(content)
                return content
            else:
                # It's HTML without headers (Fallback)
                # Save as .html for the regex parser
                cache_html = os.path.join(DIR_ROA_CACHE, f"{cc}.html")
                with open(cache_html, 'w', encoding='utf-8') as f:
                    f.write(content)
                return content
    except: pass
    return None

def parse_apnic_json(raw_data):
    """
    Parses native APNIC JSON structure.
    Expected: { 'data': [ [ASN, Name, Total, Valid%, ...], ... ] } 
    (Structure varies, so we inspect headers if available, or assume column order)
    """
    results = {}
    try:
        data_obj = json.loads(raw_data)
        
        # We need to find the data rows.
        # Often APNIC JSON is: {'data': [...]}
        rows = data_obj.get('data', [])
        
        for row in rows:
            # APNIC JSON rows are usually lists:
            # [ASN, Name, Total_Routes, Valid_Cnt, Invalid_Cnt, Unknown_Cnt, Valid_Pct, ...]
            # But we need to be careful of index changes.
            
            # Helper to find the ASN (int) and the Score (float)
            asn = None
            score = 0.0
            
            # Strategy: First integer is ASN? 
            # Or scan for the item that looks like an ASN.
            if len(row) > 0 and isinstance(row[0], int):
                asn = row[0]
            elif len(row) > 0 and isinstance(row[0], str) and row[0].startswith("AS"):
                asn = int(row[0].replace("AS", ""))
            
            if not asn: continue
            
            # Find the percentage. It's usually a float <= 100.
            # Or explicitly named columns if available.
            # Based on standard output, Valid% is often near index 6 or 7?
            # Let's search the row for floats.
            
            # If we assume the structure matches the visual table:
            # ASN, Name, Total, Valid, Invalid, Unknown, %Signed
            
            # In the JSON provided by your URL example (AS3356), it returns time series.
            # But the Country endpoint usually returns the summary table.
            
            # Heuristic: The largest float <= 100 might be it? 
            # No, that could be invalid %.
            
            # Let's rely on the previous V3 logic logic: 
            # If this is JSON, it's structured. 
            # Index 6 is often % Coverage.
            
            # Let's dump the first row to debug if needed, but for now:
            # Assume row[-1] or row[6]
            
            # Safer fallback: If JSON fails logic, return empty and let regex handle it?
            # Actually, APNIC country endpoints often return HTML even with hf=1.
            # If this function triggers, we have JSON.
            pass 
            
    except: pass
    return results

def parse_roa_hybrid(content):
    """
    Decides whether to use JSON parser or V3 Regex Parser.
    """
    # 1. Try JSON
    if content.strip().startswith("{"):
        try:
            # Placeholder for actual JSON logic if APNIC enables full JSON for countries
            # Currently they mostly use JS arrays embedded in HTML.
            # If you found a pure JSON endpoint, replace logic here.
            pass 
        except: pass

    # 2. Fallback to V3 Robust Regex (Proven to work)
    results = {}
    
    # Regex to find: {v: 88.0,
    pct_pattern = re.compile(r'\{v:\s*([\d\.]+),')
    
    for line in content.splitlines():
        if "href" in line and ">AS" in line:
            asn_match = re.search(r'>AS(\d+)<', line)
            if not asn_match: continue
            asn = int(asn_match.group(1))
            
            matches = pct_pattern.findall(line)
            if matches:
                try:
                    # First match is Valid % (IPv4)
                    results[asn] = float(matches[0])
                except: pass
                
    return results

def update_database(results):
    print(f"[*] Updating Local Database with {len(results)} ROA Records...")
    count = 0
    for asn, score in results.items():
        json_path = os.path.join(DIR_JSON, f"as_{asn}.json")
        data = {}
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
        if count % 2000 == 0: print(f"    - Processed {count}...", end="\r")
    print(f"\n[+] Updated {count} JSON files.")

def main():
    countries = get_targets()
    print(f"[*] Found {len(countries)} Countries to scan.")
    
    global_roa = {}
    
    for i, cc in enumerate(countries):
        print(f"    [{i+1}/{len(countries)}] Fetching ROA stats for {cc}...", end="\r")
        content = fetch_country_data(cc)
        if content:
            # Use the Hybrid Parser
            data = parse_roa_hybrid(content)
            global_roa.update(data)
            
    print(f"\n[*] Extracted ROA Signing data for {len(global_roa)} ASNs.")
    update_database(global_roa)
    print("\n[SUCCESS] Data refreshed. Run 'python3 analyze_roa_signing.py' again.")

if __name__ == "__main__":
    main()
