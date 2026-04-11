import pandas as pd
import requests
import os
import time
import json
import re
import glob

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

    try:
        time.sleep(0.5)
        resp = requests.get(url, headers=HEADERS, timeout=15)
        if resp.status_code == 200:
            with open(cache_file, 'w', encoding='utf-8') as f:
                f.write(resp.text)
            return resp.text
    except: pass
    return None

def parse_roa_data_strict(html):
    """
    Strictly parses Google Viz objects: {v: 88.0, ...}
    The first occurrence in an ASN row is the IPv4 Valid %.
    """
    results = {}
    
    # Regex to find the value inside the object
    # Matches: {v: 88.0,
    pct_pattern = re.compile(r'\{v:\s*([\d\.]+),')
    
    for line in html.splitlines():
        # Only process lines that define a row
        if "href" in line and ">AS" in line:
            # Extract ASN
            asn_match = re.search(r'>AS(\d+)<', line)
            if not asn_match: continue
            asn = int(asn_match.group(1))
            
            # Find all percentage objects
            matches = pct_pattern.findall(line)
            
            # The structure is: [Name, Count, {v:Valid%}, Count, {v:Invalid%}, Count, {v:Unknown%}, ...]
            # So the FIRST match is Valid % (IPv4)
            if matches:
                try:
                    valid_pct = float(matches[0])
                    results[asn] = valid_pct
                    
                    # DEBUG: Print Level3 to confirm fix
                    if asn == 3356:
                        print(f"    [DEBUG] Found AS3356: {valid_pct}%")
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
        print(f"    [{i+1}/{len(countries)}] Parsing ROA stats for {cc}...", end="\r")
        html = fetch_country_roa(cc)
        if html:
            data = parse_roa_data_strict(html)
            global_roa.update(data)
            
    print(f"\n[*] Extracted ROA Signing data for {len(global_roa)} ASNs.")
    update_database(global_roa)
    
    print("\n[SUCCESS] Data refreshed. Run 'python3 analyze_roa_signing.py' again.")

if __name__ == "__main__":
    main()
