import os
import re
import json
import glob
import requests
import time
from bs4 import BeautifulSoup
from collections import Counter

# --- CONFIGURATION ---
HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

DIR_HTML = "data/html"
DIR_JSON = "data/parsed"
DIR_APNIC = "data/apnic"

# Ensure directories exist
for d in [DIR_HTML, DIR_JSON, DIR_APNIC]:
    os.makedirs(d, exist_ok=True)

# --- 1. ROBUST APNIC PARSER (JS Regex) ---
def parse_apnic_js_robust(html_content):
    scores = {}
    # Matches: >AS1234< ... {v: 99.81
    pattern = re.compile(r'>AS(\d+)<.*?\{v:\s*([\d\.]+)', re.IGNORECASE)
    matches = pattern.findall(html_content)
    for asn_str, score_str in matches:
        try: scores[asn_str] = float(score_str)
        except: continue
    return scores

# --- 2. APNIC DOWNLOADER ---
def download_apnic_country(cc):
    cc = cc.upper()
    cache_file = os.path.join(DIR_APNIC, f"{cc}.json")
    
    # Check if already exists and has data
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
                if len(data) > 0:
                    return # Already cached
        except: pass

    print(f"    [DOWNLOAD] Fetching APNIC RPKI data for Country: {cc}...", end=" ")
    try:
        url = f"https://stats.labs.apnic.net/rpki/{cc}"
        resp = requests.get(url, headers=HEADERS)
        if resp.status_code == 200:
            scores = parse_apnic_js_robust(resp.text)
            if scores:
                with open(cache_file, 'w') as f:
                    json.dump(scores, f)
                print(f"Success! ({len(scores)} ASNs found)")
            else:
                print("Failed (No data found in Regex)")
        else:
            print(f"Failed (HTTP {resp.status_code})")
        
        time.sleep(1.0) # Polite delay
    except Exception as e:
        print(f"Error: {e}")

# --- 3. COUNTRY CODE EXTRACTOR (Scans your HTML Cache) ---
def extract_cc_from_html(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # Strategy A: Look for the big flag in the header or tables
    # Matches /assets/flags/au.svg or /flags/au.svg
    flags = re.findall(r'flags/([a-z]{2})\.svg', html_content)
    
    # Strategy B: Look for CSS classes "flag-icon-au"
    css_flags = re.findall(r'flag-icon-([a-z]{2})', html_content)
    
    all_found = [f.upper() for f in flags + css_flags]
    
    if not all_found:
        return None
    
    # Return the most frequent country code found in the file
    # (Fixes edge cases where a foreign peer shows up in a table)
    most_common = Counter(all_found).most_common(1)
    return most_common[0][0]

# --- MAIN LOOP ---
def main():
    html_files = glob.glob(os.path.join(DIR_HTML, "*.html"))
    print(f"[*] Scanning {len(html_files)} cached HTML files to recover Country Codes...")
    
    cc_map = {} # cc -> count
    
    for i, file_path in enumerate(html_files):
        filename = os.path.basename(file_path)
        asn = filename.replace("as_", "").replace(".html", "")
        
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        cc = extract_cc_from_html(content)
        
        if cc:
            # Update the parsed JSON file if it exists, so the main script works faster next time
            json_path = os.path.join(DIR_JSON, f"as_{asn}.json")
            if os.path.exists(json_path):
                try:
                    with open(json_path, 'r') as jf:
                        data = json.load(jf)
                    data['cc'] = cc
                    with open(json_path, 'w') as jf:
                        json.dump(data, jf)
                except: pass
            
            # Queue for APNIC download
            if cc not in cc_map:
                cc_map[cc] = 0
            cc_map[cc] += 1
            
            # Trigger download immediately for this country
            download_apnic_country(cc)
            
        if i % 100 == 0:
            print(f"    Scanned {i}/{len(html_files)} files...", end="\r")

    print("\n\n" + "="*50)
    print("SUMMARY")
    print("="*50)
    print(f"Identified {len(cc_map)} unique countries.")
    print("Top Countries found in your cache:")
    for cc, count in sorted(cc_map.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {cc}: {count} ASNs")
    
    apnic_files = glob.glob(os.path.join(DIR_APNIC, "*.json"))
    print(f"\n[+] 'data/apnic/' now contains {len(apnic_files)} files.")
    print("You can now run the main analysis script.")

if __name__ == "__main__":
    main()
