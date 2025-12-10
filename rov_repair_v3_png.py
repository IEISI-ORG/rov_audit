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

# --- 1. APNIC PARSER ---
def parse_apnic_js_robust(html_content):
    scores = {}
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
    
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r') as f:
                data = json.load(f)
                if len(data) > 0: return 
        except: pass

    print(f"    [DOWNLOAD] Fetching APNIC RPKI for {cc}...", end=" ")
    try:
        url = f"https://stats.labs.apnic.net/rpki/{cc}"
        resp = requests.get(url, headers=HEADERS)
        if resp.status_code == 200:
            scores = parse_apnic_js_robust(resp.text)
            if scores:
                with open(cache_file, 'w') as f: json.dump(scores, f)
                print(f"OK ({len(scores)} ASNs)")
            else:
                print("Failed (Regex mismatch)")
        else:
            print(f"HTTP {resp.status_code}")
        time.sleep(1.0)
    except Exception as e:
        print(f"Error: {e}")

# --- 3. FIX: EXTRACT CC FROM PNG FLAGS ---
def extract_data_from_html(html_content):
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # A. Country Code: Look for /assets/flags/XX.png
    # Case insensitive flag to handle AU.png vs au.png
    flags = re.findall(r'/assets/flags/([a-z]{2})\.png', html_content, re.IGNORECASE)
    
    # Also check the title="AU" attribute in img tags just in case
    titles = re.findall(r'<img[^>]+class="flag-img"[^>]+title="([a-z]{2})"', html_content, re.IGNORECASE)
    
    all_found = [f.upper() for f in flags + titles]
    
    cc = None
    if all_found:
        # Most common flag in the file (usually from the prefix list) is the owner's country
        cc = Counter(all_found).most_common(1)[0][0]

    # B. ROA Signed %
    # We look for the specific rpki.png image you found
    # <img class="flag-img" src="/assets/rpki.png" title="Has a valid RPKI cert">
    
    # Count rows in the prefix table roughly by counting flag occurrences
    total_prefixes = len(flags) 
    
    # Count valid RPKI images
    rpki_valid_count = len(re.findall(r'/assets/rpki\.png', html_content))
    
    signed_pct = 0.0
    if total_prefixes > 0:
        signed_pct = round((rpki_valid_count / total_prefixes) * 100, 1)

    return cc, signed_pct

# --- MAIN LOOP ---
def main():
    html_files = glob.glob(os.path.join(DIR_HTML, "*.html"))
    print(f"[*] Scanning {len(html_files)} cached HTML files using PNG Logic...")
    
    cc_map = {} 
    
    for i, file_path in enumerate(html_files):
        filename = os.path.basename(file_path)
        asn = filename.replace("as_", "").replace(".html", "")
        
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
            
        cc, signed_pct = extract_data_from_html(content)
        
        if cc:
            # Update JSON Cache
            json_path = os.path.join(DIR_JSON, f"as_{asn}.json")
            if os.path.exists(json_path):
                try:
                    with open(json_path, 'r') as jf: data = json.load(jf)
                    
                    # Update fields
                    data['cc'] = cc
                    data['roa_signed_pct'] = signed_pct
                    
                    with open(json_path, 'w') as jf: json.dump(data, jf)
                except: pass
            
            # Queue Download
            if cc not in cc_map: cc_map[cc] = 0
            cc_map[cc] += 1
            download_apnic_country(cc)

        if i % 100 == 0:
            print(f"    Scanned {i}/{len(html_files)}...", end="\r")

    print("\n" + "="*50)
    print(f"REPAIR COMPLETE.")
    print(f"Found {len(cc_map)} unique countries.")
    
    apnic_files = glob.glob(os.path.join(DIR_APNIC, "*.json"))
    print(f"[+] 'data/apnic/' now has {len(apnic_files)} datasets.")

if __name__ == "__main__":
    main()

