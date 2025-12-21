import os
import re
import json
import glob
import requests
import time
from datetime import datetime

# --- CONFIGURATION ---
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'}
DIR_JSON = "data/parsed"
DIR_ROA_CACHE = "data/apnic_roa" # Temporary cache for HTML/JSON responses
os.makedirs(DIR_ROA_CACHE, exist_ok=True)

# Cache TTL (If you want to "pick peaks over 30 days", you'd run this daily)
# For now, we fetch fresh.
CACHE_TTL = 86400 

def get_country_list():
    """Scans local parsed files to find which countries to fetch."""
    print("[*] Building Country List from local data...")
    ccs = set()
    files = glob.glob(os.path.join(DIR_JSON, "*.json"))
    for f in files:
        try:
            with open(f, 'r') as h:
                d = json.load(h)
                if d.get('cc') and d['cc'] != 'XX':
                    ccs.add(d['cc'])
        except: pass
    print(f"    - Found {len(ccs)} countries to scan.")
    return sorted(list(ccs))

def fetch_roa_page(cc):
    """Downloads the APNIC ROA page for a country."""
    url = f"https://stats.labs.apnic.net/roa/{cc}"
    cache_file = os.path.join(DIR_ROA_CACHE, f"{cc}.html")
    
    # Check Cache
    if os.path.exists(cache_file):
        if (time.time() - os.path.getmtime(cache_file)) < CACHE_TTL:
            with open(cache_file, 'r', encoding='utf-8') as f:
                return f.read()

    # Download
    try:
        time.sleep(0.5) # Politeness
        resp = requests.get(url, headers=HEADERS, timeout=15)
        if resp.status_code == 200:
            with open(cache_file, 'w', encoding='utf-8') as f:
                f.write(resp.text)
            return resp.text
    except Exception as e:
        print(f"    [!] Error fetching {cc}: {e}")
    
    return None

def parse_roa_js(html):
    """
    Parses the 'table_a' Google Viz data.
    Looking for rows: [ "AS1234", "Name", Total, Valid, Invalid, Unknown ... ]
    """
    roa_data = {}
    
    # Regex to find the data.addRows([...]) block for the main table.
    # We look for the pattern of an array starting with an ASN link.
    # Pattern: [ "<a href=... >AS(\d+)<", "Name", Total, Valid, Invalid, Unknown
    
    # We'll use a robust line-by-line scanner since the format is dense.
    for line in html.splitlines():
        if "AS" in line and "<a href" in line and "data.addRows" not in line:
            # Typical row: [ '<a href="...">AS1234</a>', 'Name', 100, 80, 0, 20, ... ]
            try:
                # Extract ASN
                asn_match = re.search(r'>AS(\d+)<', line)
                if not asn_match: continue
                asn = int(asn_match.group(1))
                
                # Extract Numbers
                # The line contains comma-separated values. 
                # We need to be careful of commas in the Name string.
                # Strategy: Extract all numbers after the Name.
                
                # Find the numbers using regex
                # We expect: Name, Total, Valid, Invalid, Unknown
                # JS numeric values don't have quotes.
                
                # This regex looks for: number, number, number, number
                # It handles the {v:1, f:'1%'} format if present, or raw numbers
                
                # Simplified approach: Extract all integers from the line
                # The first one found AFTER the "ASxxxx" link is usually the Total Routes
                # However, the Name is in between.
                
                # Let's split by comma, but respect quotes? Hard in regex.
                # Let's look for the sequence of numbers at the end.
                
                # Matches: , 100, 80, 0, 20 ]
                # Or: , {v:100...}, {v:80...}
                
                # Let's try to extract specific metrics if APNIC formats them as {v:X}
                # APNIC ROA table usually uses raw ints for counts.
                
                # Extract all digit sequences that stand alone
                nums = re.findall(r',\s*(\d+)\s*(?:,|\])', line)
                
                # Usually: [Total, Valid, Invalid, Unknown]
                # We need at least 4 numbers
                if len(nums) >= 4:
                    total = int(nums[0])
                    valid = int(nums[1])
                    invalid = int(nums[2])
                    unknown = int(nums[3])
                    
                    roa_data[asn] = {
                        'routes_total': total,
                        'routes_valid': valid,
                        'routes_invalid': invalid,
                        'routes_unknown': unknown,
                        'roa_coverage_pct': (valid / total * 100) if total > 0 else 0.0
                    }
            except: 
                continue
                
    return roa_data

def update_local_cache(roa_stats):
    """Updates the main data/parsed/as_XXXX.json files with ROA stats."""
    print(f"[*] Updating Local JSON Cache with ROA Stats ({len(roa_stats)} ASNs)...")
    
    count = 0
    for asn, stats in roa_stats.items():
        json_path = os.path.join(DIR_JSON, f"as_{asn}.json")
        
        # We only update if we have a record for this ASN (we don't create new files for random ASNs)
        # Or should we? The prompt implies we want to enhance existing data.
        if os.path.exists(json_path):
            try:
                with open(json_path, 'r') as f:
                    data = json.load(f)
                
                # Merge stats
                # Logic: If we already have stats (e.g. from another country scan), 
                # keep the one with the HIGHER total routes (Peak data logic).
                existing_total = data.get('roa_stats', {}).get('routes_total', -1)
                
                if stats['routes_total'] > existing_total:
                    data['roa_stats'] = stats
                    # Update the top-level pct for easy sorting later
                    data['roa_signed_pct'] = stats['roa_coverage_pct'] 
                    
                    with open(json_path, 'w') as f:
                        json.dump(data, f, indent=2)
                    count += 1
            except: pass
            
    print(f"    - Updated {count} JSON files with fresh ROA data.")

def main():
    countries = get_country_list()
    
    global_roa_data = {}
    
    print(f"[*] Fetching ROA Data for {len(countries)} countries...")
    for i, cc in enumerate(countries):
        print(f"    - [{i+1}/{len(countries)}] Fetching {cc}...", end="\r")
        
        html = fetch_roa_page(cc)
        if html:
            data = parse_roa_js(html)
            # Merge into global dict
            # If ASN exists, keep the one with max total routes (Peak detection)
            for asn, stats in data.items():
                if asn in global_roa_data:
                    if stats['routes_total'] > global_roa_data[asn]['routes_total']:
                        global_roa_data[asn] = stats
                else:
                    global_roa_data[asn] = stats
                    
    print("\n[*] Fetch complete.")
    print(f"    - Collected ROA stats for {len(global_roa_data)} unique ASNs.")
    
    update_local_cache(global_roa_data)

if __name__ == "__main__":
    main()
