import sys
import os
import json
import re
import time
import requests
import argparse
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

# ==============================================================================
# 1. BGP TOOLS PARSER
# ==============================================================================
def parse_bgptools_html(html_content, asn):
    soup = BeautifulSoup(html_content, 'html.parser')
    text = soup.get_text()
    
    data = {
        'asn': int(asn),
        'name': 'Unknown',
        'is_tier1': False,
        'cone_size': 0,
        'upstreams': [],
        'cc': None,
        'roa_signed_pct': 0.0
    }

    # Name (Title)
    title = soup.find('title')
    if title:
        t_text = title.get_text().replace(" - bgp.tools", "")
        data['name'] = re.sub(r'^AS\d+\s+', '', t_text).strip()

    # Tier 1 & Cone
    if "This network is transit-free" in text: data['is_tier1'] = True
    cone = re.search(r'Cone:\s*([\d,]+)', text)
    if cone: data['cone_size'] = int(cone.group(1).replace(',', ''))

    # Upstreams
    if not data['is_tier1']:
        upstreams = set()
        headers = soup.find_all(string=re.compile(r"Upstream", re.IGNORECASE))
        tables = []
        for h in headers:
            if "Downstream" in h or "Peer" in h: continue
            t = h.find_next("table")
            if t: tables.append(t)
        
        for t in tables:
            for row in t.find_all('tr'):
                cols = row.find_all('td')
                if len(cols) < 2: continue
                # Check first 2 cols for ASN
                for cell in cols[:2]:
                    txt = cell.get_text(strip=True).upper()
                    if txt.startswith("AS") and txt[2:].isdigit():
                        upstreams.add(int(txt[2:]))
                        break
        data['upstreams'] = list(upstreams)

    # Country Code (Flags)
    # Matches /assets/flags/au.png OR /flags/au.svg
    flags = re.findall(r'flags/([a-z]{2})\.(?:png|svg)', html_content, re.IGNORECASE)
    css_flags = re.findall(r'flag-icon-([a-z]{2})', html_content, re.IGNORECASE)
    all_ccs = [f.upper() for f in flags + css_flags]
    
    if all_ccs:
        data['cc'] = Counter(all_ccs).most_common(1)[0][0]
    else:
        # Fallback link
        link = re.search(r'href="/country/([a-z]{2})"', html_content, re.IGNORECASE)
        if link: data['cc'] = link.group(1).upper()

    # ROA Signed %
    rpki_valid_count = len(re.findall(r'/assets/rpki\.png', html_content))
    total_prefixes = len(all_ccs)
    if total_prefixes > 0:
        data['roa_signed_pct'] = round((rpki_valid_count / total_prefixes) * 100, 1)

    return data

# ==============================================================================
# 2. APNIC PARSER
# ==============================================================================
def parse_apnic_js(html_content):
    scores = {}
    pattern = re.compile(r'>AS(\d+)<.*?\{v:\s*([\d\.]+)', re.IGNORECASE)
    matches = pattern.findall(html_content)
    for asn_str, score_str in matches:
        try: scores[int(asn_str)] = float(score_str)
        except: continue
    return scores

# ==============================================================================
# 3. MAIN LOGIC
# ==============================================================================
def scrape_asn(asn):
    print(f"[*] Starting Fresh Scrape for AS{asn}...")
    
    # --- STEP 1: BGP TOOLS ---
    url = f"https://bgp.tools/as/{asn}"
    print(f"    - Downloading {url}...")
    
    try:
        resp = requests.get(url, headers=HEADERS)
        if resp.status_code == 404:
            print("    [!] ASN Not Found on bgp.tools")
            return
        resp.raise_for_status()
        html = resp.text
        
        # Save HTML Cache
        html_path = os.path.join(DIR_HTML, f"as_{asn}.html")
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        # Parse
        data = parse_bgptools_html(html, asn)
        print(f"      Name: {data['name']}")
        print(f"      Country: {data['cc']}")
        print(f"      Upstreams: {len(data['upstreams'])}")
        
        # Save Parsed JSON
        json_path = os.path.join(DIR_JSON, f"as_{asn}.json")
        with open(json_path, 'w') as f:
            json.dump(data, f, indent=2)
            
    except Exception as e:
        print(f"    [!] Error fetching bgp.tools: {e}")
        return

    # --- STEP 2: APNIC (If Country Found) ---
    if data['cc'] and data['cc'] != 'XX':
        cc = data['cc']
        apnic_file = os.path.join(DIR_APNIC, f"{cc}.json")
        
        # Determine if we should refresh APNIC data (e.g. if file is old or doesn't exist)
        should_refresh_apnic = True
        if os.path.exists(apnic_file):
            # Check file age (optional, here we force fresh because user asked for "fresh scrape")
            pass
            
        print(f"    - Updating APNIC Data for Country: {cc}...")
        try:
            apnic_url = f"https://stats.labs.apnic.net/rpki/{cc}"
            resp = requests.get(apnic_url, headers=HEADERS)
            
            if resp.status_code == 200:
                scores = parse_apnic_js(resp.text)
                
                # Update Cache
                with open(apnic_file, 'w') as f:
                    # Convert int keys back to str for JSON compatibility if needed, 
                    # but typically json.dump handles dicts fine. 
                    # Note: Previous scripts used str keys for APNIC json. Let's stick to that.
                    scores_str_keys = {str(k): v for k,v in scores.items()}
                    json.dump(scores_str_keys, f)
                
                my_score = scores.get(asn, -1)
                print(f"      APNIC ROV Score: {my_score}%")
            else:
                print(f"      [!] Failed to fetch APNIC data (HTTP {resp.status_code})")
                
        except Exception as e:
            print(f"      [!] Error fetching APNIC: {e}")
    else:
        print("    - Skipping APNIC (No Country Code found)")

    print(f"[*] Done. Data cached for AS{asn}.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fresh scrape a single ASN.")
    parser.add_argument("asn", type=int, help=" The ASN to scrape (e.g. 3356)")
    args = parser.parse_args()
    
    scrape_asn(args.asn)
