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

for d in [DIR_HTML, DIR_JSON, DIR_APNIC]: os.makedirs(d, exist_ok=True)

# ==============================================================================
# 1. ADVANCED HTML PARSER
# ==============================================================================
def parse_bgptools_html_v2(html_content, asn):
    soup = BeautifulSoup(html_content, 'html.parser')
    text = soup.get_text()
    
    data = {
        'asn': int(asn),
        'name': 'Unknown',
        'is_tier1': False,
        'cone_size': 0,
        'peer_count': 0,
        'downstream_direct': 0,
        'upstream_count_summary': 0,
        'upstreams': [],
        'cc': None,
        'roa_signed_pct': 0.0,
        'is_dead': False
    }

    # A. Name
    title = soup.find('title')
    if title:
        t_text = title.get_text().replace(" - bgp.tools", "")
        data['name'] = re.sub(r'^AS\d+\s+', '', t_text).strip()

    # B. Connectivity Summary (Hidden Div)
    conn_div = soup.find(id="connectivity-page")
    if conn_div:
        for dl in conn_div.find_all('dl'):
            dt = dl.find('dt')
            dd = dl.find('dd')
            if not dt or not dd: continue
            
            label = dt.get_text(strip=True).lower()
            val_text = dd.get_text(strip=True)
            clean_num = re.sub(r'[^\d]', '', val_text)
            
            if 'peers' in label:
                data['peer_count'] = int(clean_num) if clean_num else 0
            elif 'upstreams' in label:
                data['upstream_count_summary'] = int(clean_num) if clean_num else 0
            elif 'downstreams' in label:
                match = re.search(r'(\d+)\s*\(Cone:\s*(\d+)\)', val_text)
                if match:
                    data['downstream_direct'] = int(match.group(1))
                    data['cone_size'] = int(match.group(2))
                else:
                    data['downstream_direct'] = int(clean_num) if clean_num else 0
                    data['cone_size'] = data['downstream_direct']

    # C. Fallback Cone / Tier 1
    if data['cone_size'] == 0:
        if "This network is transit-free" in text: data['is_tier1'] = True
        cone_match = re.search(r'Cone:\s*([\d,]+)', text)
        if cone_match: data['cone_size'] = int(cone_match.group(1).replace(',', ''))

    # D. Upstream List (Specific ASNs)
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
                for cell in cols[:2]:
                    txt = cell.get_text(strip=True).upper()
                    if txt.startswith("AS") and txt[2:].isdigit():
                        upstreams.add(int(txt[2:]))
                        break
        data['upstreams'] = list(upstreams)

    # E. Country & ROA
    flags = re.findall(r'flags/([a-z]{2})\.(?:png|svg)', html_content, re.IGNORECASE)
    css_flags = re.findall(r'flag-icon-([a-z]{2})', html_content, re.IGNORECASE)
    all_ccs = [f.upper() for f in flags + css_flags]
    
    if all_ccs:
        data['cc'] = Counter(all_ccs).most_common(1)[0][0]
    else:
        link = re.search(r'href="/country/([a-z]{2})"', html_content, re.IGNORECASE)
        if link: data['cc'] = link.group(1).upper()

    rpki_valid_count = len(re.findall(r'/assets/rpki\.png', html_content))
    total_prefixes = len(all_ccs)
    if total_prefixes > 0:
        data['roa_signed_pct'] = round((rpki_valid_count / total_prefixes) * 100, 1)

    # F. Dead Check
    if data['cone_size'] == 0 and len(data['upstreams']) == 0 and data['peer_count'] == 0 and not data['cc']:
        data['is_dead'] = True

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
# 3. MAIN WORKFLOW
# ==============================================================================
def scrape_asn(asn):
    print(f"[*] Starting Precision Scrape for AS{asn}...")
    
    # 1. Fetch BGP Tools
    url = f"https://bgp.tools/as/{asn}"
    print(f"    - Downloading {url}...")
    
    try:
        resp = requests.get(url, headers=HEADERS)
        if resp.status_code == 404:
            print("    [!] ASN Not Found.")
            return
        
        # Save HTML
        with open(os.path.join(DIR_HTML, f"as_{asn}.html"), 'w', encoding='utf-8') as f:
            f.write(resp.text)
        
        # Parse
        data = parse_bgptools_html_v2(resp.text, asn)
        
        # Save JSON
        with open(os.path.join(DIR_JSON, f"as_{asn}.json"), 'w') as f:
            json.dump(data, f, indent=2)

        # Report
        status = "\033[91mDEAD\033[0m" if data['is_dead'] else "\033[92mACTIVE\033[0m"
        print(f"      Name:      {data['name']}")
        print(f"      Country:   {data['cc']}")
        print(f"      Status:    {status}")
        print(f"      Cone:      {data['cone_size']} (Direct: {data['downstream_direct']})")
        print(f"      Peers:     {data['peer_count']}")
        print(f"      Upstreams: {len(data['upstreams'])} (Claimed: {data['upstream_count_summary']})")
        print(f"      ROA Sign:  {data['roa_signed_pct']}%")

        if data['is_dead']: return

    except Exception as e:
        print(f"    [!] Error fetching bgp.tools: {e}")
        return

    # 2. Fetch APNIC (if applicable)
    if data['cc'] and data['cc'] != 'XX':
        print(f"    - Checking APNIC for {data['cc']}...")
        try:
            apnic_url = f"https://stats.labs.apnic.net/rpki/{data['cc']}"
            resp = requests.get(apnic_url, headers=HEADERS)
            
            if resp.status_code == 200:
                scores = parse_apnic_js(resp.text)
                
                # Update Cache
                with open(os.path.join(DIR_APNIC, f"{data['cc']}.json"), 'w') as f:
                    json.dump({str(k):v for k,v in scores.items()}, f)
                
                score = scores.get(asn)
                if score is not None:
                    print(f"      APNIC ROV Score: \033[96m{score}%\033[0m")
                else:
                    print(f"      APNIC ROV Score: N/A (Not in dataset)")
            else:
                print(f"      [!] Failed to fetch APNIC data.")
        except Exception as e:
            print(f"      [!] Error fetching APNIC: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Surgical data scrape for a single ASN.")
    parser.add_argument("asn", type=int)
    args = parser.parse_args()
    scrape_asn(args.asn)
