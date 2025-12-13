import os
import re
import json
import glob
import time
from bs4 import BeautifulSoup
from collections import Counter

# --- CONFIGURATION ---
DIR_HTML = "data/html"
DIR_JSON = "data/parsed"
os.makedirs(DIR_JSON, exist_ok=True)

# ==============================================================================
# THE MASTER PARSER (V2)
# ==============================================================================
def parse_html_content(html_content, asn):
    soup = BeautifulSoup(html_content, 'html.parser')
    text = soup.get_text()
    
    data = {
        'asn': int(asn),
        'name': 'Unknown',
        'is_tier1': False,
        'cone_size': 0,
        'peer_count': 0,           # New
        'downstream_direct': 0,    # New
        'upstream_count_summary': 0, # New (Claimed count)
        'upstreams': [],           # Actual list
        'cc': None,
        'roa_signed_pct': 0.0
    }

    # 1. Extract Name
    title = soup.find('title')
    if title:
        t_text = title.get_text().replace(" - bgp.tools", "")
        data['name'] = re.sub(r'^AS\d+\s+', '', t_text).strip()

    # 2. CONNECTIVITY SUMMARY (The "Hidden" Div)
    # <div style="display: none" id="connectivity-page">
    conn_div = soup.find(id="connectivity-page")
    if conn_div:
        # Loop through definition lists (<dl>) inside columns
        for dl in conn_div.find_all('dl'):
            dt = dl.find('dt')
            dd = dl.find('dd')
            if not dt or not dd: continue
            
            label = dt.get_text(strip=True).lower()
            val_text = dd.get_text(strip=True)
            
            # Clean number (remove non-digits temporarily)
            clean_num = re.sub(r'[^\d]', '', val_text)
            
            if 'peers' in label:
                data['peer_count'] = int(clean_num) if clean_num else 0
            
            elif 'upstreams' in label:
                data['upstream_count_summary'] = int(clean_num) if clean_num else 0
                
            elif 'downstreams' in label:
                # Format: "925 (Cone: 935)"
                # We need regex to split Direct vs Cone
                match = re.search(r'(\d+)\s*\(Cone:\s*(\d+)\)', val_text)
                if match:
                    data['downstream_direct'] = int(match.group(1))
                    data['cone_size'] = int(match.group(2))
                else:
                    # Just a number
                    data['downstream_direct'] = int(clean_num) if clean_num else 0
                    data['cone_size'] = data['downstream_direct'] # Fallback

    # 3. Fallback for Cone/Tier 1 (If div missing)
    if data['cone_size'] == 0:
        if "This network is transit-free" in text: data['is_tier1'] = True
        cone_match = re.search(r'Cone:\s*([\d,]+)', text)
        if cone_match: data['cone_size'] = int(cone_match.group(1).replace(',', ''))

    # 4. UPSTREAM TABLE (The specific ASNs)
    # We still need the list to build the graph
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

    # 5. Country & ROA
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

    return data

# ==============================================================================
# MAIN LOOP
# ==============================================================================
def main():
    files = glob.glob(os.path.join(DIR_HTML, "*.html"))
    print(f"[*] Found {len(files)} HTML files. Re-harvesting V2 Data...")
    
    count = 0
    
    for i, fpath in enumerate(files):
        filename = os.path.basename(fpath)
        
        if i % 100 == 0:
            print(f"    Processed {count}/{len(files)}...", end="\r")

        try:
            asn_str = filename.replace("as_", "").replace(".html", "")
            asn = int(asn_str)
            
            with open(fpath, 'r', encoding='utf-8') as f:
                html = f.read()
            
            data = parse_html_content(html, asn)
            
            # Update JSON
            json_path = os.path.join(DIR_JSON, f"as_{asn}.json")
            with open(json_path, 'w') as f:
                json.dump(data, f, indent=2)
                
            count += 1
                
        except Exception as e:
            pass

    print(f"\n[+] Harvest V2 Complete.")
    print(f"    - Updated {count} JSON files with Peer/Connectivity stats.")

if __name__ == "__main__":
    main()
