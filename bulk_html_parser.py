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
# THE MASTER PARSER
# ==============================================================================
def parse_html_content(html_content, asn):
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

    # 1. Extract Name
    title = soup.find('title')
    if title:
        t_text = title.get_text().replace(" - bgp.tools", "")
        data['name'] = re.sub(r'^AS\d+\s+', '', t_text).strip()

    # 2. Tier 1 & Cone
    if "This network is transit-free" in text: data['is_tier1'] = True
    cone = re.search(r'Cone:\s*([\d,]+)', text)
    if cone: data['cone_size'] = int(cone.group(1).replace(',', ''))

    # 3. Upstreams
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

    # 4. Country Code & ROA
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
# MAIN LOOP (INCREMENTAL)
# ==============================================================================
def main():
    files = glob.glob(os.path.join(DIR_HTML, "*.html"))
    print(f"[*] Found {len(files)} HTML files. Checking for updates...")
    
    processed_count = 0
    skipped_count = 0
    errors = 0
    
    for i, fpath in enumerate(files):
        filename = os.path.basename(fpath)
        
        # Progress Indicator
        if i % 100 == 0:
            print(f"    Checking {i}/{len(files)} (Processed: {processed_count} | Skipped: {skipped_count})...", end="\r")

        try:
            asn_str = filename.replace("as_", "").replace(".html", "")
            asn = int(asn_str)
        except ValueError:
            continue
            
        json_path = os.path.join(DIR_JSON, f"as_{asn}.json")

        # --- INCREMENTAL LOGIC ---
        # If JSON exists AND JSON is newer than HTML, skip it.
        if os.path.exists(json_path):
            html_mtime = os.path.getmtime(fpath)
            json_mtime = os.path.getmtime(json_path)
            
            if json_mtime > html_mtime:
                skipped_count += 1
                continue
        # -------------------------
        
        # If we are here, we need to parse (either new file or HTML changed)
        try:
            with open(fpath, 'r', encoding='utf-8') as f:
                html = f.read()
            
            data = parse_html_content(html, asn)
            
            with open(json_path, 'w') as f:
                json.dump(data, f, indent=2)
                
            processed_count += 1
                
        except Exception as e:
            errors += 1
            # print(f"\n[-] Error AS{asn}: {e}")

    print(f"\n" + "="*50)
    print("HARVEST COMPLETE")
    print("="*50)
    print(f"Total HTML Files: {len(files)}")
    print(f"Skipped (Cached): {skipped_count}")
    print(f"Parsed (New/Upd): {processed_count}")
    print(f"Errors:           {errors}")

if __name__ == "__main__":
    main()
