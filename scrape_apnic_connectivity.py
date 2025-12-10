import os
import glob
import json
import time
import requests

# --- CONFIGURATION ---
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'}
DIR_HTML = "data/html"
DIR_APNIC = "data/apnic"

# 1. Load all ASNs that APNIC has measured
print("[*] Building target list from APNIC cache...")
apnic_asns = set()
files = glob.glob(os.path.join(DIR_APNIC, "*.json"))

for f in files:
    try:
        with open(f, 'r') as handle:
            data = json.load(handle)
            for k in data.keys():
                apnic_asns.add(int(k))
    except: pass

print(f"    Found {len(apnic_asns)} ASNs with ROV scores.")

# 2. Filter out ASNs we already have cached
existing_html = set()
for f in glob.glob(os.path.join(DIR_HTML, "*.html")):
    # Extract 1234 from 'data/html/as_1234.html'
    try:
        base = os.path.basename(f)
        asn = int(base.replace("as_", "").replace(".html", ""))
        existing_html.add(asn)
    except: pass

targets = list(apnic_asns - existing_html)
print(f"    We already have {len(existing_html)} cached.")
print(f"    Need to download {len(targets)} new pages.")
print("    (This will take time. Press Ctrl+C to stop and analyze what you have.)")
print("-" * 60)

# 3. Mass Downloader
for i, asn in enumerate(targets):
    url = f"https://bgp.tools/as/{asn}"
    file_path = os.path.join(DIR_HTML, f"as_{asn}.html")
    
    try:
        resp = requests.get(url, headers=HEADERS)
        if resp.status_code == 200:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(resp.text)
            print(f"[{i+1}/{len(targets)}] Downloaded AS{asn}")
        else:
            print(f"[{i+1}/{len(targets)}] Failed AS{asn} (HTTP {resp.status_code})")
            
        time.sleep(0.8) # Polite delay
        
    except KeyboardInterrupt:
        print("\n[!] Stopping download. You can run the analysis script now.")
        break
    except Exception as e:
        print(f"    Error: {e}")
