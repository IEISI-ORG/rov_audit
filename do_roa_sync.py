import rov_utils
import subprocess
import os
import json
import glob
import pandas as pd

def main():
    # 1. Load Metadata
    meta, countries = rov_utils.load_metadata()
    if not countries:
        print("[!] No countries found.")
        return

    # 2. Build Go Tool
    if not os.path.exists("./fetch-roa"):
        print("[*] Building Go ROA fetcher...")
        subprocess.run(["go", "build", "-o", "fetch-roa", "fetch-roa.go"], check=True)

    # 3. PHASE 1: Country Bulk Sync (Fast)
    cc_list = ",".join(sorted(list(countries)))
    print(f"[*] PHASE 1: Bulk Country Sync ({len(countries)} countries)...")
    subprocess.run(["./fetch-roa", "-countries", cc_list], check=True)

    # 4. PHASE 2: Targeted ASN Sync (For missing giants)
    print("[*] PHASE 2: Checking for missing high-impact ASNs...")
    
    # Load all ASNs from audit and packed data
    if not os.path.exists(rov_utils.FILE_AUDIT_FINAL):
        print("[!] Audit file not found. Skipping Phase 2.")
        return
        
    df = pd.read_csv(rov_utils.FILE_AUDIT_FINAL)
    asn_data = rov_utils.load_all_asn_data()
    
    # Important ASNs (Cone > 50)
    important = df[df['cone'] > 50]['asn'].tolist()
    
    missing = []
    for asn in important:
        data = asn_data.get(asn, {})
        if 'roa_signed_pct' not in data:
            missing.append(str(asn))
            
    if missing:
        print(f"[*] Found {len(missing)} missing high-impact ASNs. Syncing individually...")
        # Chunking to avoid command line length limits
        chunk_size = 200
        for i in range(0, len(missing), chunk_size):
            chunk = ",".join(missing[i:i+chunk_size])
            subprocess.run(["./fetch-roa", "-asns", chunk, "-workers", "20"], check=True)
    else:
        print("[*] No missing high-impact ASNs found.")

    print("\n[SUCCESS] Global ROA Sync Complete.")

if __name__ == "__main__":
    main()
