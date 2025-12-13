import os
import json
import glob
import pandas as pd
import argparse
from collections import Counter

# --- CONFIGURATION ---
DIR_JSON = "data/parsed"
FILE_AUDIT_CSV = "rov_audit_v12.csv"  # Default, can be changed via args

def scan_dataset(csv_file):
    print(f"[*] Scanning Local Database and {csv_file}...")

    # 1. Inventory Scraped ASNs (What we HAVE)
    scraped_asns = set()
    upstream_usage = Counter()
    
    json_files = glob.glob(os.path.join(DIR_JSON, "*.json"))
    print(f"    - analyzing {len(json_files)} JSON files...")
    
    for f in json_files:
        try:
            with open(f, 'r') as h:
                data = json.load(h)
                asn = data.get('asn')
                if asn:
                    scraped_asns.add(int(asn))
                    
                    # Record upstreams
                    for u in data.get('upstreams', []):
                        upstream_usage[int(u)] += 1
        except: pass

    # 2. Inventory Referenced ASNs (What we KNOW ABOUT)
    # The set of all ASNs that appear as an upstream to someone
    all_known_upstreams = set(upstream_usage.keys())
    
    # 3. Calculate Gaps
    # Missing = Listed as an upstream, but we don't have a JSON file for it
    missing_scrapes = all_known_upstreams - scraped_asns
    
    # 4. CSV Analysis (Verdicts)
    stats = {
        'total_rows': 0,
        'unverified': 0,
        'vulnerable': 0,
        'secure': 0,
        'dead': 0
    }
    
    if os.path.exists(csv_file):
        try:
            df = pd.read_csv(csv_file)
            stats['total_rows'] = len(df)
            stats['unverified'] = len(df[df['verdict'].str.contains("Unverified", na=False)])
            stats['vulnerable'] = len(df[df['verdict'].str.contains("VULNERABLE", na=False)])
            stats['secure'] = len(df[df['verdict'].str.contains("SECURE", na=False)])
            stats['dead'] = len(df[df['verdict'].str.contains("DEAD", na=False)])
        except Exception as e:
            print(f"[-] Error reading CSV: {e}")

    return scraped_asns, missing_scrapes, upstream_usage, stats

def main():
    parser = argparse.ArgumentParser(description="Find missing data gaps in the ROV dataset.")
    parser.add_argument("--csv", default=FILE_AUDIT_CSV, help="Path to the main audit CSV")
    parser.add_argument("--save", action="store_true", help="Save missing ASNs to missing_targets.txt")
    args = parser.parse_args()

    scraped, missing, usage, stats = scan_dataset(args.csv)

    print("\n" + "="*60)
    print("DATASET HEALTH SUMMARY")
    print("="*60)
    
    print(f"Total ASNs Scraped (JSON):      {len(scraped):,}")
    print(f"Total Unique Upstreams Found:   {len(usage):,}")
    
    print("-" * 60)
    print(f"AUDIT STATUS (from {args.csv}):")
    print(f"  Secure:           {stats['secure']:,}")
    print(f"  Vulnerable:       {stats['vulnerable']:,}")
    print(f"  Dead/Inactive:    {stats['dead']:,}")
    print(f"  \033[93mUnverified:       {stats['unverified']:,}\033[0m (Missing Data)")

    print("-" * 60)
    print(f"\033[91mMISSING UPSTREAM DATA: {len(missing):,} ASNs\033[0m")
    print("(These are providers for other networks, but we haven't scraped them yet)")

    # Top Missing Targets
    print("\nTOP 20 MISSING TARGETS (High Impact)")
    print("Scraping these will resolve the most 'Unverified' chains:")
    print(f"{'ASN':<8} | {'Downstreams':<12}")
    print("-" * 30)
    
    # Sort missing ASNs by how many people use them (popularity)
    top_missing = sorted(list(missing), key=lambda x: usage[x], reverse=True)
    
    for asn in top_missing[:20]:
        count = usage[asn]
        print(f"AS{asn:<6} | Used by {count}")

    if args.save and top_missing:
        with open("missing_targets.txt", "w") as f:
            for asn in top_missing:
                f.write(f"{asn}\n")
        print("\n[+] Saved all missing ASNs to 'missing_targets.txt'")
        print("    Run: while read asn; do python3 scrape_single_asn_v2.py $asn; done < missing_targets.txt")

if __name__ == "__main__":
    main()
