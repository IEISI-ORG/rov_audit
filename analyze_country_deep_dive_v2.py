import pandas as pd
import argparse
import os
import rov_utils

def print_header(title):
    print("\n" + "="*100)
    print(f" {title}")
    print("="*100)

def analyze_country(target_cc):
    target_cc = target_cc.upper()
    csv_file = rov_utils.FILE_AUDIT_FINAL
    
    if not os.path.exists(csv_file):
        print(f"[!] {csv_file} not found. Run rov_no_scrape_v21.py first.")
        return

    # 1. Load Data
    print(f"[*] Loading Global Audit for {target_cc}...")
    df = pd.read_csv(csv_file, low_memory=False)
    country_df = df[df['cc'] == target_cc].copy()
    
    if len(country_df) == 0:
        print(f"[!] No ASNs found for country code '{target_cc}'.")
        return

    country_df['cone'] = pd.to_numeric(country_df['cone'], errors='coerce').fillna(0).astype(int)
    country_df['apnic_score'] = pd.to_numeric(country_df['apnic_score'], errors='coerce').fillna(-1)
    
    # SECTION 1: NATIONAL IMMUNITY STATS
    print_header(f"NATIONAL ROUTING SECURITY: {target_cc}")
    total_asns = len(country_df)
    total_cone = country_df['cone'].sum()
    
    country_df['category'] = country_df['verdict'].apply(rov_utils.classify_verdict)
    
    secure = country_df[country_df['category'] == "SECURE"]
    vuln = country_df[country_df['category'] == "VULNERABLE"]
    
    pct_secure_traffic = (secure['cone'].sum() / total_cone * 100) if total_cone > 0 else 0
    pct_vuln_traffic = (vuln['cone'].sum() / total_cone * 100) if total_cone > 0 else 0
    
    print(f"Total Networks:      {total_asns:,}")
    print(f"Total Cone Gravity:  {total_cone:,}")
    print("-" * 60)
    print(f"\033[92mSECURE (ACTIVE/PASSIVE):\033[0m {len(secure):>5} ({len(secure)/total_asns*100:>4.1f}%) -> Protects {pct_secure_traffic:.1f}% of Traffic")
    print(f"\033[91mVULNERABLE NETWORKS:\033[0m     {len(vuln):>5} ({len(vuln)/total_asns*100:>4.1f}%) -> Exposes  {pct_vuln_traffic:.1f}% of Traffic")
    
    # SECTION 2: THE NATIONAL GIANTS
    print_header(f"THE {target_cc} CORE (Top 20 Networks)")
    print(f"{'ASN':<8} | {'Verdict':<30} | {'Cone':<8} | {'APNIC%':<6} | {'Name'}")
    print("-" * 100)
    
    giants = country_df.sort_values(by='cone', ascending=False).head(20)
    for _, r in giants.iterrows():
        v = r['verdict']
        cat = rov_utils.classify_verdict(v)
        color = "\033[92m" if cat == "SECURE" else "\033[91m" if cat == "VULNERABLE" else "\033[93m" if cat == "PARTIAL" else "\033[90m"
        score = f"{int(r['apnic_score'])}%" if r['apnic_score'] > -1 else "-"
        print(f"AS{r['asn']:<6} | {color}{v:<30}\033[0m | {r['cone']:<8} | {score:<6} | {r['name'][:40]}")

    # SECTION 3: SUPPLY CHAIN ANALYSIS
    print_header(f"TRANSIT SUPPLY CHAIN (Who provides to {target_cc}?)")
    cc_asns = country_df['asn'].astype(int).tolist()
    upstream_counts = rov_utils.load_upstreams_from_cache(cc_asns)
    
    print(f"{'Rank':<4} | {'Upstream':<8} | {'Dependents':<10} | {'Global Status':<30} | {'Name'}")
    print("-" * 100)
    
    for i, (asn, count) in enumerate(upstream_counts.most_common(20)):
        provider_row = df[df['asn'] == asn]
        if not provider_row.empty:
            r = provider_row.iloc[0]
            v = r['verdict']
            cat = rov_utils.classify_verdict(v)
            color = "\033[92m" if cat == "SECURE" else "\033[91m" if cat == "VULNERABLE" else "\033[90m"
            print(f"#{i+1:<3} | AS{asn:<6} | {count:<10} | {color}{v:<30}\033[0m | {r['name'][:40]}")
        else:
            print(f"#{i+1:<3} | AS{asn:<6} | {count:<10} | {'Unknown (Not in Audit)':<30} | -")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("cc", help="ISO-2 Country Code (e.g. FR, US, AU)")
    args = parser.parse_args()
    analyze_country(args.cc)
