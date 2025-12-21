import pandas as pd
import argparse
import os
import json
import sys
from collections import Counter

# --- CONFIGURATION ---
DEFAULT_INPUT = "rov_audit_v19_final.csv"
DIR_JSON = "data/parsed"

def print_header(title):
    print("\n" + "="*100)
    print(f" {title}")
    print("="*100)

def load_upstream_dependencies(target_asns):
    """
    Reads the local JSON files ONLY for the target ASNs to find out who feeds them.
    Returns: Counter({upstream_asn: count_of_dependents})
    """
    print(f"[*] Analyzing Upstream Supply Chain for {len(target_asns)} networks...")
    dependencies = Counter()
    
    found = 0
    for asn in target_asns:
        json_path = os.path.join(DIR_JSON, f"as_{asn}.json")
        if os.path.exists(json_path):
            try:
                with open(json_path, 'r') as f:
                    data = json.load(f)
                    upstreams = data.get('upstreams', [])
                    for u in upstreams:
                        dependencies[int(u)] += 1
                found += 1
            except: pass
            
    print(f"    - Analyzed connectivity for {found} networks.")
    return dependencies

def analyze_country(csv_file, target_cc):
    target_cc = target_cc.upper()
    
    if not os.path.exists(csv_file):
        print("CSV not found.")
        return

    # 1. Load Data
    print(f"[*] Loading Global Audit for {target_cc}...")
    df = pd.read_csv(csv_file, low_memory=False)
    
    # Filter for Country
    country_df = df[df['cc'] == target_cc].copy()
    
    if len(country_df) == 0:
        print(f"[!] No ASNs found for country code '{target_cc}'.")
        return

    # Clean numbers
    country_df['cone'] = pd.to_numeric(country_df['cone'], errors='coerce').fillna(0).astype(int)
    country_df['apnic_score'] = pd.to_numeric(country_df['apnic_score'], errors='coerce').fillna(-1)
    
    # ---------------------------------------------------------
    # SECTION 1: NATIONAL IMMUNITY STATS
    # ---------------------------------------------------------
    print_header(f"NATIONAL ROUTING SECURITY: {target_cc}")
    
    total_asns = len(country_df)
    total_cone = country_df['cone'].sum()
    
    # Verdict Groups
    secure = country_df[country_df['verdict'].str.contains("SECURE") | country_df['verdict'].str.contains("PROTECTED")]
    vuln = country_df[country_df['verdict'].str.contains("VULNERABLE") | country_df['verdict'].str.contains("UNPROTECTED")]
    partial = country_df[country_df['verdict'].str.contains("PARTIAL") | country_df['verdict'].str.contains("MIXED")]
    
    # Calculate Traffic %
    pct_secure_traffic = (secure['cone'].sum() / total_cone * 100) if total_cone > 0 else 0
    pct_vuln_traffic = (vuln['cone'].sum() / total_cone * 100) if total_cone > 0 else 0
    
    print(f"Total Networks:      {total_asns:,}")
    print(f"Total Cone Gravity:  {total_cone:,}")
    print("-" * 60)
    print(f"\033[92mSECURE NETWORKS:\033[0m     {len(secure):>5} ({len(secure)/total_asns*100:>4.1f}%) -> Protects {pct_secure_traffic:.1f}% of Traffic")
    print(f"\033[91mVULNERABLE NETWORKS:\033[0m {len(vuln):>5} ({len(vuln)/total_asns*100:>4.1f}%) -> Exposes  {pct_vuln_traffic:.1f}% of Traffic")
    
    # ---------------------------------------------------------
    # SECTION 2: ROA SIGNING HYGIENE
    # ---------------------------------------------------------
    # We don't have the ROA % in the V18 CSV explicitly as a column (it was in the JSON).
    # BUT, we can infer it if we load it or if it was added. 
    # V18 didn't explicitly save 'roa_signed_pct' column? 
    # Wait, check V18 script... it didn't save 'roa_signed_pct' to CSV.
    # We will skip this or reload from JSON if needed. 
    # Let's skip precise ROA % stats from CSV and focus on Verdicts.
    
    # ---------------------------------------------------------
    # SECTION 3: THE NATIONAL GIANTS (Top 20 by Cone)
    # ---------------------------------------------------------
    print_header(f"THE {target_cc} CORE (Top 20 Networks)")
    print(f"{'ASN':<8} | {'Verdict':<30} | {'Cone':<8} | {'APNIC%':<6} | {'Name'}")
    print("-" * 100)
    
    giants = country_df.sort_values(by='cone', ascending=False).head(20)
    for _, r in giants.iterrows():
        color = "\033[90m"
        v = r['verdict']
        if "SECURE" in v or "PROTECTED" in v: color = "\033[92m"
        elif "VULNERABLE" in v or "UNPROTECTED" in v: color = "\033[91m"
        elif "PARTIAL" in v: color = "\033[93m"
        
        score = f"{int(r['apnic_score'])}%" if r['apnic_score'] > -1 else "-"
        print(f"AS{r['asn']:<6} | {color}{v:<30}\033[0m | {r['cone']:<8} | {score:<6} | {r['name'][:40]}")

    # ---------------------------------------------------------
    # SECTION 4: SUPPLY CHAIN ANALYSIS (Who feeds France?)
    # ---------------------------------------------------------
    print_header(f"TRANSIT SUPPLY CHAIN (Who provides to {target_cc}?)")
    
    # Get all French ASNs
    fr_asns = country_df['asn'].astype(int).tolist()
    
    # Find who they buy from
    upstream_counts = load_upstream_dependencies(fr_asns)
    
    # We need to know the status of these Upstreams.
    # Look them up in the Global DF (not just the Country DF)
    
    print(f"{'Rank':<4} | {'Upstream':<8} | {'Dependents':<10} | {'Global Status':<30} | {'Name'}")
    print("-" * 100)
    
    # Sort by number of French customers
    top_providers = upstream_counts.most_common(20)
    
    for i, (asn, count) in enumerate(top_providers):
        # Lookup in master DF
        provider_row = df[df['asn'] == asn]
        
        if not provider_row.empty:
            r = provider_row.iloc[0]
            name = r['name']
            v = r['verdict']
            
            color = "\033[90m"
            if "SECURE" in v or "PROTECTED" in v: color = "\033[92m"
            elif "VULNERABLE" in v or "UNPROTECTED" in v: color = "\033[91m"
            
            print(f"#{i+1:<3} | AS{asn:<6} | {count:<10} | {color}{v:<30}\033[0m | {name[:40]}")
        else:
            print(f"#{i+1:<3} | AS{asn:<6} | {count:<10} | {'Unknown (Not in Audit)':<30} | -")

    # ---------------------------------------------------------
    # SECTION 5: TOP OFFENDERS (Vulnerable Giants)
    # ---------------------------------------------------------
    print_header(f"TOP VULNERABLE {target_cc} NETWORKS")
    
    bad_list = vuln.sort_values(by='cone', ascending=False).head(15)
    
    if bad_list.empty:
        print(f"No major vulnerable networks found in {target_cc}!")
    else:
        print(f"{'ASN':<8} | {'Cone':<8} | {'Feeds':<6} | {'Name'}")
        print("-" * 80)
        for _, r in bad_list.iterrows():
            ups = f"{r['dirty_feeds']}/{r['total_feeds']}"
            print(f"AS{r['asn']:<6} | {r['cone']:<8} | {ups:<6} | {r['name'][:50]}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Deep Dive Analysis for a specific Country")
    parser.add_argument("cc", help="ISO-2 Country Code (e.g. FR, US, AU)")
    parser.add_argument("--csv", default=DEFAULT_INPUT, help="Path to audit CSV")
    args = parser.parse_args()
    
    analyze_country(args.csv, args.cc)
