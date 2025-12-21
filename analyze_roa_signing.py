import pandas as pd
import json
import os
import glob
import argparse

# --- CONFIGURATION ---
DIR_JSON = "data/parsed"
FILE_AUDIT = "rov_audit_v18_final.csv"

def analyze():
    print("[*] Loading ROV Audit Data...")
    if not os.path.exists(FILE_AUDIT):
        print(f"[!] {FILE_AUDIT} not found.")
        return

    # 1. Load the Verdicts
    df = pd.read_csv(FILE_AUDIT, low_memory=False)
    df.set_index('asn', inplace=True)
    
    # 2. Enrich with Signing Data from JSON Cache
    print("[*] Loading Signing Stats from JSON Cache...")
    signing_data = {}
    
    files = glob.glob(os.path.join(DIR_JSON, "*.json"))
    for f in files:
        try:
            with open(f, 'r') as h:
                d = json.load(h)
                asn = d.get('asn')
                # The bulk parser calculates this from the flag icons
                pct = d.get('roa_signed_pct', 0.0)
                if asn:
                    signing_data[asn] = pct
        except: pass

    # Map to DataFrame
    df['signed_pct'] = df.index.map(signing_data).fillna(0.0)

    # ---------------------------------------------------------
    # SEGMENTATION
    # ---------------------------------------------------------
    
    # Categories
    fully_signed = df[df['signed_pct'] >= 90.0]
    partial_signed = df[(df['signed_pct'] > 0) & (df['signed_pct'] < 90.0)]
    unsigned = df[df['signed_pct'] == 0.0]
    
    # Verdict Masks
    is_secure = df['verdict'].str.contains("SECURE") | df['verdict'].str.contains("PROTECTED")
    is_vuln = df['verdict'].str.contains("VULNERABLE") | df['verdict'].str.contains("UNPROTECTED")

    # ---------------------------------------------------------
    # REPORTING
    # ---------------------------------------------------------
    print("\n" + "="*80)
    print("GLOBAL ROA SIGNING REPORT")
    print("="*80)
    
    total = len(df)
    print(f"Total Networks: {total:,}")
    print(f"  - Fully Signed (>90%):  {len(fully_signed):>6,}  ({(len(fully_signed)/total)*100:.1f}%)")
    print(f"  - Partially Signed:     {len(partial_signed):>6,}  ({(len(partial_signed)/total)*100:.1f}%)")
    print(f"  - Totally Unsigned:     {len(unsigned):>6,}  ({(len(unsigned)/total)*100:.1f}%)")

    # --- INSIGHT 1: GLASS HOUSES ---
    # They filter others (ROV), but don't sign their own routes.
    # If they get hijacked, their own filtering logic won't save them.
    glass_houses = df[is_secure & (df['signed_pct'] < 10.0)].sort_values(by='cone', ascending=False)
    
    print("\n" + "="*80)
    print("THE 'GLASS HOUSES' (Secure Provider, but Unsigned Routes)")
    print("These giants protect the internet, but don't protect themselves.")
    print("-" * 80)
    print(f"{'ASN':<8} | {'CC':<2} | {'Cone':<8} | {'Signed':<6} | {'Name'}")
    print("-" * 80)
    
    for asn, row in glass_houses.head(15).iterrows():
        print(f"AS{asn:<6} | {row['cc']:<2} | {int(row['cone']):<8} | {row['signed_pct']:>5.1f}% | {row['name'][:40]}")

    # --- INSIGHT 2: SCREAMING INTO THE VOID ---
    # They signed 100%, but their provider is Vulnerable.
    # Their ROAs are useless because their upstream accepts hijacks.
    screaming = df[is_vuln & (df['signed_pct'] > 95.0)].sort_values(by='cone', ascending=False)
    
    print("\n" + "="*80)
    print("SCREAMING INTO THE VOID (Fully Signed, but Vulnerable Upstreams)")
    print("They did their job (ROA), but their providers are failing them.")
    print("-" * 80)
    print(f"{'ASN':<8} | {'CC':<2} | {'Cone':<8} | {'Feeds':<6} | {'Name'}")
    print("-" * 80)
    
    for asn, row in screaming.head(15).iterrows():
        ups = f"{row['dirty_feeds']}/{row['total_feeds']}"
        print(f"AS{asn:<6} | {row['cc']:<2} | {int(row['cone']):<8} | {ups:<6} | {row['name'][:40]}")

    # --- INSIGHT 3: THE TOTAL FAILURES ---
    # No ROV, No ROA. Total Wild West.
    wild_west = df[is_vuln & (df['signed_pct'] == 0.0)].sort_values(by='cone', ascending=False)
    
    print("\n" + "="*80)
    print("THE WILD WEST (Vulnerable Upstreams + 0% Signed)")
    print("The most dangerous networks on the internet.")
    print("-" * 80)
    
    for asn, row in wild_west.head(10).iterrows():
        print(f"AS{asn:<6} | {row['cc']:<2} | {int(row['cone']):<8} | {row['name'][:45]}")

    print("\n")

if __name__ == "__main__":
    analyze()
