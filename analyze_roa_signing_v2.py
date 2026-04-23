import pandas as pd
import os
import rov_utils

def analyze():
    print("[*] Loading Data for ROA Signing Report...")
    if not os.path.exists(rov_utils.FILE_AUDIT_FINAL):
        print(f"[!] {rov_utils.FILE_AUDIT_FINAL} not found. Run rov_no_scrape_v21.py first.")
        return

    # 1. Load Audit Results
    df = pd.read_csv(rov_utils.FILE_AUDIT_FINAL, low_memory=False)
    df.set_index('asn', inplace=True)
    
    # 2. Load Signing Stats from Cache
    signing_data = rov_utils.load_signing_stats()
    df['signed_pct'] = df.index.map(signing_data).fillna(0.0)

    # Segmentation
    fully_signed = df[df['signed_pct'] >= 90.0]
    partial_signed = df[(df['signed_pct'] > 0) & (df['signed_pct'] < 90.0)]
    unsigned = df[df['signed_pct'] == 0.0]
    
    is_secure = df['verdict'].str.contains("ACTIVE") | df['verdict'].str.contains("PASSIVE") | df['verdict'].str.contains("PROTECTOR")
    is_vuln = df['verdict'].str.contains("VULNERABLE") | df['verdict'].str.contains("UNPROTECTED")

    print("\n" + "="*80)
    print("GLOBAL ROA SIGNING REPORT")
    print("="*80)
    
    total = len(df)
    print(f"Total Networks: {total:,}")
    print(f"  - Fully Signed (>90%):  {len(fully_signed):>6,}  ({(len(fully_signed)/total)*100:.1f}%)")
    print(f"  - Partially Signed:     {len(partial_signed):>6,}  ({(len(partial_signed)/total)*100:.1f}%)")
    print(f"  - Totally Unsigned:     {len(unsigned):>6,}  ({(len(unsigned)/total)*100:.1f}%)")

    # Insight 1: Glass Houses
    glass_houses = df[is_secure & (df['signed_pct'] < 10.0)].sort_values(by='cone', ascending=False)
    print("\n" + "="*80)
    print("THE 'GLASS HOUSES' (Secure Provider, but Unsigned Routes)")
    print("These giants protect the internet, but don't protect themselves.")
    print("-" * 80)
    print(f"{'ASN':<8} | {'CC':<2} | {'Cone':<8} | {'Signed':<6} | {'Name'}")
    print("-" * 80)
    for asn, row in glass_houses.head(15).iterrows():
        print(f"AS{asn:<6} | {row['cc']:<2} | {int(row['cone']):<8} | {row['signed_pct']:>5.1f}% | {row['name'][:40]}")

    # Insight 2: Screaming into the Void
    screaming = df[is_vuln & (df['signed_pct'] > 95.0)].sort_values(by='cone', ascending=False)
    print("\n" + "="*80)
    print("SCREAMING INTO THE VOID (Fully Signed, but Vulnerable Upstreams)")
    print("-" * 80)
    print(f"{'ASN':<8} | {'CC':<2} | {'Cone':<8} | {'Feeds':<6} | {'Name'}")
    print("-" * 80)
    for asn, row in screaming.head(15).iterrows():
        ups = f"{row['dirty_feeds']}/{row['total_feeds']}"
        print(f"AS{asn:<6} | {row['cc']:<2} | {int(row['cone']):<8} | {ups:<6} | {row['name'][:40]}")

    print("\n")

if __name__ == "__main__":
    analyze()
