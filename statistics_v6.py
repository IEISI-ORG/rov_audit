import pandas as pd
import argparse
import os
import rov_utils

def print_header(title):
    print("\n" + "="*95)
    print(f" {title}")
    print("="*95)

def analyze(csv_file):
    if not os.path.exists(csv_file):
        print(f"[!] Error: File {csv_file} not found.")
        return

    print(f"[*] Loading {csv_file}...")
    try:
        df = pd.read_csv(csv_file, low_memory=False)
    except Exception as e:
        print(f"[!] Error reading CSV: {e}")
        return

    # Normalize columns
    df.columns = [c.strip().lower() for c in df.columns]
    
    if 'verdict' not in df.columns:
        print("[!] Critical Error: 'verdict' column missing.")
        return

    if 'cone' in df.columns:
        df['cone'] = pd.to_numeric(df['cone'], errors='coerce').fillna(0).astype(int)
    else:
        df['cone'] = 0
        
    # Standardized name from v21
    atlas_col = 'atlas_result'
    has_atlas = atlas_col in df.columns
    if has_atlas:
        df[atlas_col] = df[atlas_col].fillna("Not Tested/No Data")

    total_asns = len(df)
    global_cone_sum = df['cone'].sum()

    # 1. VERDICT ANALYSIS
    print_header("GLOBAL VERDICT STATISTICS")
    verdict_stats = df.groupby('verdict').agg(
        Count=('asn', 'count'),
        Avg_Cone=('cone', 'mean'),
        Total_Cone=('cone', 'sum')
    ).reset_index().sort_values(by='Count', ascending=False)

    print(f"{'VERDICT':<35} | {'ASNs':>8} | {'% ASNs':>7} | {'Avg Cone':>10} | {'Impact%':>7}")
    print("-" * 95)

    for _, row in verdict_stats.iterrows():
        v = str(row['verdict'])
        cnt = int(row['Count'])
        avg = row['Avg_Cone']
        cone_sum = row['Total_Cone']
        
        pct_asn = (cnt / total_asns) * 100
        pct_impact = (cone_sum / global_cone_sum) * 100 if global_cone_sum > 0 else 0.0
        
        color = ""
        if "SECURE" in v or "PROTECTED" in v: color = "\033[92m" 
        elif "VULNERABLE" in v or "UNPROTECTED" in v: color = "\033[91m" 
        elif "PARTIAL" in v: color = "\033[93m" 
        reset = "\033[0m"

        print(f"{color}{v:<35}{reset} | {cnt:>8,} | {pct_asn:>6.1f}% | {avg:>10.1f} | {pct_impact:>6.1f}%")

    # 2. ATLAS ANALYSIS
    if has_atlas:
        print_header("RIPE ATLAS VERIFICATION RESULTS")
        atlas_df = df[~df[atlas_col].isin(["", "Not Tested/No Data"])]
        if not atlas_df.empty:
            atlas_stats = atlas_df.groupby(atlas_col).agg(
                Count=('asn', 'count'),
                Avg_Cone=('cone', 'mean')
            ).reset_index().sort_values(by='Count', ascending=False)

            print(f"{'ATLAS RESULT':<35} | {'ASNs':>8} | {'Avg Cone':>10}")
            print("-" * 60)
            for _, row in atlas_stats.iterrows():
                r = str(row[atlas_col])
                cnt = int(row['Count'])
                avg = row['Avg_Cone']
                color = "\033[92m" if "SECURE" in r else "\033[91m" if "VULNERABLE" in r else "\033[93m"
                print(f"{color}{r:<35}\033[0m | {cnt:>8,} | {avg:>10.1f}")

    # 3. HIGH LEVEL SUMMARY
    print_header("SUMMARY")
    mask_secure = df['verdict'].str.contains("SECURE") | df['verdict'].str.contains("PROTECTED")
    mask_vuln   = df['verdict'].str.contains("VULNERABLE") | df['verdict'].str.contains("UNPROTECTED")
    mask_partial = df['verdict'].str.contains("PARTIAL")
    
    cnt_sec = len(df[mask_secure])
    cnt_vuln = len(df[mask_vuln])
    cnt_part = len(df[mask_partial])
    
    print(f"Total Networks: {total_asns:,}")
    print("-" * 60)
    print(f"\033[92mSECURE:\033[0m     {cnt_sec:>8,}  ({(cnt_sec/total_asns)*100:.1f}%)")
    print(f"\033[93mPARTIAL:\033[0m    {cnt_part:>8,}  ({(cnt_part/total_asns)*100:.1f}%)")
    print(f"\033[91mVULNERABLE:\033[0m {cnt_vuln:>8,}  ({(cnt_vuln/total_asns)*100:.1f}%)")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("csv_file", nargs='?', default=rov_utils.FILE_AUDIT_FINAL)
    args = parser.parse_args()
    analyze(args.csv_file)
