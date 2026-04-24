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
    ).reset_index()
    
    # Custom Sort: NOT ROUTED and Unverified at the bottom
    def verdict_priority(v):
        v = str(v).upper()
        if "NOT ROUTED" in v: return 100
        if "UNVERIFIED" in v: return 99
        return 0

    verdict_stats['priority'] = verdict_stats['verdict'].apply(verdict_priority)
    verdict_stats = verdict_stats.sort_values(by=['priority', 'Count'], ascending=[True, False])

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
        if rov_utils.is_secure(v): color = "\033[92m" 
        elif rov_utils.is_vulnerable(v): color = "\033[91m" 
        elif rov_utils.is_partial(v): color = "\033[93m" 
        reset = "\033[0m"

        print(f"{color}{v:<35}{reset} | {cnt:>8,} | {pct_asn:>6.1f}% | {avg:>10.1f} | {pct_impact:>6.1f}%")

    # 2. ATLAS ANALYSIS
    # ... (Atlas analysis remains similar as it uses internal SECURE/VULNERABLE tags)

    # 3. HIGH LEVEL SUMMARY
    print_header("SUMMARY")
    df['category'] = df['verdict'].apply(rov_utils.classify_verdict)
    
    cnt_sec = len(df[df['category'] == "SECURE"])
    cnt_vuln = len(df[df['category'] == "VULNERABLE"])
    cnt_part = len(df[df['category'] == "PARTIAL"])
    
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
