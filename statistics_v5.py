import pandas as pd
import argparse
import os
import sys

# --- CONFIGURATION ---
DEFAULT_INPUT = "rov_audit_v19_final.csv"

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
        # low_memory=False handles mixed types cleanly
        df = pd.read_csv(csv_file, low_memory=False)
    except Exception as e:
        print(f"[!] Error reading CSV: {e}")
        return

    # --- DYNAMIC COLUMN HANDLING ---
    # 1. Normalize column names
    df.columns = [c.strip().lower() for c in df.columns]
    
    # 2. Check for critical columns
    if 'verdict' not in df.columns:
        print("[!] Critical Error: 'verdict' column missing from CSV.")
        return

    # 3. Handle optional columns with defaults
    if 'cone' in df.columns:
        df['cone'] = pd.to_numeric(df['cone'], errors='coerce').fillna(0).astype(int)
    else:
        df['cone'] = 0
        
    has_atlas = 'atlas_result' in df.columns
    if has_atlas:
        df['atlas_result'] = df['atlas_result'].fillna("Not Tested/No Data")

    total_asns = len(df)

    # ---------------------------------------------------------
    # 1. VERDICT ANALYSIS (Global Status)
    # ---------------------------------------------------------
    print_header("GLOBAL VERDICT STATISTICS")
    
    # Group by Verdict
    # We aggregate count and cone sum
    verdict_stats = df.groupby('verdict').agg(
        Count=('asn', 'count'),
        Avg_Cone=('cone', 'mean'),
        Median_Cone=('cone', 'median'),
        Total_Cone=('cone', 'sum')
    ).reset_index()

    # Sort by Count
    verdict_stats = verdict_stats.sort_values(by='Count', ascending=False)
    global_cone_sum = df['cone'].sum()

    print(f"{'VERDICT':<35} | {'ASNs':>8} | {'% ASNs':>7} | {'Avg Cone':>10} | {'Impact%':>7}")
    print("-" * 95)

    for _, row in verdict_stats.iterrows():
        v = str(row['verdict'])
        cnt = int(row['Count'])
        avg = row['Avg_Cone']
        cone_sum = row['Total_Cone']
        
        pct_asn = (cnt / total_asns) * 100
        pct_impact = (cone_sum / global_cone_sum) * 100 if global_cone_sum > 0 else 0.0
        
        # Color coding
        color = ""
        if "SECURE" in v or "PROTECTED" in v: color = "\033[92m" 
        elif "VULNERABLE" in v or "UNPROTECTED" in v: color = "\033[91m" 
        elif "DEAD" in v: color = "\033[90m" 
        elif "PARTIAL" in v: color = "\033[93m" 
        reset = "\033[0m"

        print(f"{color}{v:<35}{reset} | {cnt:>8,} | {pct_asn:>6.1f}% | {avg:>10.1f} | {pct_impact:>6.1f}%")

    # ---------------------------------------------------------
    # 2. ATLAS RESULT ANALYSIS (If Available)
    # ---------------------------------------------------------
    if has_atlas:
        print_header("RIPE ATLAS VERIFICATION RESULTS")
        
        atlas_df = df[df['atlas_result'] != "Not Tested/No Data"]
        
        if len(atlas_df) == 0:
            print("No Atlas results found in this dataset.")
        else:
            atlas_stats = atlas_df.groupby('atlas_result').agg(
                Count=('asn', 'count'),
                Avg_Cone=('cone', 'mean')
            ).reset_index().sort_values(by='Count', ascending=False)

            print(f"{'ATLAS RESULT':<35} | {'ASNs':>8} | {'Avg Cone':>10}")
            print("-" * 60)

            for _, row in atlas_stats.iterrows():
                r = str(row['atlas_result'])
                cnt = int(row['Count'])
                avg = row['Avg_Cone']
                
                color = ""
                if "SECURE" in r: color = "\033[92m"
                elif "VULNERABLE" in r: color = "\033[91m"
                elif "INCONCLUSIVE" in r or "MIXED" in r: color = "\033[93m"
                reset = "\033[0m"

                print(f"{color}{r:<35}{reset} | {cnt:>8,} | {avg:>10.1f}")
    else:
        # Gracefully skip if column missing
        pass

    # ---------------------------------------------------------
    # 3. HIGH LEVEL SUMMARY
    # ---------------------------------------------------------
    print_header("SUMMARY")
    
    df['verdict'] = df['verdict'].astype(str)
    
    mask_secure = df['verdict'].str.contains("SECURE") | df['verdict'].str.contains("PROTECTED")
    mask_vuln   = df['verdict'].str.contains("VULNERABLE") | df['verdict'].str.contains("UNPROTECTED")
    mask_partial = df['verdict'].str.contains("PARTIAL") | df['verdict'].str.contains("MIXED")
    mask_dead = df['verdict'].str.contains("DEAD")
    
    cnt_sec = len(df[mask_secure])
    cnt_vuln = len(df[mask_vuln])
    cnt_part = len(df[mask_partial])
    cnt_dead = len(df[mask_dead])
    
    # Active networks (exclude dead/unrouted for percentage calc)
    active_total = total_asns - cnt_dead
    if active_total < 1: active_total = 1
    
    print(f"Total Networks in DB: {total_asns:,}")
    print(f"Active / Routed:      {active_total:,}")
    print("-" * 60)
    
    print(f"\033[92mSECURE:\033[0m     {cnt_sec:>8,}  ({(cnt_sec/active_total)*100:.1f}% of Active)")
    print(f"\033[93mPARTIAL:\033[0m    {cnt_part:>8,}  ({(cnt_part/active_total)*100:.1f}% of Active)")
    print(f"\033[91mVULNERABLE:\033[0m {cnt_vuln:>8,}  ({(cnt_vuln/active_total)*100:.1f}% of Active)")

    if not has_atlas:
        print("\n[!] Note: 'atlas_result' column missing. Atlas stats skipped.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate statistics from ROV Audit CSV")
    parser.add_argument("csv_file", nargs='?', default=DEFAULT_INPUT, help="Path to CSV file")
    args = parser.parse_args()
    
    analyze(args.csv_file)
