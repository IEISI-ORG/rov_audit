import pandas as pd
import argparse
import os
import sys

# --- CONFIGURATION ---
DEFAULT_INPUT = "rov_audit_v18_final.csv"

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
        # low_memory=False to handle mixed types cleanly
        df = pd.read_csv(csv_file, low_memory=False)
    except Exception as e:
        print(f"[!] Error reading CSV: {e}")
        return

    # Clean Data
    df['atlas_result'] = df['atlas_result'].fillna("Not Tested/No Data")
    df['cone'] = pd.to_numeric(df['cone'], errors='coerce').fillna(0).astype(int)
    total_asns = len(df)

    # ---------------------------------------------------------
    # 1. VERDICT ANALYSIS (Global Status)
    # ---------------------------------------------------------
    print_header("GLOBAL VERDICT STATISTICS")
    
    # Calculate Stats: Count, Average Cone, Median Cone
    verdict_stats = df.groupby('verdict').agg(
        Count=('asn', 'count'),
        Avg_Cone=('cone', 'mean'),
        Median_Cone=('cone', 'median')
    ).reset_index()

    # Sort by Count descending
    verdict_stats = verdict_stats.sort_values(by='Count', ascending=False)

    print(f"{'VERDICT':<35} | {'ASNs':>8} | {'% ASNs':>7} | {'Avg Cone':>10} | {'Median':>8}")
    print("-" * 95)

    for _, row in verdict_stats.iterrows():
        v = str(row['verdict'])
        cnt = int(row['Count'])
        avg = row['Avg_Cone']
        med = row['Median_Cone']
        
        pct_asn = (cnt / total_asns) * 100
        
        # Color coding
        color = ""
        if "SECURE" in v or "PROTECTED" in v: color = "\033[92m" # Green
        elif "VULNERABLE" in v or "UNPROTECTED" in v: color = "\033[91m" # Red
        elif "DEAD" in v: color = "\033[90m" # Grey
        elif "PARTIAL" in v: color = "\033[93m" # Yellow
        reset = "\033[0m"

        print(f"{color}{v:<35}{reset} | {cnt:>8,} | {pct_asn:>6.1f}% | {avg:>10.1f} | {med:>8.0f}")

    # ---------------------------------------------------------
    # 2. ATLAS RESULT ANALYSIS
    # ---------------------------------------------------------
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

    # ---------------------------------------------------------
    # 3. HIGH LEVEL SUMMARY
    # ---------------------------------------------------------
    print_header("SUMMARY")
    
    # Helper to calculate stats for a filter
    def get_stats(mask):
        subset = df[mask]
        count = len(subset)
        avg = subset['cone'].mean() if count > 0 else 0
        return count, avg

    # Filters
    df['verdict'] = df['verdict'].astype(str)
    
    mask_secure = df['verdict'].str.contains("SECURE") | df['verdict'].str.contains("PROTECTED")
    mask_vuln   = df['verdict'].str.contains("VULNERABLE") | df['verdict'].str.contains("UNPROTECTED")
    mask_partial = df['verdict'].str.contains("PARTIAL") | df['verdict'].str.contains("MIXED")
    
    cnt_sec, avg_sec = get_stats(mask_secure)
    cnt_vuln, avg_vuln = get_stats(mask_vuln)
    cnt_part, avg_part = get_stats(mask_partial)
    
    print(f"Total Networks Analyzed: {total_asns:,}")
    print("-" * 60)
    
    print(f"\033[92mSECURE:\033[0m     {cnt_sec:>8,} Networks  (Avg Cone: {avg_sec:,.1f})")
    print(f"\033[93mPARTIAL:\033[0m    {cnt_part:>8,} Networks  (Avg Cone: {avg_part:,.1f})")
    print(f"\033[91mVULNERABLE:\033[0m {cnt_vuln:>8,} Networks  (Avg Cone: {avg_vuln:,.1f})")
    
    print("-" * 60)
    # Interpretation
    if avg_vuln > avg_sec:
        print("Observation: Vulnerable networks are, on average, LARGER than secure ones.")
    else:
        print("Observation: Secure networks are, on average, LARGER than vulnerable ones.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate statistics from ROV Audit CSV")
    parser.add_argument("csv_file", nargs='?', default=DEFAULT_INPUT, help="Path to CSV file")
    args = parser.parse_args()
    
    analyze(args.csv_file)
