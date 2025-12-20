import pandas as pd
import argparse
import os
import sys

# --- CONFIGURATION ---
DEFAULT_INPUT = "rov_audit_v18_final.csv"

def print_header(title):
    print("\n" + "="*80)
    print(f" {title}")
    print("="*80)

def analyze(csv_file):
    if not os.path.exists(csv_file):
        print(f"[!] Error: File {csv_file} not found.")
        return

    print(f"[*] Loading {csv_file}...")
    try:
        # FIX: low_memory=False prevents mixed-type warnings on columns like 'apnic_score'
        df = pd.read_csv(csv_file, low_memory=False)
    except Exception as e:
        print(f"[!] Error reading CSV: {e}")
        return

    # Clean up data types for analysis
    df['atlas_result'] = df['atlas_result'].fillna("Not Tested/No Data")
    
    # Ensure cone is integer (handle non-numeric errors gracefully)
    df['cone'] = pd.to_numeric(df['cone'], errors='coerce').fillna(0).astype(int)

    # ---------------------------------------------------------
    # 1. VERDICT ANALYSIS (Global Status)
    # ---------------------------------------------------------
    print_header("GLOBAL VERDICT STATISTICS")
    
    # Group by Verdict to get Count (ASNs) and Sum (Cone)
    verdict_stats = df.groupby('verdict').agg(
        ASN_Count=('asn', 'count'),
        Total_Cone=('cone', 'sum')
    ).reset_index()

    # Sort by ASN Count descending
    verdict_stats = verdict_stats.sort_values(by='ASN_Count', ascending=False)

    total_asns = len(df)
    total_cone = df['cone'].sum()

    print(f"{'VERDICT':<35} | {'ASNs':>8} | {'% ASNs':>7} | {'Cone Impact':>12} | {'% Cone':>7}")
    print("-" * 80)

    for _, row in verdict_stats.iterrows():
        v = str(row['verdict'])
        cnt = row['ASN_Count']
        cone = row['Total_Cone']
        
        pct_asn = (cnt / total_asns) * 100
        pct_cone = (cone / total_cone) * 100 if total_cone > 0 else 0
        
        # Color coding for terminal
        color = ""
        if "SECURE" in v or "PROTECTED" in v: color = "\033[92m" # Green
        elif "VULNERABLE" in v or "UNPROTECTED" in v: color = "\033[91m" # Red
        elif "DEAD" in v: color = "\033[90m" # Grey
        reset = "\033[0m"

        print(f"{color}{v:<35}{reset} | {cnt:>8,} | {pct_asn:>6.1f}% | {cone:>12,} | {pct_cone:>6.1f}%")

    # ---------------------------------------------------------
    # 2. ATLAS RESULT ANALYSIS (Active Verification)
    # ---------------------------------------------------------
    print_header("RIPE ATLAS VERIFICATION RESULTS")
    
    atlas_df = df[df['atlas_result'] != "Not Tested/No Data"]
    
    if len(atlas_df) == 0:
        print("No Atlas results found in this dataset.")
    else:
        atlas_stats = atlas_df.groupby('atlas_result').agg(
            ASN_Count=('asn', 'count'),
            Total_Cone=('cone', 'sum')
        ).reset_index().sort_values(by='ASN_Count', ascending=False)

        print(f"{'ATLAS RESULT':<35} | {'ASNs':>8} | {'Cone Impact':>12}")
        print("-" * 65)

        for _, row in atlas_stats.iterrows():
            r = str(row['atlas_result'])
            cnt = row['ASN_Count']
            cone = row['Total_Cone']
            
            color = ""
            if "SECURE" in r: color = "\033[92m"
            elif "VULNERABLE" in r: color = "\033[91m"
            elif "INCONCLUSIVE" in r or "MIXED" in r: color = "\033[93m"
            reset = "\033[0m"

            print(f"{color}{r:<35}{reset} | {cnt:>8,} | {cone:>12,}")

    # ---------------------------------------------------------
    # 3. HIGH LEVEL SUMMARY
    # ---------------------------------------------------------
    print_header("SUMMARY")
    
    # Calculate Secure vs Vulnerable totals
    # Convert verdict to string to avoid attribute errors on non-string types
    df['verdict'] = df['verdict'].astype(str)
    
    secure_mask = df['verdict'].str.contains("SECURE") | df['verdict'].str.contains("PROTECTED")
    vuln_mask = df['verdict'].str.contains("VULNERABLE") | df['verdict'].str.contains("UNPROTECTED")
    
    secure_cnt = df[secure_mask]['asn'].count()
    vuln_cnt = df[vuln_mask]['asn'].count()
    
    secure_cone = df[secure_mask]['cone'].sum()
    vuln_cone = df[vuln_mask]['cone'].sum()
    
    print(f"Total Networks Analyzed: {total_asns:,}")
    print(f"Total Downstream Networks (Cone): {total_cone:,}\n")
    
    print(f"SECURE Networks (Count):     \033[92m{secure_cnt:,}\033[0m")
    print(f"SECURE Impact (Cone):        \033[92m{secure_cone:,}\033[0m")
    print("-" * 40)
    print(f"VULNERABLE Networks (Count): \033[91m{vuln_cnt:,}\033[0m")
    print(f"VULNERABLE Impact (Cone):    \033[91m{vuln_cone:,}\033[0m")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate statistics from ROV Audit CSV")
    parser.add_argument("csv_file", nargs='?', default=DEFAULT_INPUT, help="Path to CSV file")
    args = parser.parse_args()
    
    analyze(args.csv_file)
