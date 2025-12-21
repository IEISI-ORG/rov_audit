import pandas as pd
import argparse
import os
import sys

# --- CONFIGURATION ---
DEFAULT_INPUT = "rov_audit_v19_final.csv"

def print_header(title):
    print("\n" + "="*80)
    print(f" {title}")
    print("="*80)

def analyze(csv_file):
    if not os.path.exists(csv_file):
        print(f"[!] Error: {csv_file} not found.")
        return

    print(f"[*] Loading {csv_file}...")
    df = pd.read_csv(csv_file, low_memory=False)
    
    # Ensure cone is int
    df['cone'] = pd.to_numeric(df['cone'], errors='coerce').fillna(0).astype(int)
    
    # Filter for Transit Providers only (Cone > 5) to remove noise
    df_transit = df[df['cone'] > 5].sort_values(by='cone', ascending=False)
    
    # ---------------------------------------------------------
    # 1. THE POWER LAW (Top 100 vs Top 1000)
    # ---------------------------------------------------------
    def analyze_tier(top_n, label):
        subset = df_transit.head(top_n)
        
        # Categorize
        secure = subset[subset['verdict'].str.contains("SECURE") | subset['verdict'].str.contains("PROTECTED")]
        vuln = subset[subset['verdict'].str.contains("VULNERABLE") | subset['verdict'].str.contains("UNPROTECTED")]
        partial = subset[subset['verdict'].str.contains("PARTIAL") | subset['verdict'].str.contains("MIXED")]
        
        # Calculate "Power" (Sum of Cones)
        total_power = subset['cone'].sum()
        secure_power = secure['cone'].sum()
        vuln_power = vuln['cone'].sum()
        partial_power = partial['cone'].sum()
        
        pct_secure = (secure_power / total_power) * 100
        
        print(f"\n[{label}] (The {top_n} largest networks)")
        print(f"  Networks Secure:     {len(secure):>3} / {top_n}  ({(len(secure)/top_n)*100:.1f}%)")
        print(f"  Traffic Protected:   {pct_secure:.1f}% (by Cone Weight)")
        
        # Progress Bar
        bar_len = 50
        filled = int(bar_len * (pct_secure / 100))
        bar = "\033[92m" + "█" * filled + "\033[91m" + "░" * (bar_len - filled) + "\033[0m"
        print(f"  Progress: |{bar}|")

        return vuln

    print_header("HERD IMMUNITY STATUS")
    
    # Analyze the Core (Tier 1s + Giants)
    vuln_top100 = analyze_tier(100, "GLOBAL CORE")
    
    # Analyze the Transit Layer
    vuln_top1000 = analyze_tier(1000, "TRANSIT LAYER")

    # ---------------------------------------------------------
    # 2. THE HOLDOUTS (Who is holding us back?)
    # ---------------------------------------------------------
    print_header("THE HOLDOUTS (Top Vulnerable Transit Nets)")
    print("If these networks enable ROV, global immunity jumps.")
    print("-" * 80)
    print(f"{'Rank':<5} | {'ASN':<8} | {'CC':<2} | {'Cone Size':<10} | {'Name'}")
    print("-" * 80)
    
    # Show top 25 from the Top 1000 list that are failing
    for i, row in enumerate(vuln_top1000.head(25).iterrows()):
        _, r = row
        rank = df_transit.index.get_loc(r.name) + 1
        print(f"#{rank:<4} | AS{r['asn']:<6} | {r['cc']:<2} | {r['cone']:<10} | {r['name'][:40]}")

    print("-" * 80)
    print("\nCONCLUSION:")
    
    # Simple Heuristic Verdict
    core_score = (vuln_top100['cone'].sum() / df_transit.head(100)['cone'].sum())
    
    if core_score < 0.05:
        print("\033[92mHERD IMMUNITY ACHIEVED.\033[0m The Core is essentially safe.")
    elif core_score < 0.20:
        print("\033[93mCLOSE TO IMMUNITY.\033[0m The Core is mostly safe, but key giants remain.")
    else:
        print("\033[91mNO IMMUNITY.\033[0m Major transit providers are still leaking routes.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("csv_file", nargs='?', default=DEFAULT_INPUT)
    args = parser.parse_args()
    analyze(args.csv_file)
