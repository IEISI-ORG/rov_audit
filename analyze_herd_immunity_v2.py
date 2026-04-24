import pandas as pd
import os
import rov_utils

def print_header(title):
    print("\n" + "="*80)
    print(f" {title}")
    print("="*80)

def analyze():
    csv_file = rov_utils.FILE_AUDIT_FINAL
    if not os.path.exists(csv_file):
        print(f"[!] {csv_file} not found. Run rov_no_scrape_v21.py first.")
        return

    print(f"[*] Loading {csv_file}...")
    df = pd.read_csv(csv_file, low_memory=False)
    df['cone'] = pd.to_numeric(df['cone'], errors='coerce').fillna(0).astype(int)
    
    # Filter for Transit Providers only
    df_transit = df[df['cone'] > 5].sort_values(by='cone', ascending=False)
    
    def analyze_tier(top_n, label):
        subset = df_transit.head(top_n).copy()
        subset['category'] = subset['verdict'].apply(rov_utils.classify_verdict)
        
        secure = subset[subset['category'] == "SECURE"]
        vuln = subset[subset['category'] == "VULNERABLE"]
        
        total_power = subset['cone'].sum()
        secure_power = secure['cone'].sum()
        pct_secure = (secure_power / total_power) * 100 if total_power > 0 else 0
        
        print(f"\n[{label}] (The {top_n} largest networks)")
        print(f"  Networks Secure:     {len(secure):>3} / {top_n}  ({(len(secure)/top_n)*100:.1f}%)")
        print(f"  Traffic Protected:   {pct_secure:.1f}% (by Cone Weight)")
        
        bar_len = 50
        filled = int(bar_len * (pct_secure / 100))
        bar = "\033[92m" + "█" * filled + "\033[91m" + "░" * (bar_len - filled) + "\033[0m"
        print(f"  Progress: |{bar}|")
        return vuln

    print_header("HERD IMMUNITY STATUS")
    vuln_top100 = analyze_tier(100, "GLOBAL CORE")
    vuln_top1000 = analyze_tier(1000, "TRANSIT LAYER")

    print_header("THE HOLDOUTS (Top Vulnerable Transit Nets)")
    print("-" * 80)
    print(f"{'Rank':<5} | {'ASN':<8} | {'CC':<2} | {'Cone Size':<10} | {'Name'}")
    print("-" * 80)
    
    for i, (idx, r) in enumerate(vuln_top1000.head(25).iterrows()):
        rank = df_transit.index.get_loc(idx) + 1
        print(f"#{rank:<4} | AS{r['asn']:<6} | {r['cc']:<2} | {r['cone']:<10} | {r['name'][:40]}")

    print("-" * 80)
    print("\nCONCLUSION:")
    core_score = (vuln_top100['cone'].sum() / df_transit.head(100)['cone'].sum()) if not df_transit.head(100).empty else 1.0
    if core_score < 0.05: print("\033[92mHERD IMMUNITY ACHIEVED.\033[0m The Core is essentially safe.")
    elif core_score < 0.20: print("\033[93mCLOSE TO IMMUNITY.\033[0m The Core is mostly safe, but key giants remain.")
    else: print("\033[91mNO IMMUNITY.\033[0m Major transit providers are still leaking routes.")

if __name__ == "__main__":
    analyze()
