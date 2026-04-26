import pandas as pd
import os
from collections import defaultdict
import rov_utils


def print_header(title):
    print("\n" + "=" * 80)
    print(f" {title}")
    print("=" * 80)


def analyze():
    csv_file = rov_utils.FILE_AUDIT_FINAL
    if not os.path.exists(csv_file):
        print(f"[!] {csv_file} not found. Run rov_no_scrape_v22.py first.")
        return

    print(f"[*] Loading {csv_file}...")
    df = pd.read_csv(csv_file, low_memory=False)
    df['cone'] = pd.to_numeric(df['cone'], errors='coerce').fillna(0).astype(int)

    # Load topology for cone quality checks
    _, downstream, upstreams = rov_utils.load_topology()
    providers_of: dict[int, set] = defaultdict(set)
    for p, customers in downstream.items():
        for c in customers:
            providers_of[c].add(p)

    def is_real_transit(asn: int) -> bool:
        """True if ASN has a legitimate cone (not IXP phantom inflation)."""
        if asn in rov_utils.TIER_1_ASNS:
            return True  # T1s are exempt: Tier 2 customers legitimately multi-home
        _, excl_pct, _ = rov_utils.cone_quality(asn, downstream, providers_of)
        return excl_pct >= rov_utils.CONE_QUALITY_THRESHOLD

    # Filter: transit networks with legitimate cones
    df_transit = df[df['cone'] > 5].sort_values(by='cone', ascending=False)
    df_transit = df_transit[df_transit['asn'].apply(lambda a: is_real_transit(int(a)))]

    phantom_count = len(df[df['cone'] > 5]) - len(df_transit)
    if phantom_count:
        print(f"[!] {phantom_count} IXP phantom networks excluded "
              f"(< {rov_utils.CONE_QUALITY_THRESHOLD:.0f}% captive customers). "
              f"Re-run build_topology for full fix.")

    def analyze_tier(top_n: int, label: str) -> pd.DataFrame:
        subset = df_transit.head(top_n).copy()
        subset['category'] = subset['verdict'].apply(rov_utils.classify_verdict)

        secure = subset[subset['category'] == "SECURE"]
        total_power = subset['cone'].sum()
        secure_power = secure['cone'].sum()
        pct_secure = (secure_power / total_power * 100) if total_power > 0 else 0

        print(f"\n[{label}] (The {top_n} largest legitimate transit networks)")
        print(f"  Networks Secure:     {len(secure):>3} / {top_n}  ({len(secure)/top_n*100:.1f}%)")
        print(f"  Traffic Protected:   {pct_secure:.1f}% (by Cone Weight)")

        bar_len = 50
        filled = int(bar_len * pct_secure / 100)
        bar = "\033[92m" + "█" * filled + "\033[91m" + "░" * (bar_len - filled) + "\033[0m"
        print(f"  Progress: |{bar}|")
        return subset[subset['category'] == "VULNERABLE"]

    print_header("HERD IMMUNITY STATUS")
    vuln_top100  = analyze_tier(100,  "GLOBAL CORE")
    vuln_top1000 = analyze_tier(1000, "TRANSIT LAYER")

    print_header("THE HOLDOUTS (Top Vulnerable Transit Nets)")
    print("-" * 84)
    print(f"{'Rank':<5} | {'ASN':<8} | {'CC':<2} | {'Cone':>10} | {'Excl%':>6} | {'Name'}")
    print("-" * 84)

    shown = 0
    for idx, r in df_transit.iterrows():
        if shown >= 25:
            break
        asn = int(r['asn'])
        cat = rov_utils.classify_verdict(str(r['verdict']))
        if cat != "VULNERABLE":
            continue
        rank = df_transit.index.get_loc(idx) + 1
        _, excl_pct, _ = rov_utils.cone_quality(asn, downstream, providers_of)
        print(f"#{rank:<4} | AS{asn:<6} | {r['cc']:<2} | {r['cone']:>10,} | {excl_pct:>5.0f}% | {str(r['name'])[:40]}")
        shown += 1

    print("-" * 84)

    print("\nCONCLUSION:")
    core_vuln_power = vuln_top100['cone'].sum()
    core_total_power = df_transit.head(100)['cone'].sum()
    core_score = core_vuln_power / core_total_power if core_total_power > 0 else 1.0
    if core_score < 0.05:
        print("\033[92mHERD IMMUNITY ACHIEVED.\033[0m The Core is essentially safe.")
    elif core_score < 0.20:
        print("\033[93mCLOSE TO IMMUNITY.\033[0m The Core is mostly safe, but key giants remain.")
    else:
        print("\033[91mNO IMMUNITY.\033[0m Major transit providers are still leaking routes.")


if __name__ == "__main__":
    analyze()
