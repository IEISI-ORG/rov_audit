import pandas as pd
import os
from collections import defaultdict
import rov_utils

MIN_CONE = 20        # Ignore tiny networks
HIGH_SIGNING = 60.0  # Threshold for "Good" customer hygiene


def print_header(title: str) -> None:
    print("\n" + "=" * 110)
    print(f" {title}")
    print("=" * 110)


def calculate_cone_roa(root_asn: int, downstream: dict[int, list[int]], roa_map: dict[int, float]) -> float:
    """Average ROA signing % of all downstream customers (BFS over the customer cone)."""
    queue = [root_asn]
    seen = {root_asn}
    customers: list[int] = []

    idx = 0
    while idx < len(queue):
        curr = queue[idx]
        idx += 1
        for child in downstream.get(curr, []):
            if child not in seen:
                seen.add(child)
                queue.append(child)
                customers.append(child)

    if not customers:
        return 0.0
    return sum(roa_map.get(c, 0.0) for c in customers) / len(customers)


def analyze() -> None:
    if not os.path.exists(rov_utils.FILE_AUDIT_FINAL):
        print(f"[!] {rov_utils.FILE_AUDIT_FINAL} not found. Run rov_no_scrape_v22.py first.")
        return

    print("[*] Loading Data...")
    df = pd.read_csv(rov_utils.FILE_AUDIT_FINAL, low_memory=False)
    df['cone'] = pd.to_numeric(df['cone'], errors='coerce').fillna(0).astype(int)

    _, downstream, _ = rov_utils.load_topology()
    providers_of: dict[int, set] = defaultdict(set)
    for p, customers in downstream.items():
        for c in customers:
            providers_of[c].add(p)

    asn_data = rov_utils.load_all_asn_data()
    roa_map = {asn: d.get('roa_signed_pct', 0.0) for asn, d in asn_data.items()}

    def is_real_transit(asn: int) -> bool:
        """True if ASN has a legitimate cone (not IXP phantom inflation)."""
        if asn in rov_utils.TIER_1_ASNS:
            return True  # T1s are exempt: Tier 2 customers legitimately multi-home
        _, excl_pct, _ = rov_utils.cone_quality(asn, downstream, providers_of)
        return excl_pct >= rov_utils.CONE_QUALITY_THRESHOLD

    candidates = df[df['cone'] >= MIN_CONE]
    providers = candidates[candidates['asn'].apply(lambda a: is_real_transit(int(a)))].copy()

    phantom_count = len(candidates) - len(providers)
    if phantom_count:
        print(f"[!] {phantom_count} IXP phantom networks excluded "
              f"(< {rov_utils.CONE_QUALITY_THRESHOLD:.0f}% captive customers).")

    print("[*] Classifying Quadrants (this takes a moment)...")
    results = []
    total = len(providers)
    count = 0
    for _, row in providers.iterrows():
        asn = int(row['asn'])
        count += 1
        if count % 200 == 0:
            print(f"    - Processing {count}/{total}...", end="\r")

        avg_roa = calculate_cone_roa(asn, downstream, roa_map)
        secure = rov_utils.is_secure(str(row['verdict']))
        is_high_sign = avg_roa >= HIGH_SIGNING

        if secure and is_high_sign:
            quadrant = "Q1: GOLD STANDARD"
        elif not secure and is_high_sign:
            quadrant = "Q2: THE VICTIMS"
        elif secure and not is_high_sign:
            quadrant = "Q3: WASTED TECH"
        else:
            quadrant = "Q4: THE SWAMP"

        results.append({
            'Quadrant': quadrant,
            'ASN': asn,
            'CC': row['cc'],
            'Cone': row['cone'],
            'Percentile': avg_roa,
            'Name': row['name'],
        })

    out_df = pd.DataFrame(results)

    print_header("ROV STRATEGIC QUADRANT REPORT")

    definitions = {
        "Q1: GOLD STANDARD": "IDEAL STATE: Secure Provider + Responsible Customers.\n   The system is working as intended.",
        "Q2: THE VICTIMS":   "SCREAMING INTO THE VOID: Customers have signed ROAs (>60%), but Provider is LEAKING.\n   These providers are negating their customers' hard work.",
        "Q3: WASTED TECH":   "GLASS HOUSES: Provider filters invalids, but Customers (<60%) haven't signed ROAs.\n   The provider's security hardware is idle because customers are lazy.",
        "Q4: THE SWAMP":     "TOTAL FAILURE: Vulnerable Provider + Unsigned Customers.\n   The 'Wild West' of the internet.",
    }

    q_order = [
        ("Q1: GOLD STANDARD", "\033[92m"),  # Green
        ("Q2: THE VICTIMS",   "\033[93m"),  # Yellow
        ("Q3: WASTED TECH",   "\033[96m"),  # Cyan
        ("Q4: THE SWAMP",     "\033[91m"),  # Red
    ]

    for q_name, color in q_order:
        print(f"\n{color}=== {q_name} ===\033[0m")
        print(f"   {definitions[q_name]}")
        print("-" * 110)
        print(f"{'ASN':<8} | {'CC':<2} | {'Cone':<8} | {'% Sign':<6} | {'Name'}")
        print("-" * 110)

        subset = out_df[out_df['Quadrant'] == q_name].sort_values(by='Cone', ascending=False).head(5)
        for _, row in subset.iterrows():
            print(f"AS{row['ASN']:<6} | {row['CC']:<2} | {row['Cone']:<8} | {row['Percentile']:>5.1f}% | {row['Name'][:55]}")

    filename = "rov_quadrants_full.csv"
    out_df.sort_values(by=['Quadrant', 'Cone'], ascending=[True, False]).to_csv(filename, index=False)
    print(f"\n[+] Full quadrant data saved to {filename}")


if __name__ == "__main__":
    analyze()
