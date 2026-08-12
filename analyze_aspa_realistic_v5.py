import pandas as pd
import os
from collections import Counter
import rov_utils


def print_header(title: str) -> None:
    print("\n" + "=" * 95)
    print(f" {title}")
    print("=" * 95)


def get_prob(verdict: str) -> float:
    """Probability weight that a provider actually enforces ASPV if it signs."""
    if rov_utils.is_secure(verdict):
        return 1.0
    if rov_utils.is_partial(verdict):
        return 0.4
    return 0.05


def is_regular_network(asn: int) -> bool:
    """Exclude Tier 1 cores and non-transit infrastructure (RIRs, root servers, IXP
    route servers) — these don't have meaningful 'upstream' relationships to model."""
    return asn not in rov_utils.TIER_1_ASNS and asn not in rov_utils.NON_TRANSIT_ASNS


def analyze() -> None:
    if not os.path.exists(rov_utils.FILE_AUDIT_FINAL):
        print(f"[!] {rov_utils.FILE_AUDIT_FINAL} not found. Run rov_no_scrape_v22.py first.")
        return

    print("[*] Loading Data...")
    df = pd.read_csv(rov_utils.FILE_AUDIT_FINAL, low_memory=False)
    df['cone'] = pd.to_numeric(df['cone'], errors='coerce').fillna(0).astype(int)
    verdict_map = df.set_index('asn')['verdict'].to_dict()
    name_map = df.set_index('asn')['name'].to_dict()
    cone_map = df.set_index('asn')['cone'].to_dict()

    asn_data = rov_utils.load_all_asn_data()
    records: dict[int, list[int]] = {}
    for asn, data in asn_data.items():
        if not is_regular_network(asn):
            continue
        upstreams = [int(u) for u in data.get('upstreams', [])]
        if upstreams:
            records[asn] = upstreams
    print(f"    - Modeled: {len(records):,} 'Regular' Networks")

    # ---------------------------------------------------------
    # 1. COMPLEXITY DISTRIBUTION
    # ---------------------------------------------------------
    print_header("1. ASPA READINESS (Simplicity vs Complexity)")

    total = len(records)
    complexity = Counter(len(ups) for ups in records.values())
    c_simple = complexity[1] + complexity[2]
    c_mod = sum(c for k, c in complexity.items() if 2 < k <= 5)
    c_complex = sum(c for k, c in complexity.items() if k > 5)

    print(f"Total Networks: {total:,}")
    print("-" * 60)
    print(f"  - Trivial (1-2 Providers):   {c_simple:>6,} ({c_simple/total*100:>4.1f}%)")
    print(f"  - Moderate (3-5 Providers):  {c_mod:>6,} ({c_mod/total*100:>4.1f}%)")
    print(f"  - Complex (>5 Providers):    {c_complex:>6,} ({c_complex/total*100:>4.1f}%) -> \033[93mTarget for Engineering Support\033[0m")

    # ---------------------------------------------------------
    # 2. REALISTIC ENFORCERS — ranked by ROV-weighted leverage, not raw link count.
    # A provider only actually protects a customer's ASPA record if the provider
    # itself does ROV; ranking by raw customer count overstates providers who
    # have lots of customers but currently leak invalids themselves.
    # ---------------------------------------------------------
    print_header("2. THE REALISTIC ENFORCERS (Ranked by ROV-Weighted Leverage)")
    print("Raw = customer-links held. Realistic = raw, weighted by the provider's own ROV status.")
    print("-" * 95)
    print(f"{'Rank':<5} | {'ASN':<8} | {'Raw':<6} | {'Realistic':<9} | {'ROV?':<5} | {'Name'}")
    print("-" * 95)

    raw_leverage: Counter = Counter()
    for ups in records.values():
        for p in ups:
            raw_leverage[p] += 1

    realistic_leverage = {
        p: count * get_prob(str(verdict_map.get(p, "")))
        for p, count in raw_leverage.items()
    }

    total_links = sum(raw_leverage.values())
    realistic_total = sum(realistic_leverage.values())

    ranked = sorted(realistic_leverage.items(), key=lambda kv: kv[1], reverse=True)
    for rank, (asn, score) in enumerate(ranked[:30], start=1):
        rov_flag = "YES" if rov_utils.is_secure(str(verdict_map.get(asn, ""))) else "no"
        print(f"#{rank:<4} | AS{asn:<6} | {raw_leverage[asn]:<6,} | {score:<9.1f} | {rov_flag:<5} | {name_map.get(asn, 'Unknown')[:45]}")

    print("-" * 95)
    print(f"Total links: {total_links:,}  |  Realistic protected leverage: {realistic_total:,.0f} "
          f"({realistic_total/total_links*100:.1f}% of theoretical max)")

    # ---------------------------------------------------------
    # 3. COMPLEXITY GIANTS (Traffic Engineering Heavyweights)
    # ---------------------------------------------------------
    print_header("3. COMPLEXITY GIANTS (Traffic Engineering Heavyweights)")
    print("Networks with >5 Upstreams (Highest Maintenance Burden).")
    print("-" * 90)
    print(f"{'ASN':<8} | {'Providers':<10} | {'Cone':<8} | {'Name'}")
    print("-" * 90)

    complex_list = [
        {'asn': asn, 'count': len(ups), 'cone': cone_map.get(asn, 0), 'name': name_map.get(asn, "Unknown")}
        for asn, ups in records.items() if len(ups) > 5
    ]
    complex_list.sort(key=lambda x: (x['count'], x['cone']), reverse=True)

    for item in complex_list[:50]:
        print(f"AS{item['asn']:<6} | {item['count']:<10} | {item['cone']:<8} | {item['name'][:50]}")

    if complex_list:
        out_df = pd.DataFrame(complex_list)
        filename = "aspa_complexity_list.csv"
        out_df.to_csv(filename, index=False)
        print(f"\n[+] Full list of {len(complex_list)} complex networks saved to '{filename}'")


if __name__ == "__main__":
    analyze()
