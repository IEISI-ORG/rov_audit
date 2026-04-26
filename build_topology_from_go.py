import json
import os
import csv
import glob
from collections import defaultdict
import rov_utils

# Single source of truth — defined in rov_utils.py
TIER_1_FIREWALL        = rov_utils.TIER_1_ASNS
IS_NON_TRANSIT         = rov_utils.NON_TRANSIT_ASNS
RATIO                  = rov_utils.PROVIDER_RATIO
SINGLE_REGION_RATIO    = rov_utils.RRC_SINGLE_REGION_RATIO
CONFIRM_REGIONS        = rov_utils.RRC_CONFIRM_REGIONS
IXP_PRUNE_THRESHOLD    = rov_utils.CONE_QUALITY_THRESHOLD  # 5.0 %


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_scraped_metadata() -> dict:
    print("    - Loading ASN data from packed file...")
    data = rov_utils.load_all_asn_data()
    return {
        asn: {'name': d.get('name', 'Unknown'), 'cc': d.get('cc', 'XX'), 'cone': d.get('cone_size', 0)}
        for asn, d in data.items()
    }


def _find_collector_files() -> list[tuple[str, str]]:
    """
    Return [(rrc_name, filepath)] for every relationships.csv found under
    output/rrcNN/.  Falls back to the legacy single-file path if no
    per-collector directories exist.
    """
    files = []
    for rrc_name in rov_utils.RRC_COLLECTORS:
        path = os.path.join(rov_utils.DIR_RRC, rrc_name, "relationships.csv")
        if os.path.exists(path):
            files.append((rrc_name, path))

    if not files:
        legacy = rov_utils.FILE_RELATIONSHIPS
        if os.path.exists(legacy):
            print(f"    [!] No per-collector directories found; falling back to {legacy}")
            files.append(("rrc00", legacy))
        else:
            print(f"    [!] No relationship files found. Run bgp-extractor first.")
    return files


def load_multi_collector_relationships() -> tuple[dict, dict, dict]:
    """
    Load adjacency data from all available RRC collectors.

    Returns
    -------
    adj : {asn: set(neighbour_asns)}   — combined undirected adjacency (union)
    degrees : {asn: int}               — degree in the combined graph
    link_regions : {(min_asn, max_asn): set(region_str)}
        Set of geographic regions that independently observed this link.
        A link confirmed by both EU and APAC collectors is strong transit evidence;
        a link seen only from a single EU collector is suspect IXP peering.

    Multi-collector rationale
    -------------------------
    rrc00 at Amsterdam and rrc23 at Singapore are at completely different IXPs.
    A route-server adjacency fabricated at AMS-IX will NOT appear in Singapore
    BGP dumps.  A *real* transit link (e.g. Cogent → small stub) propagates
    globally and shows up in ALL collectors.

    The IXP route-server problem (RFC 7947 path stripping) cannot be detected
    by valley-free analysis alone because stripped paths look identical to
    transit paths.  Cross-regional confirmation is the primary defence;
    the excl_pct pruning pass below is the secondary backstop.
    """
    collector_files = _find_collector_files()
    if not collector_files:
        return None, None, None

    adj = defaultdict(set)
    link_regions: dict[tuple, set] = defaultdict(set)

    rrc_meta = rov_utils.RRC_COLLECTORS

    for rrc_name, filepath in collector_files:
        region = rrc_meta.get(rrc_name, {}).get("region", rrc_name)
        location = rrc_meta.get(rrc_name, {}).get("location", rrc_name)
        count = 0
        with open(filepath) as f:
            reader = csv.reader(f)
            next(reader, None)
            for row in reader:
                if len(row) < 3:
                    continue
                as1, as2 = int(row[0]), int(row[1])
                adj[as1].add(as2)
                adj[as2].add(as1)
                link_regions[tuple(sorted((as1, as2)))].add(region)
                count += 1
        print(f"      {rrc_name} ({location}): {count:,} relationship rows")

    degrees = {asn: len(nbrs) for asn, nbrs in adj.items()}
    n_confirmed = sum(1 for regions in link_regions.values() if len(regions) >= CONFIRM_REGIONS)
    print(f"    - Combined: {len(degrees):,} ASNs, {len(link_regions):,} unique links")
    print(f"      Cross-regional confirmed (≥{CONFIRM_REGIONS} regions): {n_confirmed:,} links")
    return adj, degrees, link_regions


# ---------------------------------------------------------------------------
# IXP phantom pruning
# ---------------------------------------------------------------------------

def _build_providers_of(downstream_map: dict) -> dict:
    providers_of = defaultdict(set)
    for provider, customers in downstream_map.items():
        for c in customers:
            providers_of[c].add(provider)
    return providers_of


def _prune_ixp_phantoms(downstream_map: dict, tier1_set: set) -> tuple[int, int]:
    """
    Secondary defence: remove non-T1 providers whose captive-customer fraction
    is below IXP_PRUNE_THRESHOLD.

    This catches any phantoms that slipped through the multi-collector check —
    for example, links that appear in two European collectors but are still
    local to European IXPs.

    See the docstring in build_topology() for the full explanation of why
    the valley-free algorithm cannot detect IXP phantoms.
    """
    providers_of = _build_providers_of(downstream_map)
    excl_map: dict[int, float] = {}
    for provider, customers in downstream_map.items():
        if provider in tier1_set or not customers:
            continue
        total = len(customers)
        captive = sum(1 for c in customers if len(providers_of.get(c, set())) <= 2)
        excl_map[provider] = captive / total * 100.0

    phantoms = {p for p, pct in excl_map.items() if pct < IXP_PRUNE_THRESHOLD}
    removed_links = removed_providers = 0
    for provider in phantoms:
        n = len(downstream_map.get(provider, []))
        if n:
            downstream_map[provider] = []
            removed_links += n
            removed_providers += 1
    return removed_providers, removed_links


# ---------------------------------------------------------------------------
# Main topology builder
# ---------------------------------------------------------------------------

def build_topology():
    """
    Build the provider→customer directed graph from RIPE RIS BGP dumps.

    Uses data from multiple geographically diverse RRC collectors so that
    IXP route-server adjacencies (which are local to one IXP fabric) can be
    distinguished from genuine transit relationships (which appear globally).

    Rule priority (identical to cone-calculator.go):
      1. Non-transit exclusion  (RIRs, root servers, IXP route servers)
      2. Tier-1 affirmative override
      3. Cross-regional degree-ratio:
           ≥ CONFIRM_REGIONS regions see the link → use RATIO (4×)
           < CONFIRM_REGIONS regions            → use SINGLE_REGION_RATIO (8×)
      4. IXP phantom pruning  (excl_pct backstop)
    """
    print("[*] Building Topology from RIPE RIS (Multi-Collector)...")

    meta_map = load_scraped_metadata()
    print(f"    - Loading collector data...")
    adj, degrees, link_regions = load_multi_collector_relationships()
    if not adj:
        return

    # Build directed graph
    downstream_map = defaultdict(list)
    stats = {'total': 0, 'kept': 0, 'dropped_peer': 0, 'dropped_t1': 0,
             'dropped_single_region': 0}
    processed = set()

    for as1, neighbors in adj.items():
        for as2 in neighbors:
            pair_key = tuple(sorted((as1, as2)))
            if pair_key in processed:
                continue
            processed.add(pair_key)
            stats['total'] += 1

            d1, d2 = degrees[as1], degrees[as2]
            provider = customer = None

            # Rule 1: Non-transit exclusion
            if as1 in IS_NON_TRANSIT or as2 in IS_NON_TRANSIT:
                stats['dropped_peer'] += 1
                continue

            # Rule 2: Tier-1 affirmative override (always provider of non-T1)
            t1_as1 = as1 in TIER_1_FIREWALL
            t1_as2 = as2 in TIER_1_FIREWALL
            if t1_as1 and t1_as2:
                stats['dropped_t1'] += 1
                continue
            elif t1_as1:
                provider, customer = as1, as2
            elif t1_as2:
                provider, customer = as2, as1

            else:
                # Rule 3: Cross-regional degree-ratio
                n_regions = len(link_regions.get(pair_key, set()))
                ratio = RATIO if n_regions >= CONFIRM_REGIONS else SINGLE_REGION_RATIO

                if d1 > d2 * ratio:
                    provider, customer = as1, as2
                elif d2 > d1 * ratio:
                    provider, customer = as2, as1
                else:
                    if n_regions < CONFIRM_REGIONS and (d1 > d2 * RATIO or d2 > d1 * RATIO):
                        stats['dropped_single_region'] += 1
                    else:
                        stats['dropped_peer'] += 1
                    continue

            downstream_map[provider].append(customer)
            stats['kept'] += 1

    print(f"    - Initial graph built.")
    print(f"      Total Unique Links:       {stats['total']:,}")
    print(f"      Kept (Transit):           {stats['kept']:,}")
    print(f"      Dropped (Peering):        {stats['dropped_peer']:,}")
    print(f"      Dropped (T1 Loops):       {stats['dropped_t1']:,}")
    print(f"      Dropped (Single-Region):  {stats['dropped_single_region']:,}  ← IXP suspects")

    # Rule 4: IXP phantom pruning backstop
    print(f"    - Pruning IXP phantom providers (excl% < {IXP_PRUNE_THRESHOLD:.0f}%)...")
    n_prov, n_links = _prune_ixp_phantoms(downstream_map, TIER_1_FIREWALL)
    print(f"      Removed {n_prov} phantom providers, {n_links:,} phantom links.")

    # Save
    with open(os.path.join(rov_utils.DIR_DATA, "downstream_graph.json"), 'w') as f:
        json.dump(downstream_map, f)

    new_asns = 0
    for asn in degrees:
        if asn not in meta_map:
            meta_map[asn] = {'name': 'Unknown (RIS)', 'cc': 'XX', 'cone': 0}
            new_asns += 1
    with open(os.path.join(rov_utils.DIR_DATA, "asn_meta.json"), 'w') as f:
        json.dump(meta_map, f)

    print(f"    - Added {new_asns} unscraped ASNs to metadata.")
    print("[+] Topology saved to 'data/downstream_graph.json'")


if __name__ == "__main__":
    build_topology()
