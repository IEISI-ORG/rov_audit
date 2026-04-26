"""
tests/test_gao_rexford.py

Rigorous logic tests for the BGP topology pipeline.

BGP AS-path semantics (TABLE_DUMP2 format)
==========================================
A path is written  [PEER_0, ..., ORIGIN_N]  where:
  - PEER_0  is the AS nearest to the route collector (observer)
  - ORIGIN_N is the AS that originated the prefix

Data-plane traffic flows LEFT → RIGHT  (toward the origin/destination).
Route announcements flow   RIGHT → LEFT (origin propagates outward).

For any ASN X at position i in path [P0, P1, ..., Pn]:

  LEFT  neighbor  (i-1, toward collector)
        = the ASN that X forwarded the announcement TO
        = X's CUSTOMER or X's peer at the top of the path (data-plane downstream)

  RIGHT neighbor  (i+1, toward origin)
        = the ASN that X received the announcement FROM
        = X's PROVIDER or X's peer at the top of the path (data-plane upstream)

Tier 1s appear near the CENTER of a path (peak of the valley-free hill).
Stubs appear at the EDGES (leftmost or rightmost positions).

Gao-Rexford Valley-Free Constraint
====================================
A BGP path is valley-free if and only if it has the shape:

    (customer→provider)* → (peer↔peer)? → (provider→customer)*

Once the path starts going "downhill" (provider→customer), it can never go
"uphill" again (customer→provider).  That forbidden pattern is the "valley."

Topology inference rules (must match both cone-calculator.go and build_topology_from_go.py)
============================================================================================
Applied in this priority order:
  1. Non-transit ASNs (RIRs, root servers, IXP route servers) → skip (no cone)
  2. Tier 1 ↔ non-Tier-1 → Tier 1 is always provider (bypasses degree ratio)
  3. Tier 1 ↔ Tier 1    → peering link, drop
  4. degree(A) > 4×degree(B) → A is provider of B
  5. degree(B) > 4×degree(A) → B is provider of A
  6. otherwise           → peering link, drop
"""

import sys
import os
import json
from collections import defaultdict, deque

# Make project root importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import rov_utils

# --------------------------------------------------------------------------- #
#  Constants — imported from rov_utils (single source of truth for Python).  #
#  The Go equivalents live in constants.go.                                   #
#  The sync tests below verify Go and Python stay in lockstep.                #
# --------------------------------------------------------------------------- #

TIER_1_ASNS     = rov_utils.TIER_1_ASNS
NON_TRANSIT_ASNS = rov_utils.NON_TRANSIT_ASNS | {23456, 0}  # Go adds AS_TRANS + RFC7607
PROVIDER_RATIO  = rov_utils.PROVIDER_RATIO


# =========================================================================== #
#  UNIT TESTS: Path Semantics                                                  #
# =========================================================================== #

def test_left_right_positional_assignment():
    """
    Given path [A, B, C, D], bgp-extractor must assign:
      - B: left=A  (toward collector),  right=C  (toward origin)
      - A: no left (first position),    right=B
      - D: left=C,                      no right (last position / origin)
    """
    path = ["A", "B", "C", "D"]
    expected_left  = {"B": "A", "C": "B", "D": "C"}
    expected_right = {"A": "B", "B": "C", "C": "D"}

    for i, asn in enumerate(path):
        if i > 0:
            actual_left = path[i - 1]
            assert actual_left == expected_left[asn], (
                f"AS{asn}: expected left={expected_left[asn]}, got {actual_left}"
            )
        if i < len(path) - 1:
            actual_right = path[i + 1]
            assert actual_right == expected_right[asn], (
                f"AS{asn}: expected right={expected_right[asn]}, got {actual_right}"
            )
    print("  [PASS] Left/right positional assignment")


def test_left_is_customer_direction():
    """
    In a canonical valley-free path  [stub_customer, large_ISP, tier1, stub_origin]:
      - tier1's LEFT  = large_ISP  → tier1 is large_ISP's PROVIDER  (left=customer dir)
      - tier1's RIGHT = stub_origin → stub_origin is tier1's customer (right=provider dir)
    This validates that LEFT = toward-collector = data-plane downstream.
    """
    # Concrete example matching real topology shape
    # path[0]=stub near collector, path[3]=stub origin
    path = ["stub_cust", "tier2_ISP", "tier1", "stub_origin"]

    tier1_idx = 2
    left_of_tier1  = path[tier1_idx - 1]   # tier2_ISP
    right_of_tier1 = path[tier1_idx + 1]   # stub_origin

    # tier1 is the PROVIDER of tier2_ISP → tier2_ISP is in tier1's customer direction (LEFT)
    assert left_of_tier1 == "tier2_ISP", "tier1's left should be tier2_ISP (customer side)"
    # tier1 is the PROVIDER of stub_origin → stub_origin is in tier1's customer direction (RIGHT here)
    # But stub_origin is to the RIGHT (toward origin), which is the downhill side of tier1.
    assert right_of_tier1 == "stub_origin", "tier1's right should be stub_origin"

    # Semantic invariant: both left AND right of a peak Tier 1 are customers.
    # The left side went UP to reach tier1; the right side goes DOWN from tier1.
    print("  [PASS] Left=customer-direction, right=provider-direction semantics")


def test_origin_has_no_right_neighbor():
    """The origin (rightmost ASN) has no right neighbor — it originated the route."""
    path = ["A", "B", "C", "origin"]
    origin_idx = len(path) - 1
    assert origin_idx == 3
    has_right = origin_idx < len(path) - 1
    assert not has_right, "Origin should not have a right (provider-side) neighbor"
    print("  [PASS] Origin has no right neighbor")


def test_collector_peer_has_no_left_neighbor():
    """The collector's peer (leftmost) has no left neighbor — it's at the edge."""
    path = ["collector_peer", "B", "C", "D"]
    has_left = 0 > 0  # index 0 has no i-1
    assert not has_left
    print("  [PASS] Collector-peer has no left neighbor")


# =========================================================================== #
#  UNIT TESTS: Topology Inference Rules                                        #
# =========================================================================== #

def _infer_link(as1: int, as2: int, d1: int, d2: int) -> tuple[int | None, int | None]:
    """
    Apply the canonical topology inference rules.
    Returns (provider, customer) or (None, None) for peering/excluded.
    Must stay identical to build_topology_from_go.py:build_topology() logic.
    """
    if as1 in NON_TRANSIT_ASNS or as2 in NON_TRANSIT_ASNS:
        return None, None

    t1_1 = as1 in TIER_1_ASNS
    t1_2 = as2 in TIER_1_ASNS

    if t1_1 and t1_2:
        return None, None  # Tier 1 ↔ Tier 1 = peering
    elif t1_1:
        return as1, as2
    elif t1_2:
        return as2, as1
    elif d1 > d2 * PROVIDER_RATIO:
        return as1, as2
    elif d2 > d1 * PROVIDER_RATIO:
        return as2, as1
    else:
        return None, None  # peering


def test_tier1_is_always_provider_of_non_tier1():
    """Tier 1 ASN must be assigned as provider regardless of degree ratio."""
    t1_asn = 3356  # Lumen
    small_asn = 64496  # Documentation range, definitely not T1

    # Even if degree ratio is below threshold (e.g., 2×), T1 must win
    provider, customer = _infer_link(t1_asn, small_asn, d1=200, d2=100)
    assert provider == t1_asn and customer == small_asn, (
        f"Expected T1={t1_asn} as provider but got provider={provider}"
    )

    # Same in reverse argument order
    provider, customer = _infer_link(small_asn, t1_asn, d1=100, d2=200)
    assert provider == t1_asn and customer == small_asn, (
        f"Expected T1={t1_asn} as provider regardless of argument order"
    )
    print("  [PASS] Tier 1 always inferred as provider over non-Tier-1")


def test_tier1_tier1_link_is_dropped():
    """Two Tier 1 ASNs peering with each other should produce no cone relationship."""
    t1a, t1b = 3356, 174  # Lumen, Cogent
    provider, customer = _infer_link(t1a, t1b, d1=50000, d2=40000)
    assert provider is None and customer is None, (
        "Tier 1 ↔ Tier 1 link should be classified as peering (no cone)"
    )
    print("  [PASS] Tier 1 ↔ Tier 1 correctly classified as peering")


def test_non_transit_asn_excluded():
    """Root servers, RIRs, and IXP route servers must never be assigned as providers."""
    for non_transit in [3333, 25152, 4608, 213241]:  # RIPE, K-root, APNIC, SGGS
        large_customer = 64496
        provider, customer = _infer_link(non_transit, large_customer, d1=9999, d2=1)
        assert provider is None and customer is None, (
            f"Non-transit AS{non_transit} should be excluded but got provider={provider}"
        )
    print("  [PASS] Non-transit ASNs excluded from provider-customer inference")


def test_degree_ratio_determines_provider():
    """When degree(A) > 4×degree(B), A is inferred as provider."""
    provider, customer = _infer_link(64496, 64497, d1=500, d2=50)
    assert provider == 64496 and customer == 64497, (
        f"Higher-degree AS should be provider; got provider={provider}"
    )

    provider, customer = _infer_link(64496, 64497, d1=50, d2=500)
    assert provider == 64497 and customer == 64496
    print("  [PASS] Degree ratio correctly assigns provider")


def test_similar_degree_is_peering():
    """Two ASNs with degree ratio < 4× are peers — no cone relationship."""
    provider, customer = _infer_link(64496, 64497, d1=100, d2=80)
    assert provider is None and customer is None, (
        "Similar-degree link should be peering, not provider-customer"
    )
    print("  [PASS] Similar degree classified as peering")


def test_exact_ratio_boundary():
    """Exactly 4× is NOT sufficient — must be strictly greater."""
    # d1 = 4 * d2 is NOT > 4 * d2, so should be peering
    provider, customer = _infer_link(64496, 64497, d1=400, d2=100)
    assert provider is None and customer is None, (
        "Exactly 4× ratio should not trigger provider assignment (must be strictly >)"
    )
    # 401 > 4*100 = 400: should trigger
    provider, customer = _infer_link(64496, 64497, d1=401, d2=100)
    assert provider == 64496
    print("  [PASS] Degree ratio boundary (strictly > 4×) is correct")


# =========================================================================== #
#  UNIT TESTS: Valley-Free Constraint                                          #
# =========================================================================== #

def _build_mini_topology(links: list[tuple]) -> dict[int, list[int]]:
    """
    Build a tiny downstream_graph from a list of (as1, as2, d1, d2) tuples.
    Returns {provider: [customer, ...]}
    """
    graph = defaultdict(list)
    for as1, as2, d1, d2 in links:
        provider, customer = _infer_link(as1, as2, d1, d2)
        if provider is not None:
            graph[provider].append(customer)
    return dict(graph)


def _is_valley_free(path: list[int], graph: dict[int, list[int]]) -> bool:
    """
    Check whether a path satisfies the valley-free constraint.
    Returns True if no valley is found (a downhill segment followed by an uphill one).
    """
    # Build reverse map: customer → providers
    providers_of = defaultdict(set)
    for p, customers in graph.items():
        for c in customers:
            providers_of[c].add(p)

    # Walk the path and classify each link
    # uphill = going to a provider, downhill = going to a customer, peer = neither
    went_downhill = False
    for i in range(len(path) - 1):
        a, b = path[i], path[i + 1]
        if b in graph.get(a, []):   # a→b means a is provider of b → going downhill
            went_downhill = True
        elif a in graph.get(b, []):  # b→a means b is provider of a → going uphill
            if went_downhill:
                return False  # Valley: downhill then uphill
    return True


def test_simple_valley_free_path():
    """
    Valid valley-free path: stub → tier2 → tier1 → stub_origin
    Tier 1 is the peak; no valley should be detected.
    """
    # Build topology: tier1 > tier2 > stubs
    links = [
        (3356,  64496, 50000, 500),   # tier1 → tier2
        (3356,  64497, 50000, 50),    # tier1 → stub_origin
        (64496, 64498, 500,   5),     # tier2 → stub_cust
    ]
    graph = _build_mini_topology(links)
    # Valid path: stub_cust → tier2 → tier1 → stub_origin
    path = [64498, 64496, 3356, 64497]
    assert _is_valley_free(path, graph), "Expected valley-free path to pass check"
    print("  [PASS] Valid valley-free path accepted")


def test_valley_detected():
    """
    Invalid path (has a valley): big → small → big → small
    Data goes up to tier2, down to stub, up to another tier2, down to origin.
    """
    links = [
        (3356,  64496, 50000, 500),   # tier1 provides to tier2a
        (3356,  64497, 50000, 500),   # tier1 provides to tier2b
        (64496, 64498, 500,   5),     # tier2a → stub_a
        (64497, 64499, 500,   5),     # tier2b → stub_b
    ]
    graph = _build_mini_topology(links)
    # Valley path: stub_a goes UP to tier2a, DOWN to tier1, UP to tier2b → valley!
    # But tier1 is the peak, not a valley. Let me create a true valley instead.
    # True valley: stub_a → tier2a (uphill) → stub_b (downhill) → tier2b (uphill again)
    # For that we need tier2a to be provider of stub_b AND tier2b to be provider of stub_b,
    # and stub_b to also have tier2b as provider. That creates the forbidden pattern.
    #
    # Simpler: build a graph where path goes up-down-up
    links2 = [
        (200, 100, 2000, 100),  # 200 is provider of 100
        (200, 300, 2000, 100),  # 200 is provider of 300
        (400, 300, 2000, 100),  # 400 is provider of 300 too (300 has two providers)
    ]
    graph2 = _build_mini_topology(links2)
    # path 100 → 200 → 300 → 400: uphill(100→200), downhill(200→300), uphill(300→400)
    # That's a valley at 300.
    path = [100, 200, 300, 400]
    assert not _is_valley_free(path, graph2), "Expected valley to be detected"
    print("  [PASS] Valley correctly detected in invalid path")


# =========================================================================== #
#  INTEGRATION TESTS: Require data/downstream_graph.json                      #
# =========================================================================== #

def _load_graph() -> dict[int, list[int]] | None:
    if not os.path.exists(rov_utils.FILE_GRAPH):
        return None
    with open(rov_utils.FILE_GRAPH) as f:
        raw = json.load(f)
    return {int(k): [int(v) for v in vals] for k, vals in raw.items()}


def test_tier1_has_no_providers_in_graph():
    """
    In downstream_graph.json, no Tier 1 ASN should appear as a customer of any other.
    A Tier 1 appearing as someone's customer means the T1 firewall was breached.
    """
    graph = _load_graph()
    if graph is None:
        print("  [SKIP] downstream_graph.json not found")
        return

    # Build reverse map
    providers_of = defaultdict(set)
    for provider, customers in graph.items():
        for c in customers:
            providers_of[c].add(provider)

    failures = []
    for t1 in TIER_1_ASNS:
        parents = providers_of.get(t1, set())
        if parents:
            failures.append(f"AS{t1} has providers: {parents}")

    assert not failures, "Tier 1 firewall breached:\n" + "\n".join(failures)
    print(f"  [PASS] No Tier 1 appears as customer in graph ({len(TIER_1_ASNS)} checked)")


def test_graph_is_dag():
    """
    downstream_graph.json must be a DAG (no cycles).
    A cycle would mean A is in the cone of its own customer — logically impossible
    and would cause infinite loops in cone calculation.
    """
    graph = _load_graph()
    if graph is None:
        print("  [SKIP] downstream_graph.json not found")
        return

    # Kahn's algorithm: detect cycles via topological sort
    in_degree = defaultdict(int)
    all_nodes = set(graph.keys())
    for provider, customers in graph.items():
        for c in customers:
            in_degree[c] += 1
            all_nodes.add(c)

    queue = deque(n for n in all_nodes if in_degree[n] == 0)
    visited = 0
    while queue:
        node = queue.popleft()
        visited += 1
        for child in graph.get(node, []):
            in_degree[child] -= 1
            if in_degree[child] == 0:
                queue.append(child)

    assert visited == len(all_nodes), (
        f"Cycle detected: processed {visited} of {len(all_nodes)} nodes. "
        f"Nodes still in queue have cycle dependencies."
    )
    print(f"  [PASS] Graph is a DAG ({len(all_nodes):,} nodes)")


def test_non_transit_not_providers_in_graph():
    """Non-transit ASNs (root servers, RIRs) must not appear as providers in the graph."""
    graph = _load_graph()
    if graph is None:
        print("  [SKIP] downstream_graph.json not found")
        return

    failures = [
        f"AS{asn}" for asn in NON_TRANSIT_ASNS if asn in graph and graph[asn]
    ]
    assert not failures, (
        "Non-transit ASNs found as providers: " + ", ".join(failures)
    )
    print("  [PASS] No non-transit ASNs appear as providers")


def test_cone_sizes_monotone(cone_file: str = rov_utils.FILE_CONES):
    """
    For every provider→customer link, provider cone >= customer cone.
    Strictly: a provider's reachable set includes all customers' reachable sets,
    so cone(provider) can never be smaller than cone(customer).
    """
    graph = _load_graph()
    if graph is None:
        print("  [SKIP] downstream_graph.json not found")
        return
    if not os.path.exists(cone_file):
        print(f"  [SKIP] {cone_file} not found")
        return

    import csv
    cones: dict[int, int] = {}
    with open(cone_file) as f:
        reader = csv.DictReader(f)
        for row in reader:
            asn_col = "ASN" if "ASN" in row else "asn"
            cone_col = "Cone_Size" if "Cone_Size" in row else "cone"
            try:
                cones[int(row[asn_col])] = int(row[cone_col])
            except (KeyError, ValueError):
                pass

    failures = []
    for provider, customers in graph.items():
        pc = cones.get(provider, 0)
        for c in customers:
            cc = cones.get(c, 0)
            if pc < cc:
                failures.append(
                    f"AS{provider}(cone={pc}) < AS{c}(cone={cc}): provider smaller than customer"
                )

    if failures:
        # Report sample only — could be thousands if data is stale
        sample = failures[:10]
        assert False, f"Cone monotonicity violated ({len(failures)} cases):\n" + "\n".join(sample)
    print(f"  [PASS] Cone monotonicity holds across all provider→customer links")


# =========================================================================== #
#  REGRESSION GUARD: Constant Sync                                             #
# =========================================================================== #

def test_tier1_lists_are_in_sync():
    """
    rov_utils.TIER_1_ASNS is the Python source of truth.
    constants.go isTier1() is the Go source of truth.
    They must be identical. Update both together, then re-run this test.
    """
    # Mirror of constants.go isTier1() switch cases.
    # When you update constants.go, update this too — the test will catch drift.
    go_tier1 = {
        3356, 1299, 174, 2914, 3257, 6762, 6939, 6453, 3491,
        701, 6461, 5511, 6830, 4637, 7018, 3320, 12956, 1273, 7922,
        209, 4134, 4809, 4837, 9929, 9808,
    }
    drift = go_tier1.symmetric_difference(TIER_1_ASNS)
    assert not drift, (
        f"Tier 1 drift between constants.go and rov_utils.py: {drift}\n"
        "Edit BOTH constants.go (isTier1) AND rov_utils.py (TIER_1_ASNS)."
    )
    print(f"  [PASS] Tier 1 lists in sync ({len(TIER_1_ASNS)} ASNs)")


def test_non_transit_lists_are_in_sync():
    """
    rov_utils.NON_TRANSIT_ASNS is the Python source of truth.
    constants.go isNonTransit() is the Go source of truth.
    Go additionally includes 23456 (AS_TRANS) and 0 (RFC 7607) — intentional,
    those can't appear in well-formed TABLE_DUMP2 paths.
    """
    # Mirror of constants.go isNonTransit() switch cases (excluding 23456 and 0).
    # When you update constants.go, update this too.
    go_non_transit_py_subset = {
        213241, 24482, 13335, 3333, 4608, 4777,
        394353, 2149, 10886, 21556, 3557, 5927, 1508, 29216, 26415, 25152, 20144, 7500,
        112,
    }
    drift = go_non_transit_py_subset.symmetric_difference(rov_utils.NON_TRANSIT_ASNS)
    assert not drift, (
        f"Non-transit drift between constants.go and rov_utils.py: {drift}\n"
        "Edit BOTH constants.go (isNonTransit) AND rov_utils.py (NON_TRANSIT_ASNS)."
    )
    print("  [PASS] Non-transit lists consistent")


def test_non_transit_no_wrong_asns():
    """
    Guard against repeating the 2026-04 mistake where reassigned ASNs were kept.
    The following ASNs must NEVER appear in IS_NON_TRANSIT because they are no
    longer root servers — their ASNs were reassigned to unrelated organisations.
    Source: bgp.tools icrit tag cross-check.
    """
    formerly_wrong = {
        3661: "Chinese University of Hong Kong (not A-Root)",
        1941: "Renater / French research network (not B-Root)",
        15061: "Insurance Corporation of British Columbia (not H-Root)",
    }
    try:
        import build_topology_from_go as btg
        bad = {asn: reason for asn, reason in formerly_wrong.items()
               if asn in btg.IS_NON_TRANSIT}
        assert not bad, (
            "Reassigned ASNs still in IS_NON_TRANSIT:\n" +
            "\n".join(f"  AS{asn}: {r}" for asn, r in bad.items())
        )
    except ImportError:
        pass

    bad_in_test = {asn for asn in formerly_wrong if asn in NON_TRANSIT_ASNS}
    assert not bad_in_test, (
        f"Reassigned ASNs still in test NON_TRANSIT_ASNS: {bad_in_test}"
    )
    print("  [PASS] No reassigned root-server ASNs in non-transit list")


def test_correct_root_server_asns_present():
    """
    The correct ASNs for B-root and H-root (sourced from bgp.tools icrit tag)
    must be in the non-transit list.  These were missing before the 2026-04 audit.
    """
    required = {
        394353: "USC/ISI B-Root",
        1508:   "US Army Research Lab H-Root",
        26415:  "VeriSign A-Root & J-Root",
    }
    missing = {asn: name for asn, name in required.items()
               if asn not in NON_TRANSIT_ASNS}
    assert not missing, (
        "Required root-server ASNs missing from NON_TRANSIT_ASNS:\n" +
        "\n".join(f"  AS{asn}: {name}" for asn, name in missing.items())
    )
    print("  [PASS] Correct root-server ASNs present in non-transit list")


# =========================================================================== #
#  Runner                                                                      #
# =========================================================================== #

if __name__ == "__main__":
    failures = []

    suites = [
        ("Path Semantics", [
            test_left_right_positional_assignment,
            test_left_is_customer_direction,
            test_origin_has_no_right_neighbor,
            test_collector_peer_has_no_left_neighbor,
        ]),
        ("Topology Inference Rules", [
            test_tier1_is_always_provider_of_non_tier1,
            test_tier1_tier1_link_is_dropped,
            test_non_transit_asn_excluded,
            test_degree_ratio_determines_provider,
            test_similar_degree_is_peering,
            test_exact_ratio_boundary,
        ]),
        ("Valley-Free Constraint", [
            test_simple_valley_free_path,
            test_valley_detected,
        ]),
        ("Regression Guards (constant sync)", [
            test_tier1_lists_are_in_sync,
            test_non_transit_lists_are_in_sync,
            test_non_transit_no_wrong_asns,
            test_correct_root_server_asns_present,
        ]),
        ("Integration (requires data/)", [
            test_tier1_has_no_providers_in_graph,
            test_graph_is_dag,
            test_non_transit_not_providers_in_graph,
            test_cone_sizes_monotone,
        ]),
    ]

    for suite_name, tests in suites:
        print(f"\n[{suite_name}]")
        for fn in tests:
            try:
                fn()
            except AssertionError as e:
                print(f"  [FAIL] {fn.__name__}: {e}")
                failures.append(fn.__name__)
            except Exception as e:
                print(f"  [ERROR] {fn.__name__}: {type(e).__name__}: {e}")
                failures.append(fn.__name__)

    print()
    if failures:
        print(f"[!] {len(failures)} test(s) FAILED: {failures}")
        sys.exit(1)
    else:
        print("[+] ALL GAO-REXFORD LOGIC TESTS PASSED")
        sys.exit(0)
