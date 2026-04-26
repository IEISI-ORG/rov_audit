import pandas as pd
import rov_utils

def analyze():
    rov_utils.ensure_dirs()
    
    # 1. Load Data
    meta, countries = rov_utils.load_metadata()
    rov_utils.sync_apnic_data(countries)
    rov_set, cf_set, apnic_map = rov_utils.load_security_status()
    atlas_secure, atlas_vulnerable, atlas_raw, atlas_stale = rov_utils.load_atlas_verdicts()
    ts_map = rov_utils.sync_apnic_timeseries(apnic_map, meta)
    
    # 2. Topology
    cones, downstream, upstreams = rov_utils.load_topology()
    if not cones or not upstreams:
        print("[!] Warning: Topology files missing. Run 'do_data_gathering' and 'build_topology_from_go.py' first.")

    print("[4] Generating Global Audit...")
    results = []
    
    # All active/known ASNs
    all_asns = set(meta.keys()) | set(cones.keys()) | set(upstreams.keys())
    
    # Identify "Safe" ASNs (Passive)
    safe_asns = set()
    for asn in all_asns:
        if (asn in rov_set) or (asn in cf_set) or (apnic_map.get(asn, -1) >= 95.0):
            safe_asns.add(asn)

    # Active Overrides (Atlas & Volatility)
    # Atlas VULNERABLE can only downgrade networks with weak current evidence.
    # If a network is confirmed by both bgp.tools ROV tag AND APNIC score >= 60%,
    # the Atlas result is likely a probe-path artefact (probe routed via a
    # different provider that doesn't do ROV) rather than evidence that the
    # target ASN itself doesn't filter.  APNIC carefully selects single-provider
    # probes; our forensic test does not.
    strong_current_rov = {
        asn for asn in atlas_vulnerable
        if (asn in rov_set or asn in cf_set) and apnic_map.get(asn, -1) >= 60.0
    }
    safe_asns -= (atlas_vulnerable - strong_current_rov)
    safe_asns |= atlas_secure
    
    for asn, (sd, mn, mx, volatile, regression) in ts_map.items():
        if volatile and asn in safe_asns and asn not in rov_set and asn not in cf_set:
            safe_asns.discard(asn)

    for asn in all_asns:
        name = meta.get(asn, {}).get('name', 'Unknown')
        cc = meta.get(asn, {}).get('cc', 'XX')
        cone = cones.get(asn, 0)
        parents = list(upstreams.get(asn, []))
        score = apnic_map.get(asn, -1)
        is_safe = asn in safe_asns
        
        ts = ts_map.get(asn)
        apnic_stdev, apnic_min90, apnic_max90, volatile, regression = (ts[0], ts[1], ts[2], ts[3], ts[4]) if ts else (-1.0, -1.0, -1.0, False, False)

        dirty_feeds = sum(1 for p in parents if p not in safe_asns)
        total_feeds = len(parents)
        atlas_v = atlas_raw.get(asn, "")
        
        verdict = rov_utils.assign_verdict(
            asn, is_safe, cone, parents, dirty_feeds, volatile, atlas_v
        )
        
        # Highlight Regression in Verdict - simplified label as requested
        if regression:
            verdict = "REGRESSED"

        results.append({
            'asn': asn, 'name': name, 'cc': cc, 'cone': cone,
            'verdict': verdict, 'apnic_score': score,
            'dirty_feeds': dirty_feeds, 'total_feeds': total_feeds,
            'atlas_result': atlas_v or '', 
            'apnic_stdev': apnic_stdev, 'apnic_min90': apnic_min90, 'apnic_max90': apnic_max90,
            'regression': regression
        })

    df = pd.DataFrame(results)
    df.sort_values(by='cone', ascending=False).to_csv(rov_utils.FILE_AUDIT_FINAL, index=False)
    
    print("\n" + "="*80)
    print(f"AUDIT COMPLETE: {len(df):,} ASNs")
    print(f"File Saved: {rov_utils.FILE_AUDIT_FINAL}")
    print("="*80)

if __name__ == "__main__":
    analyze()
