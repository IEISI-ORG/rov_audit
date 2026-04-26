import argparse
import pandas as pd
import requests
import json
import os
import yaml
import time
import socket
from datetime import datetime, timezone  # <--- Added timezone
from ripe.atlas.cousteau import (
    ProbeRequest, AtlasSource, Ping, Traceroute, AtlasCreateRequest, AtlasResultsRequest
)

# --- CONFIGURATION ---
SECRETS_FILE = "secrets.yaml"
DIR_ATLAS = "data/atlas"
FILE_AUDIT = "rov_audit_v20_final.csv"
RIPE_STAT_URL = "https://stat.ripe.net/data/network-info/data.json?resource="

DOMAIN_VALID   = "valid.rpki.isbgpsafeyet.com"
DOMAIN_INVALID = "invalid.rpki.isbgpsafeyet.com"
CLOUDFLARE_ASN = 13335

# Load Key
if os.path.exists(SECRETS_FILE):
    with open(SECRETS_FILE, 'r') as f:
        ATLAS_API_KEY = yaml.safe_load(f).get('ripe_atlas_key')
else:
    ATLAS_API_KEY = None

# ==============================================================================
# 1. HELPERS
# ==============================================================================
def resolve_ip(domain):
    try: return socket.gethostbyname(domain)
    except: return None

def get_probes(asn, count=5):
    """Finds probes inside the target ASN."""
    try:
        filters = {"asn_v4": asn, "status": 1}
        probes = list(ProbeRequest(**filters))
        return [p["id"] for p in probes[:count]]
    except: return []

def resolve_asns(ip_list):
    """Resolves a list of IPs to ASNs using RIPEstat."""
    mapping = {}
    unique = list(set(ip for ip in ip_list if ip and not ip.startswith(('10.', '192.168.', '172.'))))
    
    print(f"    - Resolving {len(unique)} hops to ASNs...")
    for ip in unique:
        try:
            r = requests.get(f"{RIPE_STAT_URL}{ip}", timeout=3)
            if r.status_code == 200:
                data = r.json()
                asns = data.get('data', {}).get('asns', [])
                if asns: mapping[ip] = int(asns[0])
            time.sleep(0.05)
        except: pass
    return mapping

def ips_to_as_path(hops, mapping):
    """Converts IP hops list to AS Path list (deduplicated)."""
    path = []
    prev = None
    for ip in hops:
        asn = mapping.get(ip)
        if asn and asn != prev:
            path.append(asn)
            prev = asn
    return path

# ==============================================================================
# 2. EXECUTION ENGINE
# ==============================================================================
def run_forensic_test(asn, probes, ip_v, ip_i):
    print(f"    - Launching 4-Way Test (Ping V/I, Trace V/I) on {len(probes)} probes...")
    
    source = AtlasSource(type="probes", value=",".join(map(str, probes)), requested=len(probes))
    
    # Define measurements
    defs = [
        Ping(af=4, target=ip_v, description=f"RPKI Valid Ping - AS{asn}", is_oneoff=True, packets=3),
        Ping(af=4, target=ip_i, description=f"RPKI Invalid Ping - AS{asn}", is_oneoff=True, packets=3),
        Traceroute(af=4, target=ip_v, description=f"RPKI Valid Trace - AS{asn}", is_oneoff=True, protocol="ICMP"),
        Traceroute(af=4, target=ip_i, description=f"RPKI Invalid Trace - AS{asn}", is_oneoff=True, protocol="ICMP")
    ]
    
    # --- FIX: Use timezone-aware datetime ---
    req = AtlasCreateRequest(
        start_time=datetime.now(timezone.utc), 
        key=ATLAS_API_KEY, 
        measurements=defs, 
        sources=[source], 
        is_oneoff=True
    )
    
    success, resp = req.create()
    if not success:
        print(f"    [!] API Error: {resp}")
        return None
        
    ids = resp["measurements"]
    print(f"    - Measurement IDs: {ids}")
    
    print("    - Waiting 60s for completion...")
    time.sleep(60)
    
    results = []
    for msm_id in ids:
        success, res = AtlasResultsRequest(msm_id=msm_id).create()
        results.append(res if success else [])
        
    return results # [PingV, PingI, TraceV, TraceI]

# ==============================================================================
# 3. ANALYSIS LOGIC
# ==============================================================================

def _find_boundary(path_v: list, path_i: list) -> tuple:
    """
    Determine where path_i stops or diverges relative to path_v.

    Returns (boundary_asn, diverge_pos, is_prefix_stop) where:
      boundary_asn  — first ASN in path_v not reached by path_i (None if paths
                      fully diverge in a way that makes boundary indeterminate)
      diverge_pos   — index in path_v where paths first differ (None if path_i
                      is a clean prefix of path_v)
      is_prefix_stop — True when path_i is a proper prefix of path_v (no fork,
                       just stopped early); False when paths fork mid-route
    """
    common = 0
    for i in range(min(len(path_v), len(path_i))):
        if path_v[i] == path_i[i]:
            common = i + 1
        else:
            break

    # Did path_i follow path_v exactly up to its last hop?
    is_prefix_stop = (len(path_i) == 0 or path_i == path_v[:len(path_i)])

    if is_prefix_stop:
        boundary_asn = path_v[len(path_i)] if len(path_i) < len(path_v) else None
        diverge_pos  = None
    else:
        # Paths forked: the fork point is at index `common`
        boundary_asn = None          # can't reliably identify a single boundary
        diverge_pos  = common        # index where path_v[common] != path_i[common]

    return boundary_asn, diverge_pos, is_prefix_stop


def _classify_probe(asn: int, p_id: int,
                    path_v: list, path_i: list,
                    score_v: float, score_i: float) -> dict:
    """
    Full per-probe analysis.  Returns a dict with:

      verdict — one of:
        INCONCLUSIVE (Probe Down)       valid target unreachable; probe unusable
        INCONCLUSIVE (Off-Path)         valid path never traverses target; result
                                        tells us nothing about the target's ROV
        INCONCLUSIVE (Partial)          ping score between 10-90 %; inconsistent
        VULNERABLE                      target in path_i and invalid reachable;
                                        target confirmed NOT doing ROV on this path
        VULNERABLE (Bypass Route)       invalid reachable but via a path that avoided
                                        the target; target's ROV status ambiguous
                                        but the network as a whole leaks
        SECURE (Target Filtered)        target is the drop boundary; target
                                        confirmed doing ROV
        SECURE (Upstream Filtered)      target forwarded the invalid prefix;
                                        an upstream of target dropped it.
                                        NOTE: target itself is NOT doing ROV here
        SECURE (Pre-Target Filtered)    invalid stopped before reaching target;
                                        target's ROV status unknown from this probe

      boundary_asn   — ASN that dropped the invalid prefix (if determinable)
      boundary_type  — 'target' | 'upstream_of_target' | 'pre_target' | None
      non_rov_hops   — every ASN in path_i; each one forwarded the invalid prefix
                       and is therefore confirmed NOT doing ROV at that hop
      path_v, path_i — AS-level paths as lists
    """
    out = {
        'probe_id':     p_id,
        'verdict':      'INCONCLUSIVE',
        'boundary_asn': None,
        'boundary_type': None,
        'non_rov_hops': list(path_i),   # all hops that forwarded the invalid prefix
        'path_v':       path_v,
        'path_i':       path_i,
    }

    # ── Gate 1: probe must reach the valid destination ────────────────────────
    if score_v < 50.0:
        out['verdict'] = 'INCONCLUSIVE (Probe Down)'
        return out

    # ── Gate 2: valid path must traverse the target ───────────────────────────
    if not path_v or asn not in path_v:
        out['verdict'] = 'INCONCLUSIVE (Off-Path)'
        return out

    target_pos_v = path_v.index(asn)

    # ── Gate 3: reject noisy / inconsistent pings ────────────────────────────
    if 10.0 <= score_i <= 90.0:
        out['verdict'] = 'INCONCLUSIVE (Partial)'
        return out

    boundary_asn, diverge_pos, is_prefix_stop = _find_boundary(path_v, path_i)

    # ── Branch A: invalid prefix is reachable ────────────────────────────────
    if score_i > 90.0:
        if asn in path_i:
            # Target explicitly forwarded the invalid prefix — confirmed non-ROV
            out['verdict'] = 'VULNERABLE'
        else:
            # Invalid reachable but the path avoided the target entirely.
            # Likely the probe is multi-homed: its traffic to the invalid
            # destination went via a different provider that doesn't do ROV.
            # The target may or may not be filtering; we cannot tell.
            out['verdict'] = 'VULNERABLE (Bypass Route)'
        return out

    # ── Branch B: invalid prefix is NOT reachable (score_i < 10) ────────────
    if is_prefix_stop:
        # path_i followed path_v then stopped — clean single-boundary case
        if boundary_asn == asn:
            # Target itself is the drop boundary
            out['verdict']      = 'SECURE (Target Filtered)'
            out['boundary_asn'] = asn
            out['boundary_type'] = 'target'
        elif boundary_asn is not None:
            boundary_pos = path_v.index(boundary_asn) if boundary_asn in path_v else -1
            if boundary_pos < target_pos_v:
                # Boundary is before target in path_v → something between probe
                # and target dropped it; target's ROV status unknown
                out['verdict']      = 'SECURE (Pre-Target Filtered)'
                out['boundary_asn'] = boundary_asn
                out['boundary_type'] = 'pre_target'
            else:
                # Boundary is after target → target forwarded invalid to upstream,
                # upstream dropped it.  Target is NOT doing ROV.
                out['verdict']      = 'SECURE (Upstream Filtered)'
                out['boundary_asn'] = boundary_asn
                out['boundary_type'] = 'upstream_of_target'
        else:
            # path_i reached the end of path_v with nothing left — shouldn't
            # happen when score_i < 10, but handle gracefully
            out['verdict'] = 'INCONCLUSIVE (Partial)'
    else:
        # Paths forked mid-route and invalid became unreachable on the fork.
        # We can't reliably attribute the block to a single boundary ASN
        # because we don't know what the forked path hit.
        if asn in path_i:
            # Target was on the invalid path before the fork — it forwarded
            # the invalid prefix as far as it went
            out['verdict']      = 'SECURE (Upstream Filtered)'
            out['boundary_type'] = 'upstream_of_target'
        else:
            out['verdict'] = 'INCONCLUSIVE (Divergent)'

    return out


def analyze_results(asn: int, results: list) -> dict:
    """
    Aggregate per-probe classifications into a single verdict for the target ASN.

    Verdict precedence (highest wins):
      1. VULNERABLE — any probe where target forwarded invalid prefix
      2. SECURE (Target Filtered) — target confirmed as drop boundary
      3. VULNERABLE (Bypass Route) — invalid reachable but avoided target
      4. SECURE (Upstream Filtered) — target forwarded invalid; upstream caught it
         NOTE: counted as evidence the target is NOT doing ROV
      5. INCONCLUSIVE (Divergent) — paths forked, can't conclude
      6. INCONCLUSIVE — no on-path probes succeeded
    """
    def get_probe_map(res_list):
        return {r['prb_id']: r for r in res_list if 'prb_id' in r}

    res_pv, res_pi, res_tv, res_ti = results
    map_pv = get_probe_map(res_pv)
    map_pi = get_probe_map(res_pi)
    map_tv = get_probe_map(res_tv)
    map_ti = get_probe_map(res_ti)

    def extract_path(t_res):
        hops = []
        for h in t_res.get('result', []):
            for p in h.get('result', []):
                if 'from' in p:
                    hops.append(p['from'])
                    break
        return hops

    all_probe_ids = set(map_pv) | set(map_pi)
    probe_details = []
    all_non_rov_hops: set[int] = set()

    for p_id in all_probe_ids:
        score_v = 100.0 if map_pv.get(p_id, {}).get('avg', -1) > 0 else 0.0
        score_i = 100.0 if map_pi.get(p_id, {}).get('avg', -1) > 0 else 0.0

        hops_v = extract_path(map_tv.get(p_id, {}))
        hops_i = extract_path(map_ti.get(p_id, {}))
        all_ips = list(set(hops_v + hops_i))
        ip_map  = resolve_asns(all_ips)
        path_v  = ips_to_as_path(hops_v, ip_map)
        path_i  = ips_to_as_path(hops_i, ip_map)

        detail = _classify_probe(asn, p_id, path_v, path_i, score_v, score_i)
        probe_details.append(detail)
        all_non_rov_hops.update(detail['non_rov_hops'])

    # ── Tally per-verdict counts ──────────────────────────────────────────────
    counts = {}
    for d in probe_details:
        counts[d['verdict']] = counts.get(d['verdict'], 0) + 1

    n_vulnerable         = counts.get('VULNERABLE', 0)
    n_secure_local       = counts.get('SECURE (Target Filtered)', 0)
    n_bypass             = counts.get('VULNERABLE (Bypass Route)', 0)
    n_upstream_filtered  = counts.get('SECURE (Upstream Filtered)', 0)

    # ── Aggregate verdict ─────────────────────────────────────────────────────
    # VULNERABLE (Upstream Filtered): target forwarded invalid → counts as
    # evidence of non-ROV, same as VULNERABLE from an enforcement standpoint
    confirmed_non_rov = n_vulnerable + n_upstream_filtered

    if confirmed_non_rov > 0:
        final_verdict = 'VULNERABLE'
        # Distinguish partial-deployment: secure probes exist alongside vulnerable
        if n_secure_local > 0:
            final_verdict = 'VULNERABLE (Partial Deployment)'
    elif n_secure_local > 0:
        final_verdict = 'SECURE (Verified Active)'
    elif n_bypass > 0:
        final_verdict = 'INCONCLUSIVE (Divergent)'
    else:
        final_verdict = 'INCONCLUSIVE'

    # ── Build notes ───────────────────────────────────────────────────────────
    on_path = [d for d in probe_details if 'Off-Path' not in d['verdict']
               and 'Down' not in d['verdict']]

    if 'VULNERABLE' in final_verdict:
        # List the non-ROV hops on the invalid path as evidence
        non_rov_evidence = sorted(all_non_rov_hops - {asn})
        final_notes = (f"Invalid prefix reachable; "
                       f"{n_vulnerable} probe(s) confirm target non-ROV. "
                       f"Non-ROV hops on invalid path: {non_rov_evidence}")
    elif 'SECURE' in final_verdict:
        boundaries = [d['boundary_asn'] for d in on_path
                      if d.get('boundary_type') == 'target' and d['boundary_asn']]
        final_notes = (f"Target is drop boundary in {n_secure_local} probe(s). "
                       f"Boundary ASNs: {boundaries}")
    elif 'Divergent' in final_verdict:
        final_notes = (f"Invalid prefix reachable via bypass in {n_bypass} probe(s); "
                       f"target's ROV ambiguous — probe is multi-homed")
    else:
        inconclusive_reasons = sorted(set(
            d['verdict'] for d in probe_details if 'INCONCLUSIVE' in d['verdict']
        ))
        final_notes = f"No on-path conclusive probes. Reasons: {inconclusive_reasons}"

    # Pick representative on-path probe for the top-level boundary fields
    rep_secure = next((d for d in on_path if 'SECURE (Target' in d['verdict']), None)
    rep_any    = on_path[0] if on_path else (probe_details[0] if probe_details else {})

    return {
        'asn':             asn,
        'verdict':         final_verdict,
        'notes':           final_notes,
        'n_vulnerable':    n_vulnerable,
        'n_secure_local':  n_secure_local,
        'n_bypass':        n_bypass,
        'n_upstream_filtered': n_upstream_filtered,
        'verdict_counts':  counts,
        'non_rov_hops':    sorted(all_non_rov_hops),
        'filter_boundary': (rep_secure or rep_any).get('boundary_asn'),
        'successful_probes': len(on_path),
        'total_probes':    len(all_probe_ids),
        'probe_details':   probe_details,
        'timestamp':       datetime.now(timezone.utc).isoformat(),
    }

# ==============================================================================
# 4. MAIN
# ==============================================================================
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=10, help="Max ASNs to test")
    parser.add_argument("--target", type=int, help="Test specific ASN")
    args = parser.parse_args()

    if not ATLAS_API_KEY:
        print("[!] Missing API Key"); return

    targets = []
    
    # 1. Select Targets
    if args.target:
        targets.append(args.target)
    else:
        print("[*] Loading Audit CSV to find Unverified Targets...")
        if not os.path.exists(FILE_AUDIT):
            print("[!] CSV not found."); return
        
        df = pd.read_csv(FILE_AUDIT)
        # Filter: Unverified AND Cone > 0
        candidates = df[
            (df['verdict'].str.contains("Unverified")) & 
            (df['cone'] > 0)
        ].sort_values(by='cone', ascending=False)
        
        for asn in candidates['asn']:
            if not os.path.exists(os.path.join(DIR_ATLAS, f"as_{asn}.json")):
                targets.append(int(asn))
            if len(targets) >= args.limit: break
            
    print(f"[*] Selected {len(targets)} targets for Forensic Analysis.")
    
    ip_v = resolve_ip(DOMAIN_VALID)
    ip_i = resolve_ip(DOMAIN_INVALID)
    if not ip_v: print("[-] DNS Fail"); return

    results_summary = []
    
    for asn in targets:
        print(f"\n--- Analyzing AS{asn} ---")
        probes = get_probes(asn)
        if not probes:
            print("    [-] No probes found.")
            continue
            
        raw_results = run_forensic_test(asn, probes, ip_v, ip_i)
        if not raw_results: continue
        
        data = analyze_results(asn, raw_results)
        
        color = "\033[0m"
        if "SECURE" in data['verdict']: color = "\033[92m"
        elif "VULNERABLE" in data['verdict']: color = "\033[91m"
        elif "Divergent" in data['verdict']: color = "\033[93m"
        
        print(f"    Verdict: {color}{data['verdict']}\033[0m")
        print(f"    Notes:   {data['notes']}")
        on_path = [p for p in data.get('probe_details', [])
                   if "Off-Path" not in p['verdict'] and "Down" not in p['verdict']]
        if on_path:
            print(f"    Path V:  {on_path[0]['path_v']}")
        
        with open(os.path.join(DIR_ATLAS, f"as_{asn}.json"), 'w') as f:
            json.dump(data, f, indent=2)
            
        results_summary.append(data)

    if results_summary:
        df = pd.DataFrame(results_summary)
        df.to_csv("forensic_results_batch.csv", index=False)
        print("\n[+] Batch results saved to forensic_results_batch.csv")

if __name__ == "__main__":
    main()
