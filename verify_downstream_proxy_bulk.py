import argparse
import requests
import json
import os
import yaml
import time
import socket
from datetime import datetime, timezone
from ripe.atlas.cousteau import (
    ProbeRequest, AtlasSource, Traceroute, AtlasCreateRequest, AtlasResultsRequest
)

# --- CONFIGURATION ---
SECRETS_FILE = "secrets.yaml"
DIR_ATLAS = "data/atlas"
FILE_GRAPH = "data/downstream_graph.json"
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
# 1. TOPOLOGY & PROBE HUNTER
# ==============================================================================
def get_customers(target_asn):
    """Returns a list of direct downstream ASNs from the graph."""
    if not os.path.exists(FILE_GRAPH):
        print("[!] Error: downstream_graph.json not found. Run build_topology first.")
        return []
    
    with open(FILE_GRAPH, 'r') as f:
        graph = json.load(f)
    
    # Graph keys are strings
    return [int(x) for x in graph.get(str(target_asn), [])]

def find_candidate_probes(customer_asns, limit=5):
    """
    Checks RIPE Atlas for probes in the customer list.
    Returns a list of dicts: {'probe_id': 123, 'asn': 456}
    """
    print(f"[*] Hunting for probes in {len(customer_asns)} customer networks...")
    candidates = []
    
    for asn in customer_asns:
        try:
            # We want stable, connected, v4 probes
            filters = {"asn_v4": asn, "status": 1, "is_public": True}
            probes = list(ProbeRequest(**filters))
            
            if probes:
                # Just take the first one found per AS to spread coverage
                p = probes[0]
                candidates.append({'id': p['id'], 'asn': asn})
                print(f"    - Found probe {p['id']} in customer AS{asn}")
                
            if len(candidates) >= limit: break
        except: pass
        
    return candidates

# ==============================================================================
# 2. RESOLVERS
# ==============================================================================
def resolve_ip(domain):
    try: return socket.gethostbyname(domain)
    except: return None

def resolve_path_asns(ip_list):
    """Resolves list of IPs to ASNs using RIPEstat."""
    mapping = {}
    unique = list(set(ip for ip in ip_list if ip and not ip.startswith(('10.', '192.', '172.'))))
    
    for ip in unique:
        try:
            r = requests.get(f"{RIPE_STAT_URL}{ip}", timeout=2)
            if r.status_code == 200:
                data = r.json()
                asns = data.get('data', {}).get('asns', [])
                if asns: mapping[ip] = int(asns[0])
            time.sleep(0.05)
        except: pass
    return mapping

# ==============================================================================
# 3. EXECUTION
# ==============================================================================
def run_traces(probe_list, ip_v, ip_i, target_asn):
    # Flatten probe IDs
    p_ids = [str(c['id']) for c in probe_list]
    print(f"[*] Launching Traceroutes on {len(p_ids)} probes...")
    
    source = AtlasSource(type="probes", value=",".join(p_ids), requested=len(p_ids))
    
    defs = [
        Traceroute(af=4, target=ip_v, description=f"RPKI Valid - Audit AS{target_asn}", is_oneoff=True, protocol="ICMP"),
        Traceroute(af=4, target=ip_i, description=f"RPKI Invalid - Audit AS{target_asn}", is_oneoff=True, protocol="ICMP")
    ]
    
    req = AtlasCreateRequest(
        start_time=datetime.now(timezone.utc), 
        key=ATLAS_API_KEY, 
        measurements=defs, 
        sources=[source], 
        is_oneoff=True
    )
    
    success, resp = req.create()
    if not success:
        print(f"[!] API Error: {resp}")
        return None, None
        
    return resp["measurements"][0], resp["measurements"][1]

# ==============================================================================
# 4. ANALYSIS
# ==============================================================================
def extract_hops(result_item):
    """Extracts linear IP list from a single probe result."""
    hops = []
    if 'result' in result_item:
        for h in result_item['result']:
            for p in h.get('result', []):
                if 'from' in p:
                    hops.append(p['from'])
                    break
    return hops

def audit_target(target_asn, max_candidates=5):
    if not ATLAS_API_KEY: print("[!] Missing API Key"); return

    # 1. Setup
    customers = get_customers(target_asn)
    if not customers:
        print(f"[-] AS{target_asn} has no known downstream customers in our graph.")
        return

    candidates = find_candidate_probes(customers, limit=max_candidates)
    if not candidates:
        print(f"[-] No active probes found in any of the {len(customers)} customers.")
        return

    ip_v = resolve_ip(DOMAIN_VALID)
    ip_i = resolve_ip(DOMAIN_INVALID)
    if not ip_v: print("[-] DNS Failure"); return

    # 2. Run
    id_v, id_i = run_traces(candidates, ip_v, ip_i, target_asn)
    if not id_v: return

    print("    - Waiting 60s for traces to complete...")
    time.sleep(60)

    # 3. Fetch
    res_v = AtlasResultsRequest(msm_id=id_v).create()[1]
    res_i = AtlasResultsRequest(msm_id=id_i).create()[1]

    # 4. Analyze per Probe
    print("\n" + "="*80)
    print(f"FORENSIC ANALYSIS OF AS{target_asn}")
    print("="*80)

    valid_tests = 0
    secure_paths = 0
    leaking_paths = 0
    
    # We map probe_id back to customer ASN
    probe_map = {c['id']: c['asn'] for c in candidates}

    # Gather all IPs for bulk resolution
    all_ips = []
    for r in res_v + res_i: all_ips.extend(extract_hops(r))
    ip_to_asn = resolve_path_asns(all_ips)

    for i in range(len(res_v)):
        # Match results (assuming order matches, but safer to match prb_id)
        # RIPE results list order isn't guaranteed, need to match IDs manually in production
        # For this script, we iterate available results
        if i >= len(res_i): break
        
        rv = res_v[i]
        ri = res_i[i]
        prb_id = rv['prb_id']
        cust_asn = probe_map.get(prb_id, "Unknown")

        # Convert to AS Path
        path_v_as = []
        for ip in extract_hops(rv):
            a = ip_to_asn.get(ip)
            if a and (not path_v_as or path_v_as[-1] != a): path_v_as.append(a)

        path_i_as = []
        for ip in extract_hops(ri):
            a = ip_to_asn.get(ip)
            if a and (not path_i_as or path_i_as[-1] != a): path_i_as.append(a)

        # CHECK 1: Did Valid path go through Target?
        if target_asn not in path_v_as:
            print(f"  [SKIP] Probe {prb_id} (AS{cust_asn}): Traffic BYPASSED Target (Path: {path_v_as})")
            continue

        valid_tests += 1
        
        # CHECK 2: Did Invalid path reach Cloudflare?
        reached_cf = CLOUDFLARE_ASN in path_i_as
        
        # CHECK 3: Did Invalid path traverse Target?
        traversed_target = target_asn in path_i_as

        status = "INCONCLUSIVE"
        if reached_cf:
            if traversed_target:
                status = "\033[91mVULNERABLE (Leaked)\033[0m"
                leaking_paths += 1
            else:
                status = "BYPASSED (Invalid went diff path)"
        else:
            # Stopped. Did it stop at Target?
            if path_i_as and path_i_as[-1] == target_asn:
                status = "\033[92mSECURE (Blocked at Target)\033[0m"
                secure_paths += 1
            elif traversed_target:
                status = "\033[92mSECURE (Blocked Upstream of Target)\033[0m"
                secure_paths += 1
            else:
                # Stopped before target?
                status = "SECURE (Blocked by Customer?)"
                secure_paths += 1

        print(f"  [TEST] Probe {prb_id} (AS{cust_asn}): {status}")
        print(f"         Valid Path:   {path_v_as}")
        print(f"         Invalid Path: {path_i_as}")
        print("-" * 40)

    # 5. Final Verdict & Save
    final_verdict = "INCONCLUSIVE"
    if valid_tests == 0:
        final_verdict = "INCONCLUSIVE (No valid paths through target)"
    elif leaking_paths > 0:
        final_verdict = "VULNERABLE (Verified Leaking)"
    elif secure_paths > 0:
        final_verdict = "SECURE (Verified Active)"

    print(f"\n[*] FINAL VERDICT FOR AS{target_asn}: {final_verdict}")

    # Save to JSON for the Audit Script
    output = {
        "asn": target_asn,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "verdict": final_verdict,
        "method": "downstream_proxy_trace",
        "valid_tests_count": valid_tests,
        "leaking_paths": leaking_paths,
        "secure_paths": secure_paths
    }
    
    with open(os.path.join(DIR_ATLAS, f"as_{target_asn}.json"), 'w') as f:
        json.dump(output, f, indent=2)
    print(f"[+] Saved result to data/atlas/as_{target_asn}.json")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test an Upstream ASN by using its Customers as probes.")
    parser.add_argument("asn", type=int, help="The Transit ASN to Audit")
    parser.add_argument("--limit", type=int, default=5, help="Max number of customer probes to try")
    args = parser.parse_args()
    
    audit_target(args.asn, args.limit)
