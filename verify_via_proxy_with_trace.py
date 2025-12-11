import argparse
import socket
import os
import json
import yaml
import time
from datetime import datetime
from ripe.atlas.cousteau import (
    ProbeRequest, AtlasSource, Ping, Traceroute, AtlasCreateRequest, AtlasResultsRequest
)

# --- CONFIGURATION ---
SECRETS_FILE = "secrets.yaml"
DIR_ATLAS = "data/atlas"
DOMAIN_VALID   = "valid.rpki.isbgpsafeyet.com"
DOMAIN_INVALID = "invalid.rpki.isbgpsafeyet.com"

def load_api_key():
    if not os.path.exists(SECRETS_FILE): return None
    try:
        with open(SECRETS_FILE, 'r') as f: return yaml.safe_load(f).get('ripe_atlas_key')
    except: return None

ATLAS_API_KEY = load_api_key()

def resolve_target(domain):
    try: return socket.gethostbyname(domain)
    except: return None

def find_probes_by_asn(asn):
    filters = {"asn_v4": asn, "status": 1}
    try: return [p["id"] for p in ProbeRequest(**filters)]
    except: return []

def create_request(measurements, probe_ids):
    """Submits a bundle of measurements (Ping + Trace)."""
    source = AtlasSource(type="probes", value=",".join(map(str, probe_ids[:50])), requested=len(probe_ids[:50]))
    request = AtlasCreateRequest(
        start_time=datetime.utcnow(), 
        key=ATLAS_API_KEY, 
        measurements=measurements, 
        sources=[source], 
        is_oneoff=True
    )
    (is_success, response) = request.create()
    return response["measurements"] if is_success else None

def get_results(msm_id):
    print(f"    - Waiting for results (MSM {msm_id})...")
    for _ in range(20): # Wait up to ~3.5 mins
        time.sleep(10)
        success, res = AtlasResultsRequest(msm_id=msm_id).create()
        if success and len(res) > 0: return res
    return []

def analyze_ping(results):
    total = 0
    received = 0
    for r in results:
        if r.get('avg', -1) > 0: received += 1
        total += 1
    return (received / total) * 100.0 if total > 0 else 0.0

def extract_trace_hops(results):
    """Extracts unique IPs seen in the traceroute to help identify the path."""
    hops_seen = set()
    for res in results:
        # RIPE Atlas traceroute structure is complex: result -> result (hops) -> result (packets)
        for hop in res.get('result', []):
            for packet in hop.get('result', []):
                if 'from' in packet:
                    hops_seen.add(packet['from'])
    return list(hops_seen)

def audit_proxy(target_asn, proxy_asn):
    if not ATLAS_API_KEY: print("[!] No API Key"); return

    print(f"[*] Forensic Audit: Target AS{target_asn} via Customer AS{proxy_asn}")
    
    # 1. Resolve
    ip_v, ip_i = resolve_target(DOMAIN_VALID), resolve_target(DOMAIN_INVALID)
    if not ip_v: print("[-] DNS Error"); return

    # 2. Find Probes
    probes = find_probes_by_asn(proxy_asn)
    if not probes: print(f"[-] No probes in proxy AS{proxy_asn}"); return
    print(f"    - Found {len(probes)} probes.")

    # 3. Schedule Ping AND Traceroute
    print("    - Scheduling Pings and Traceroute...")
    
    definitions = [
        Ping(af=4, target=ip_v, description=f"RPKI Valid Ping - AS{target_asn} via AS{proxy_asn}", is_oneoff=True, packets=3),
        Ping(af=4, target=ip_i, description=f"RPKI Invalid Ping - AS{target_asn} via AS{proxy_asn}", is_oneoff=True, packets=3),
        # Traceroute specifically to the INVALID target to see how it gets there (or where it drops)
        Traceroute(af=4, target=ip_i, description=f"RPKI Invalid Trace - AS{target_asn} via AS{proxy_asn}", is_oneoff=True, protocol="ICMP")
    ]
    
    msm_ids = create_request(definitions, probes)
    if not msm_ids: print("[-] API Failure"); return
    
    id_ping_v, id_ping_i, id_trace_i = msm_ids
    print(f"    - Pings: {id_ping_v}, {id_ping_i} | Trace: {id_trace_i}")

    # 4. Wait
    print("    - Sleeping 30s for execution...")
    time.sleep(30)

    # 5. Collect Results
    res_pv = get_results(id_ping_v)
    res_pi = get_results(id_ping_i)
    res_ti = get_results(id_trace_i)

    s_v = analyze_ping(res_pv)
    s_i = analyze_ping(res_pi)
    hops = extract_trace_hops(res_ti)

    # 6. Verdict
    verdict = "INCONCLUSIVE"
    if s_v > 80.0:
        if s_i > 90.0:
            verdict = "VULNERABLE (Confirmed Leaking)"
            print(f"\033[91m[-] VERDICT: {verdict}\033[0m")
            print(f"    The Invalid route is reachable.")
            print(f"    [!] CHECK TRACEROUTE HOPS for AS{target_asn}'s IPs to confirm blame.")
        elif s_i < 5.0:
            verdict = "SECURE (Filtered)"
            print(f"\033[92m[+] VERDICT: {verdict}\033[0m")
        else:
            verdict = "MIXED"
            
    print(f"    Scores: Valid={s_v:.1f}% | Invalid={s_i:.1f}%")
    print(f"    Unique Hops seen in Trace: {len(hops)}")

    # 7. Save
    data = {
        "asn": target_asn,
        "proxy_asn": proxy_asn,
        "timestamp": datetime.utcnow().isoformat(),
        "score_valid": s_v, "score_invalid": s_i,
        "verdict": verdict,
        "trace_hops": hops,  # List of IPs
        "msm_trace_id": id_trace_i
    }
    
    outfile = os.path.join(DIR_ATLAS, f"as_{target_asn}_via_{proxy_asn}_trace.json")
    with open(outfile, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"[+] Detailed forensic data saved to {outfile}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target_asn", type=int)
    parser.add_argument("--proxy-asn", type=int, required=True)
    args = parser.parse_args()
    audit_proxy(args.target_asn, args.proxy_asn)
