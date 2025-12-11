import argparse
import socket
import os
import json
import yaml
import time
from datetime import datetime
from ripe.atlas.cousteau import (
    ProbeRequest, AtlasSource, Ping, AtlasCreateRequest, AtlasResultsRequest
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

def run_ping(probe_ids, target_ip, desc):
    ping = Ping(af=4, target=target_ip, description=desc, is_oneoff=True, packets=3)
    source = AtlasSource(type="probes", value=",".join(map(str, probe_ids[:50])), requested=len(probe_ids[:50]))
    req = AtlasCreateRequest(start_time=datetime.utcnow(), key=ATLAS_API_KEY, measurements=[ping], sources=[source], is_oneoff=True)
    success, resp = req.create()
    return resp["measurements"][0] if success else None

def get_results(msm_id):
    print(f"    - Waiting for results (MSM {msm_id})...")
    for _ in range(18):
        time.sleep(10)
        success, res = AtlasResultsRequest(msm_id=msm_id).create()
        if success and len(res) > 0: return res
    return []

def calc_score(results):
    total = 0
    received = 0
    for r in results:
        if r.get('avg', -1) > 0: received += 1
        total += 1
    return (received / total) * 100.0 if total > 0 else 0.0

def audit_proxy(target_asn, proxy_asn):
    if not ATLAS_API_KEY: print("[!] No API Key"); return

    print(f"[*] Indirect Audit: Target AS{target_asn} via Customer AS{proxy_asn}")
    
    # 1. Resolve
    ip_v, ip_i = resolve_target(DOMAIN_VALID), resolve_target(DOMAIN_INVALID)
    if not ip_v: print("[-] DNS Error"); return

    # 2. Find Probes in PROXY
    probes = find_probes_by_asn(proxy_asn)
    if not probes: print(f"[-] No probes in proxy AS{proxy_asn}"); return
    print(f"    - Found {len(probes)} probes in customer network.")

    # 3. Measure
    print("    - Running measurements...")
    id_v = run_ping(probes, ip_v, f"RPKI Valid - Target AS{target_asn} via AS{proxy_asn}")
    id_i = run_ping(probes, ip_i, f"RPKI Invalid - Target AS{target_asn} via AS{proxy_asn}")
    
    if not id_v or not id_i: return
    time.sleep(25)

    # 4. Score
    s_v = calc_score(get_results(id_v))
    s_i = calc_score(get_results(id_i))

    # 5. Verdict
    verdict = "INCONCLUSIVE"
    if s_v > 80.0:
        if s_i > 90.0:
            verdict = "VULNERABLE (Confirmed Leaking)"
            print(f"\033[91m[-] VERDICT: {verdict}\033[0m")
            print(f"    Customer AS{proxy_asn} can reach Invalid routes.")
            print(f"    Therefore, Upstream AS{target_asn} is NOT filtering.")
        elif s_i < 5.0:
            verdict = "SECURE (Filtered)"
            print(f"\033[92m[+] VERDICT: {verdict}\033[0m")
            print(f"    Customer AS{proxy_asn} blocked Invalid routes.")
            print(f"    (Block could be by Customer OR Target)")
        else:
            verdict = "MIXED"
    
    # 6. Save (Note the proxy relationship)
    data = {
        "asn": target_asn,
        "proxy_asn": proxy_asn,
        "timestamp": datetime.utcnow().isoformat(),
        "score_valid": s_v, "score_invalid": s_i, "verdict": verdict,
        "method": "indirect_customer_probe"
    }
    with open(os.path.join(DIR_ATLAS, f"as_{target_asn}_via_{proxy_asn}.json"), 'w') as f:
        json.dump(data, f, indent=2)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target_asn", type=int)
    parser.add_argument("--proxy-asn", type=int, required=True, help="The customer ASN containing probes")
    args = parser.parse_args()
    audit_proxy(args.target_asn, args.proxy_asn)
