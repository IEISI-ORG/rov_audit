import time
import argparse
import socket
import os
import json
import yaml
from datetime import datetime
from ripe.atlas.cousteau import (
    ProbeRequest, 
    AtlasSource, 
    Ping, 
    AtlasCreateRequest,
    AtlasResultsRequest
)

# --- CONFIGURATION ---
SECRETS_FILE = "secrets.yaml"
DIR_ATLAS = "data/atlas"
os.makedirs(DIR_ATLAS, exist_ok=True)

DOMAIN_VALID   = "valid.rpki.isbgpsafeyet.com"
DOMAIN_INVALID = "invalid.rpki.isbgpsafeyet.com"

def load_api_key():
    if not os.path.exists(SECRETS_FILE): return None
    try:
        with open(SECRETS_FILE, 'r') as f:
            return yaml.safe_load(f).get('ripe_atlas_key')
    except: return None

ATLAS_API_KEY = load_api_key()

def save_result(asn, score_valid, score_invalid, verdict, probe_count, skipped=False):
    data = {
        "asn": asn,
        "timestamp_utc": datetime.utcnow().isoformat(),
        "score_valid": score_valid,
        "score_invalid": score_invalid,
        "verdict": verdict,
        "probes_used": probe_count,
        "skipped_low_probe_count": skipped
    }
    filepath = os.path.join(DIR_ATLAS, f"as_{asn}.json")
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"[+] Result saved to {filepath}")

def resolve_target(domain):
    try: return socket.gethostbyname(domain)
    except: return None

def find_probes_by_asn(asn):
    filters = {"asn_v4": asn, "status": 1} 
    try:
        probes = ProbeRequest(**filters)
        return [p["id"] for p in probes]
    except: return []

def create_measurement(probe_ids, description, target_ip):
    ping = Ping(af=4, target=target_ip, description=description, is_oneoff=True, packets=3)
    # Cap at 50 to save credits, but we rely on the min threshold to ensure quality
    subset = probe_ids[:50]
    
    source = AtlasSource(type="probes", value=",".join(map(str, subset)), requested=len(subset))
    request = AtlasCreateRequest(start_time=datetime.utcnow(), key=ATLAS_API_KEY, measurements=[ping], sources=[source], is_oneoff=True)
    
    (is_success, response) = request.create()
    return response["measurements"][0] if is_success else None

def get_results(msm_id):
    print(f"    - Waiting for results (MSM {msm_id})...")
    # Wait up to 3 minutes
    for _ in range(18):
        time.sleep(10) 
        is_success, results = AtlasResultsRequest(msm_id=msm_id).create()
        # We want meaningful results. If we sent to 20 probes, getting 1 result is bad.
        # But for now, any result allows us to proceed.
        if is_success and len(results) > 0: return results
    return []

def analyze_reachability(results):
    total = 0
    received = 0
    for r in results:
        if r.get('avg', -1) > 0: received += 1
        total += 1
    return (received / total) * 100.0 if total > 0 else 0.0

def audit_asn(asn, min_probes):
    if not ATLAS_API_KEY:
        print("[!] Missing API Key in secrets.yaml"); return

    print(f"[*] Analyzing AS{asn}...")
    
    # 1. Check Previous Results
    json_path = os.path.join(DIR_ATLAS, f"as_{asn}.json")
    if os.path.exists(json_path):
        print(f"    [!] Result already exists for AS{asn}. Skipping.")
        return

    # 2. Check Probe Count
    probes = find_probes_by_asn(asn)
    count = len(probes)
    
    if count < min_probes:
        print(f"    [-] SKIPPING: Only found {count} probes (Minimum required: {min_probes}).")
        # Optional: Save a "Skipped" result so we don't query it again?
        # For now, let's not save it, so we can retry later if more probes come online.
        return

    # 3. Resolve Targets
    ip_valid = resolve_target(DOMAIN_VALID)
    ip_invalid = resolve_target(DOMAIN_INVALID)
    if not ip_valid: 
        print("    [-] DNS Error"); return

    # 4. Measure
    print(f"    - Scheduled active test on {count} probes (Sample capped at 50)...")
    id_v = create_measurement(probes, f"RPKI Valid - AS{asn}", ip_valid)
    id_i = create_measurement(probes, f"RPKI Invalid - AS{asn}", ip_invalid)
    
    if not id_v or not id_i: return

    print("    - Sleeping 25s for propagation...")
    time.sleep(25) 
    
    res_v = get_results(id_v)
    res_i = get_results(id_i)
    
    score_v = analyze_reachability(res_v)
    score_i = analyze_reachability(res_i)
    
    # 5. Verdict
    verdict = "INCONCLUSIVE"
    if score_v > 80.0:
        if score_i < 5.0: verdict = "SECURE"
        elif score_i > 90.0: verdict = "VULNERABLE"
        else: verdict = "MIXED"
    
    print("\n" + "-"*60)
    print(f"AS{asn} RESULTS ({count} Probes)")
    print(f"Valid Reachability:   {score_v:.1f}%")
    print(f"Invalid Reachability: {score_i:.1f}%")
    print(f"Verdict:              {verdict}")
    print("-"*60)
    
    save_result(asn, score_v, score_i, verdict, count)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Verify RPKI ROV using RIPE Atlas with minimum probe thresholds.")
    parser.add_argument("asn", type=int, help="The ASN to test")
    parser.add_argument("--min-probes", type=int, default=10, help="Minimum probes required to run test (Default: 10)")
    args = parser.parse_args()
    
    audit_asn(args.asn, args.min_probes)
