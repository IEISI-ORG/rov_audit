import argparse
import requests
import json
import os
import yaml
import time
import socket
from datetime import datetime, timezone
from collections import defaultdict
from ripe.atlas.cousteau import (
    ProbeRequest, AtlasSource, Ping, AtlasCreateRequest, AtlasResultsRequest
)

# --- CONFIGURATION ---
SECRETS_FILE = "secrets.yaml"
DIR_ATLAS = "data/atlas"
DOMAINS = {
    'valid': "valid.rpki.isbgpsafeyet.com",
    'invalid': "invalid.rpki.isbgpsafeyet.com"
}

# Tuning
PROBES_PER_ASN = 5  # Sufficient for a high-confidence Ping test
TOTAL_PROBE_LIMIT = 500 # Hard cap per run to manage credits

# --- SETUP ---
if not os.path.exists(DIR_ATLAS): os.makedirs(DIR_ATLAS)

def load_api_key():
    if not os.path.exists(SECRETS_FILE): return None
    try:
        with open(SECRETS_FILE, 'r') as f: return yaml.safe_load(f).get('ripe_atlas_key')
    except: return None

ATLAS_API_KEY = load_api_key()

# ==============================================================================
# 1. DISCOVERY
# ==============================================================================
def get_country_probes(cc):
    print(f"[*] Searching RIPE Atlas for probes in '{cc}'...")
    try:
        filters = {"country_code": cc, "status": 1, "is_public": True}
        probes = list(ProbeRequest(**filters))
        print(f"    - Found {len(probes)} total active probes.")
        return probes
    except Exception as e:
        print(f"[!] Error finding probes: {e}")
        return []

def group_probes_by_asn(probes):
    """
    Organizes probes into a dict: { asn: [probe_id, probe_id...] }
    """
    asn_map = defaultdict(list)
    for p in probes:
        if p.get('asn_v4'):
            asn_map[int(p['asn_v4'])].append(p['id'])
    return asn_map

def filter_targets(asn_map):
    """
    Selects probes to test based on limits and existing data.
    Returns: List of tasks [{'asn': 123, 'probes': [1,2,3]}]
    """
    tasks = []
    used_probe_count = 0
    
    # Check what we've already done
    existing = set()
    for f in os.listdir(DIR_ATLAS):
        if f.startswith("as_") and f.endswith(".json"):
            try:
                a = int(f.replace("as_", "").replace(".json", "").split("_")[0])
                existing.add(a)
            except: pass

    # Sort ASNs by probe count (prefer networks with more probes for better data)
    # or simple iteration. Let's do simple iteration.
    
    for asn, p_ids in asn_map.items():
        if used_probe_count >= TOTAL_PROBE_LIMIT:
            break
            
        if asn in existing:
            continue # Skip already tested
            
        # Select subset
        selection = p_ids[:PROBES_PER_ASN]
        
        tasks.append({
            'asn': asn,
            'probes': selection
        })
        
        used_probe_count += len(selection)
        
    return tasks, used_probe_count

# ==============================================================================
# 2. EXECUTION
# ==============================================================================
def resolve_ips():
    ips = {}
    print("[*] Resolving Cloudflare RPKI Beacons...")
    for k, v in DOMAINS.items():
        try:
            ips[k] = socket.gethostbyname(v)
            print(f"    - {k.upper()}: {ips[k]}")
        except:
            print(f"    [!] Failed to resolve {v}")
            return None
    return ips

def run_asn_test(task, ips):
    asn = task['asn']
    probe_ids = task['probes']
    
    # 1. Define Pings
    source = AtlasSource(
        type="probes", 
        value=",".join(map(str, probe_ids)), 
        requested=len(probe_ids)
    )
    
    defs = [
        Ping(af=4, target=ips['valid'], description=f"RPKI Valid - AS{asn} ({len(probe_ids)} probes)", is_oneoff=True, packets=3),
        Ping(af=4, target=ips['invalid'], description=f"RPKI Invalid - AS{asn} ({len(probe_ids)} probes)", is_oneoff=True, packets=3)
    ]
    
    # 2. Submit
    try:
        req = AtlasCreateRequest(
            start_time=datetime.now(timezone.utc),
            key=ATLAS_API_KEY,
            measurements=defs,
            sources=[source],
            is_oneoff=True
        )
        success, resp = req.create()
        if success:
            return resp["measurements"]
        else:
            print(f"    [!] API Error for AS{asn}: {resp}")
            return None
    except Exception as e:
        print(f"    [!] Exception: {e}")
        return None

def analyze_and_save(asn, res_v, res_i, probe_count):
    def score(res):
        tot, rec = 0, 0
        for r in res:
            if r.get('avg', -1) > 0: rec += 1
            tot += 1
        return (rec/tot)*100 if tot else 0

    s_v = score(res_v)
    s_i = score(res_i)
    
    verdict = "INCONCLUSIVE"
    # Thresholds: High Valid reachability, Low Invalid reachability
    if s_v > 80.0:
        if s_i < 5.0: verdict = "SECURE (Verified Active)"
        elif s_i > 90.0: verdict = "VULNERABLE (Verified Active)"
        else: verdict = "PARTIAL / MIXED"
        
    # Save
    data = {
        "asn": asn,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "verdict": verdict,
        "score_valid": s_v,
        "score_invalid": s_i,
        "probes_used": probe_count,
        "method": "bulk_country_ping"
    }
    
    with open(os.path.join(DIR_ATLAS, f"as_{asn}.json"), 'w') as f:
        json.dump(data, f, indent=2)
        
    return verdict, s_v, s_i

# ==============================================================================
# 3. MAIN
# ==============================================================================
def main():
    parser = argparse.ArgumentParser(description="Bulk RPKI Test for a specific Country Code.")
    parser.add_argument("cc", help="ISO-2 Country Code (e.g. AU, US)")
    parser.add_argument("--dry-run", action="store_true", help="List targets only")
    args = parser.parse_args()

    if not ATLAS_API_KEY and not args.dry_run:
        print("[!] No API Key found in secrets.yaml"); return

    # 1. Find & Filter
    cc = args.cc.upper()
    raw_probes = get_country_probes(cc)
    if not raw_probes: return
    
    asn_map = group_probes_by_asn(raw_probes)
    print(f"    - Probes are distributed across {len(asn_map)} ASNs.")
    
    tasks, probe_total = filter_targets(asn_map)
    
    print("-" * 60)
    print(f"PLAN: Test {len(tasks)} unique ASNs using {probe_total} total probes.")
    print(f"      (Max {PROBES_PER_ASN} probes/ASN, Total Cap {TOTAL_PROBE_LIMIT})")
    print("-" * 60)
    
    if args.dry_run:
        for t in tasks:
            print(f"Target: AS{t['asn']:<6} ({len(t['probes'])} probes)")
        return

    # 2. Prepare
    target_ips = resolve_ips()
    if not target_ips: return

    print(f"\n[*] Starting Bulk Execution...")
    
    for i, task in enumerate(tasks):
        asn = task['asn']
        print(f"\n[{i+1}/{len(tasks)}] Testing AS{asn}...", end=" ", flush=True)
        
        msm_ids = run_asn_test(task, target_ips)
        
        if msm_ids:
            # Wait loop (Blocking is fine for serial execution)
            # For 2 measurements it takes ~30-40s
            time.sleep(30)
            
            # Fetch Results
            try:
                res_v = AtlasResultsRequest(msm_id=msm_ids[0]).create()[1]
                res_i = AtlasResultsRequest(msm_id=msm_ids[1]).create()[1]
                
                verdict, sv, si = analyze_and_save(asn, res_v, res_i, len(task['probes']))
                
                color = "\033[0m"
                if "SECURE" in verdict: color = "\033[92m"
                elif "VULNERABLE" in verdict: color = "\033[91m"
                
                print(f"{color}{verdict}\033[0m (V:{sv:.0f}% I:{si:.0f}%)")
                
            except Exception as e:
                print(f"Error fetching results: {e}")
        else:
            print("Failed to schedule.")
            
        # Small delay between ASNs
        time.sleep(2)

    print("\n[*] Country Sweep Complete.")
    print("    Run 'rov_global_audit_v18.py' to integrate these new results.")

if __name__ == "__main__":
    main()
