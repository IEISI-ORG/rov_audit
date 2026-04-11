import pandas as pd
import requests
import json
import os
import argparse
import time
import yaml
import socket
from datetime import datetime, timezone
from ripe.atlas.cousteau import (
    AtlasSource, Ping, AtlasCreateRequest, AtlasResultsRequest
)

# --- CONFIGURATION ---
HEADERS = {'User-Agent': 'ResearchScript/1.0'}
SECRETS_FILE = "secrets.yaml"
DIR_ATLAS = "data/atlas"
FILE_AUDIT = "rov_audit_v19_final.csv"

# RIPE Atlas Daily Dump (Much faster than API pagination)
URL_PROBE_DUMP = "https://ftp.ripe.net/ripe/atlas/probes/archive/meta-latest"

DOMAIN_VALID   = "valid.rpki.isbgpsafeyet.com"
DOMAIN_INVALID = "invalid.rpki.isbgpsafeyet.com"

# --- 1. SETUP ---
if not os.path.exists(DIR_ATLAS): os.makedirs(DIR_ATLAS)

def load_api_key():
    if not os.path.exists(SECRETS_FILE): return None
    try:
        with open(SECRETS_FILE, 'r') as f: return yaml.safe_load(f).get('ripe_atlas_key')
    except: return None

ATLAS_API_KEY = load_api_key()

# --- 2. GLOBAL PROBE MAPPER ---
def get_asn_probe_map():
    """
    Downloads the full RIPE Atlas probe list and builds a map:
    { asn: [probe_id_1, probe_id_2, ...] }
    Only includes Connected, Public, IPv4 probes.
    """
    print("[*] Fetching Global Probe List (meta-latest)...")
    try:
        resp = requests.get(URL_PROBE_DUMP, headers=HEADERS)
        data = resp.json()
        
        mapping = {}
        count = 0
        
        for p in data.get('objects', []):
            # Status 1 = Connected
            if p.get('status_id') == 1 and p.get('is_public') and p.get('asn_v4'):
                asn = int(p['asn_v4'])
                if asn not in mapping: mapping[asn] = []
                mapping[asn].append(p['id'])
                count += 1
                
        print(f"    - Mapped {count:,} active probes across {len(mapping):,} ASNs.")
        return mapping
    except Exception as e:
        print(f"[!] Failed to download probe dump: {e}")
        return {}

# --- 3. TARGET SELECTION ---
def get_targets(probe_map):
    print(f"[*] Analyzing {FILE_AUDIT} for targets...")
    df = pd.read_csv(FILE_AUDIT, low_memory=False)
    
    # Filter for Unverified
    # We want rows where verdict contains "Unverified" or "Unknown"
    mask_unverified = df['verdict'].str.contains("Unverified", na=False) | \
                      df['verdict'].str.contains("Unknown", na=False)
    
    # Also exclude things we already tested locally
    # (Check if JSON exists in data/atlas/)
    existing_tests = set()
    for f in os.listdir(DIR_ATLAS):
        if f.startswith("as_") and f.endswith(".json"):
            try:
                asn = int(f.replace("as_", "").replace(".json", "").split("_")[0])
                existing_tests.add(asn)
            except: pass
            
    df_targets = df[mask_unverified].copy()
    total_unverified = len(df_targets)
    
    # Filter: Must have probes available
    # We create a new column 'probe_count' based on our map
    df_targets['probe_count'] = df_targets['asn'].apply(lambda x: len(probe_map.get(x, [])))
    
    # Filter: Must have at least 2 probes (for reliability)
    testable = df_targets[df_targets['probe_count'] >= 2]
    
    # Filter: Not already tested
    testable = testable[~testable['asn'].isin(existing_tests)]
    
    # Sort by Cone Size (Impact)
    testable = testable.sort_values(by='cone', ascending=False)
    
    print("-" * 60)
    print(f"Total Unverified Networks:      {total_unverified:,}")
    print(f"Testable Networks (Has Probes): {len(testable):,}  <-- COVERAGE GAP")
    print("-" * 60)
    
    return testable

# --- 4. MEASUREMENT ENGINE ---
def resolve_ip(domain):
    try: return socket.gethostbyname(domain)
    except: return None

def run_test(asn, probe_ids, ip_v, ip_i):
    # Cap at 20 probes per ASN to save credits
    selection = probe_ids[:20]
    
    # 1. Create Measurement
    source = AtlasSource(type="probes", value=",".join(map(str, selection)), requested=len(selection))
    
    defs = [
        Ping(af=4, target=ip_v, description=f"RPKI Valid - AS{asn}", is_oneoff=True, packets=3),
        Ping(af=4, target=ip_i, description=f"RPKI Invalid - AS{asn}", is_oneoff=True, packets=3)
    ]
    
    req = AtlasCreateRequest(
        start_time=datetime.now(timezone.utc), 
        key=ATLAS_API_KEY, 
        measurements=defs, 
        sources=[source], 
        is_oneoff=True
    )
    
    success, resp = req.create()
    if not success: return None
    return resp["measurements"]

def get_results_blocking(msm_ids):
    # Wait loop
    results = {}
    for msm_id in msm_ids:
        # Simple blocking wait (fast enough for batch of 1 at a time)
        # In a massive system we'd use async, but this is fine for 200 items.
        got_data = False
        for _ in range(12): # 2 mins max
            time.sleep(10)
            success, res = AtlasResultsRequest(msm_id=msm_id).create()
            if success and len(res) > 0:
                results[msm_id] = res
                got_data = True
                break
        if not got_data:
            results[msm_id] = []
    return results

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
    if s_v > 80.0:
        if s_i < 5.0: verdict = "SECURE (Verified Active)"
        elif s_i > 90.0: verdict = "VULNERABLE (Verified Active)"
        else: verdict = "PARTIAL / MIXED"
        
    data = {
        "asn": asn,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "verdict": verdict,
        "score_valid": s_v,
        "score_invalid": s_i,
        "probes_used": probe_count
    }
    
    with open(os.path.join(DIR_ATLAS, f"as_{asn}.json"), 'w') as f:
        json.dump(data, f, indent=2)
        
    return verdict, s_v, s_i

# --- 5. MAIN ---
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=200, help="Number of ASNs to test")
    parser.add_argument("--dry-run", action="store_true", help="Show targets but do not test")
    args = parser.parse_args()

    if not ATLAS_API_KEY and not args.dry_run:
        print("[!] No API Key in secrets.yaml"); return

    # 1. Map Probes
    probe_map = get_asn_probe_map()
    if not probe_map: return

    # 2. Get Targets
    targets = get_targets(probe_map)
    
    if args.dry_run:
        print(targets[['asn', 'cone', 'name', 'probe_count']].head(args.limit))
        return

    # 3. Resolve Targets
    ip_v = resolve_ip(DOMAIN_VALID)
    ip_i = resolve_ip(DOMAIN_INVALID)
    if not ip_v: print("[-] DNS Error"); return

    print(f"\n[*] Starting Batch Test on Top {args.limit} Unverified Networks...")
    
    count = 0
    for idx, row in targets.iterrows():
        if count >= args.limit: break
        
        asn = int(row['asn'])
        probes = probe_map[asn]
        
        print(f"\n[{count+1}/{args.limit}] Testing AS{asn} ({row['name']}) with {len(probes)} probes...")
        
        msm_ids = run_test(asn, probes, ip_v, ip_i)
        if not msm_ids:
            print("    [!] API Failed (Credits?)")
            continue
            
        print("    - Waiting for results...")
        res_map = get_results(msm_ids)
        
        verdict, s_v, s_i = analyze_and_save(asn, res_map[msm_ids[0]], res_map[msm_ids[1]], len(probes))
        
        color = "\033[0m"
        if "SECURE" in verdict: color = "\033[92m"
        elif "VULNERABLE" in verdict: color = "\033[91m"
        
        print(f"    -> Valid: {s_v:.0f}% | Invalid: {s_i:.0f}% | {color}{verdict}\033[0m")
        count += 1

    print("\n[*] Batch Complete. Run 'rov_global_audit_v18.py' to update report.")

if __name__ == "__main__":
    main()
