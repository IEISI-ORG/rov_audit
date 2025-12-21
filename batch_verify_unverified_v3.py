import pandas as pd
import requests
import json
import os
import argparse
import time
import yaml
import socket
import bz2
from datetime import datetime, timezone
from ripe.atlas.cousteau import (
    AtlasSource, Ping, AtlasCreateRequest, AtlasResultsRequest
)

# --- CONFIGURATION ---
HEADERS = {'User-Agent': 'ResearchScript/1.0'}
SECRETS_FILE = "secrets.yaml"
DIR_ATLAS = "data/atlas"
FILE_AUDIT = "rov_audit_v19_final.csv"

# RIPE Atlas Daily Dump
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

# --- 2. GLOBAL PROBE MAPPER (ROBUST) ---
def get_asn_probe_map():
    print("[*] Fetching Global Probe List (meta-latest)...")
    try:
        resp = requests.get(URL_PROBE_DUMP, headers=HEADERS, stream=True)
        resp.raise_for_status()
        
        print("    - Decompressing BZ2 stream...", end=" ")
        try:
            content = bz2.decompress(resp.content)
            data = json.loads(content)
            print("OK")
        except Exception as e:
            print(f"BZ2 Fail ({e}), trying raw JSON...", end=" ")
            data = resp.json()
            print("OK")

        # --- DYNAMIC STRUCTURE DETECTION ---
        probe_list = []
        if isinstance(data, list):
            probe_list = data
        elif isinstance(data, dict):
            # Try common keys
            if 'objects' in data: probe_list = data['objects']
            elif 'results' in data: probe_list = data['results']
            else:
                # Fallback: look for any key that holds a list
                for k, v in data.items():
                    if isinstance(v, list) and len(v) > 0 and 'id' in v[0]:
                        probe_list = v
                        break
        
        print(f"    - Found {len(probe_list)} total probes in file.")
        
        if len(probe_list) == 0:
            print("[!] Critical: No probes found in JSON structure.")
            # Debug keys
            if isinstance(data, dict): print(f"    - Top level keys: {list(data.keys())}")
            return {}

        # --- MAPPING ---
        mapping = {}
        count = 0
        skipped_status = 0
        skipped_no_asn = 0
        
        for p in probe_list:
            # Flexible Key Access
            status = p.get('status_id')
            if status is None: status = p.get('status') # Sometimes just 'status'
            
            # Check Connection (1 = Connected)
            # Some dumps use strings "1" or ints 1
            is_connected = str(status) == "1"
            
            if not is_connected:
                skipped_status += 1
                continue
                
            asn = p.get('asn_v4')
            if not asn:
                skipped_no_asn += 1
                continue
                
            asn = int(asn)
            if asn not in mapping: mapping[asn] = []
            mapping[asn].append(p['id'])
            count += 1
                
        print(f"    - Mapped {count:,} active probes across {len(mapping):,} ASNs.")
        print(f"    - Skipped: {skipped_status} disconnected, {skipped_no_asn} no ASN.")
        return mapping

    except Exception as e:
        print(f"\n[!] Failed to download probe dump: {e}")
        return {}

# --- 3. TARGET SELECTION ---
def get_targets(probe_map):
    print(f"[*] Analyzing {FILE_AUDIT} for targets...")
    if not os.path.exists(FILE_AUDIT):
        print("[!] Audit CSV not found."); return pd.DataFrame()

    df = pd.read_csv(FILE_AUDIT, low_memory=False)
    
    mask_unverified = df['verdict'].str.contains("Unverified", na=False) | \
                      df['verdict'].str.contains("Unknown", na=False)
    
    existing_tests = set()
    for f in os.listdir(DIR_ATLAS):
        if f.startswith("as_") and f.endswith(".json"):
            try:
                asn = int(f.replace("as_", "").replace(".json", "").split("_")[0])
                existing_tests.add(asn)
            except: pass
            
    df_targets = df[mask_unverified].copy()
    
    df_targets['probe_count'] = df_targets['asn'].apply(lambda x: len(probe_map.get(x, [])))
    
    testable = df_targets[df_targets['probe_count'] >= 2]
    testable = testable[~testable['asn'].isin(existing_tests)]
    
    testable['cone'] = pd.to_numeric(testable['cone'], errors='coerce').fillna(0)
    testable = testable.sort_values(by='cone', ascending=False)
    
    print("-" * 60)
    print(f"Total Unverified Networks:      {len(df_targets):,}")
    print(f"Testable Networks (Has Probes): {len(testable):,}  <-- COVERAGE GAP")
    print("-" * 60)
    
    return testable

# --- 4. MEASUREMENT ENGINE ---
def resolve_ip(domain):
    try: return socket.gethostbyname(domain)
    except: return None

def run_test(asn, probe_ids, ip_v, ip_i):
    selection = probe_ids[:20]
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

def get_results(msm_ids):
    results = {}
    for msm_id in msm_ids:
        got_data = False
        for _ in range(12): 
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

    probe_map = get_asn_probe_map()
    if not probe_map: return

    targets = get_targets(probe_map)
    if targets.empty: 
        print("No targets found.")
        return
    
    if args.dry_run:
        print(targets[['asn', 'cone', 'name', 'probe_count']].head(args.limit))
        return

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
