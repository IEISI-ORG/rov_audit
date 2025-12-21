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
    AtlasSource, Ping, Traceroute, AtlasCreateRequest, AtlasResultsRequest
)

# --- CONFIGURATION ---
HEADERS = {'User-Agent': 'ResearchScript/1.0'}
SECRETS_FILE = "secrets.yaml"
DIR_ATLAS = "data/atlas"
FILE_AUDIT = "rov_audit_v19_final.csv" # Updated to v19
FILE_GRAPH = "data/downstream_graph.json"
RIPE_STAT_URL = "https://stat.ripe.net/data/network-info/data.json?resource="

# RIPE Atlas Daily Dump
URL_PROBE_DUMP = "https://ftp.ripe.net/ripe/atlas/probes/archive/meta-latest"

DOMAIN_VALID   = "valid.rpki.isbgpsafeyet.com"
DOMAIN_INVALID = "invalid.rpki.isbgpsafeyet.com"
CLOUDFLARE_ASN = 13335

# --- SETUP ---
if not os.path.exists(DIR_ATLAS): os.makedirs(DIR_ATLAS)

def load_api_key():
    if not os.path.exists(SECRETS_FILE): return None
    try:
        with open(SECRETS_FILE, 'r') as f: return yaml.safe_load(f).get('ripe_atlas_key')
    except: return None

ATLAS_API_KEY = load_api_key()

# ==============================================================================
# 1. HELPERS: RESOLVERS & DATA LOADING
# ==============================================================================
def resolve_ip(domain):
    try: return socket.gethostbyname(domain)
    except: return None

def resolve_path_asns(ip_list):
    """Resolves list of IPs to ASNs using RIPEstat."""
    mapping = {}
    unique = list(set(ip for ip in ip_list if ip and not ip.startswith(('10.', '192.', '172.'))))
    # Simple serial resolver (fast enough for small batches of hops)
    for ip in unique:
        try:
            r = requests.get(f"{RIPE_STAT_URL}{ip}", timeout=2)
            if r.status_code == 200:
                asns = r.json().get('data', {}).get('asns', [])
                if asns: mapping[ip] = int(asns[0])
        except: pass
    return mapping

def get_asn_probe_map():
    """Downloads and decompresses RIPE Atlas probe dump."""
    print("[*] Fetching Global Probe List (meta-latest)...")
    try:
        resp = requests.get(URL_PROBE_DUMP, headers=HEADERS, stream=True)
        
        # Handle BZ2
        try:
            content = bz2.decompress(resp.content)
            data = json.loads(content)
        except:
            data = resp.json() # Fallback

        # Find list
        probe_list = []
        if isinstance(data, dict):
            if 'objects' in data: probe_list = data['objects']
            else: probe_list = list(data.values())[0] if data else []
        elif isinstance(data, list):
            probe_list = data

        mapping = {}
        for p in probe_list:
            status = str(p.get('status_id', p.get('status')))
            if status == "1" and p.get('is_public') and p.get('asn_v4'):
                asn = int(p['asn_v4'])
                if asn not in mapping: mapping[asn] = []
                mapping[asn].append(p['id'])
                
        print(f"    - Mapped active probes across {len(mapping):,} ASNs.")
        return mapping
    except Exception as e:
        print(f"[!] Probe Dump Error: {e}")
        return {}

def load_topology():
    if not os.path.exists(FILE_GRAPH): return {}
    with open(FILE_GRAPH, 'r') as f:
        return json.load(f)

# ==============================================================================
# 2. TARGET SELECTION (THE SMART PART)
# ==============================================================================
def find_test_strategy(target_asn, probe_map, topology):
    """
    Decides how to test the target.
    Returns: (probe_id, strategy_type, description)
    strategy_type: 'DIRECT' or 'PROXY'
    """
    # 1. Try Direct
    if target_asn in probe_map:
        return probe_map[target_asn][0], "DIRECT", f"Direct Probe"

    # 2. Try Proxy (Downstream Customers)
    # The topology file maps Parent -> [Children]
    # We want Children of Target
    children = topology.get(str(target_asn), [])
    
    for child in children:
        child_asn = int(child)
        if child_asn in probe_map:
            return probe_map[child_asn][0], "PROXY", f"Via Customer AS{child_asn}"
            
    return None, "NONE", "No probes found in ASN or Customers"

def get_targets(probe_map, topology):
    print(f"[*] Analyzing Targets...")
    if not os.path.exists(FILE_AUDIT): return []

    df = pd.read_csv(FILE_AUDIT, low_memory=False)
    
    # Filter: Unverified
    mask = df['verdict'].str.contains("Unverified", na=False) | df['verdict'].str.contains("Unknown", na=False)
    
    # Filter: Not already tested
    tested = set()
    for f in os.listdir(DIR_ATLAS):
        if f.startswith("as_") and f.endswith(".json"):
            try: tested.add(int(f.split("_")[1].split(".")[0]))
            except: pass
            
    candidates = df[mask & ~df['asn'].isin(tested)].copy()
    candidates['cone'] = pd.to_numeric(candidates['cone'], errors='coerce').fillna(0)
    candidates = candidates.sort_values(by='cone', ascending=False)
    
    work_queue = []
    
    print(f"    - Scanning {len(candidates)} candidates for testability...")
    
    for _, row in candidates.iterrows():
        asn = int(row['asn'])
        pid, strat, desc = find_test_strategy(asn, probe_map, topology)
        
        if pid:
            work_queue.append({
                'asn': asn,
                'name': row['name'],
                'cone': row['cone'],
                'probe_id': pid,
                'strategy': strat,
                'desc': desc
            })
            
    return work_queue

# ==============================================================================
# 3. MEASUREMENT & ANALYSIS
# ==============================================================================
def run_measurements(asn, probe_id, strategy, ip_v, ip_i):
    # Always run Traceroute if PROXY, to prove path.
    # If DIRECT, Traceroute is also good for forensics.
    # Let's standardize on Trace for this batch script for robustness.
    
    source = AtlasSource(type="probes", value=str(probe_id), requested=1)
    
    desc_v = f"RPKI Valid ({strategy}) - AS{asn}"
    desc_i = f"RPKI Invalid ({strategy}) - AS{asn}"
    
    defs = [
        Traceroute(af=4, target=ip_v, description=desc_v, is_oneoff=True, protocol="ICMP"),
        Traceroute(af=4, target=ip_i, description=desc_i, is_oneoff=True, protocol="ICMP")
    ]
    
    req = AtlasCreateRequest(
        start_time=datetime.now(timezone.utc), 
        key=ATLAS_API_KEY, 
        measurements=defs, 
        sources=[source], 
        is_oneoff=True
    )
    
    success, resp = req.create()
    if success: return resp["measurements"]
    else: return None

def analyze_trace_result(target_asn, res_v, res_i, strategy):
    # 1. Extract Hops (IPs)
    def get_hops(res):
        ips = []
        if not res: return []
        for h in res[0].get('result', []):
            for p in h.get('result', []):
                if 'from' in p: 
                    ips.append(p['from'])
                    break
        return ips

    hops_v = get_hops(res_v)
    hops_i = get_hops(res_i)
    
    # 2. Resolve ASNs
    all_ips = list(set(hops_v + hops_i))
    ip_map = resolve_path_asns(all_ips)
    
    path_v = []
    for ip in hops_v:
        a = ip_map.get(ip)
        if a and (not path_v or path_v[-1] != a): path_v.append(a)

    path_i = []
    for ip in hops_i:
        a = ip_map.get(ip)
        if a and (not path_i or path_i[-1] != a): path_i.append(a)

    # 3. Logic
    reached_cf = CLOUDFLARE_ASN in path_i
    target_in_valid = target_asn in path_v
    
    verdict = "INCONCLUSIVE"
    notes = ""
    
    if strategy == "PROXY" and not target_in_valid:
        verdict = "INCONCLUSIVE (Bypassed)"
        notes = f"Valid path did not traverse Target AS{target_asn}"
    elif reached_cf:
        verdict = "VULNERABLE (Verified Active)"
        notes = "Invalid route reached Cloudflare"
    else:
        # It stopped.
        if strategy == "DIRECT":
            verdict = "SECURE (Verified Active)" # Direct probe couldn't reach invalid
        elif strategy == "PROXY":
            # Did it stop AT or AFTER the target?
            # If target is in Invalid Path, and it stopped later -> Secure
            if target_asn in path_i:
                verdict = "SECURE (Verified Active)"
                notes = "Traffic passed Target and was dropped upstream"
            elif path_i and path_i[-1] == target_asn:
                verdict = "SECURE (Verified Active)"
                notes = "Traffic dropped AT Target"
            else:
                # Stopped BEFORE target?
                verdict = "INCONCLUSIVE (Upstream Block)"
                notes = "Traffic dropped before reaching Target"

    return verdict, notes, path_v

# ==============================================================================
# 4. MAIN
# ==============================================================================
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=10, help="Max tests to run")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if not ATLAS_API_KEY and not args.dry_run:
        print("[!] No API Key"); return

    probe_map = get_asn_probe_map()
    topology = load_topology()
    queue = get_targets(probe_map, topology)
    
    print("-" * 60)
    print(f"Total Testable Candidates: {len(queue)}")
    print("-" * 60)
    
    if args.dry_run:
        print(f"Top {args.limit} candidates:")
        for q in queue[:args.limit]:
            print(f"AS{q['asn']:<6} | Cone: {int(q['cone']):<6} | {q['strategy']:<6} | {q['desc']}")
        return

    # Execute
    ip_v = resolve_ip(DOMAIN_VALID)
    ip_i = resolve_ip(DOMAIN_INVALID)
    if not ip_v: print("[-] DNS Error"); return

    print(f"\n[*] Executing {min(len(queue), args.limit)} Tests...")
    
    for i, item in enumerate(queue[:args.limit]):
        asn = item['asn']
        print(f"\n[{i+1}] Testing AS{asn} ({item['strategy']})...")
        
        msm_ids = run_measurements(asn, item['probe_id'], item['strategy'], ip_v, ip_i)
        if not msm_ids:
            print("    [!] API Fail"); continue
            
        print("    - Waiting 40s...")
        time.sleep(40)
        
        # Fetch Result
        try:
            res_v = AtlasResultsRequest(msm_id=msm_ids[0]).create()[1]
            res_i = AtlasResultsRequest(msm_id=msm_ids[1]).create()[1]
            
            verdict, notes, path = analyze_trace_result(asn, res_v, res_i, item['strategy'])
            
            color = "\033[0m"
            if "SECURE" in verdict: color = "\033[92m"
            elif "VULNERABLE" in verdict: color = "\033[91m"
            
            print(f"    -> {color}{verdict}\033[0m")
            print(f"    -> {notes}")
            print(f"    -> Path: {path}")
            
            # Save
            data = {
                "asn": asn,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "verdict": verdict,
                "strategy": item['strategy'],
                "valid_path": path,
                "notes": notes
            }
            with open(os.path.join(DIR_ATLAS, f"as_{asn}.json"), 'w') as f:
                json.dump(data, f, indent=2)
                
        except Exception as e:
            print(f"    [!] Error processing results: {e}")

    print("\n[*] Batch Complete. Run 'rov_global_audit_v18.py' to update report.")

if __name__ == "__main__":
    main()
