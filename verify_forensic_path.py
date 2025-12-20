import argparse
import pandas as pd
import requests
import json
import os
import yaml
import time
import socket
from datetime import datetime
from ripe.atlas.cousteau import (
    ProbeRequest, AtlasSource, Ping, Traceroute, AtlasCreateRequest, AtlasResultsRequest
)

# --- CONFIGURATION ---
SECRETS_FILE = "secrets.yaml"
DIR_ATLAS = "data/atlas"
FILE_AUDIT = "rov_audit_v17_final.csv"
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
        # Prefer stable probes? For now just take first N
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
    
    req = AtlasCreateRequest(
        start_time=datetime.utcnow(), 
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
def analyze_results(asn, results):
    res_pv, res_pi, res_tv, res_ti = results
    
    # A. Ping Scores
    def get_ping_rate(res):
        total, rec = 0, 0
        for r in res:
            if r.get('avg', -1) > 0: rec += 1
            total += 1
        return (rec/total)*100 if total else 0

    score_v = get_ping_rate(res_pv)
    score_i = get_ping_rate(res_pi)
    
    # B. Extract Hops (Flatten all probes into one linear path for simplicity)
    # In production, analyze per-probe.
    def extract_hops(res):
        hops = []
        if not res: return []
        # Take first successful probe
        for r in res:
            if 'result' in r:
                for h in r['result']:
                    for p in h.get('result', []):
                        if 'from' in p:
                            hops.append(p['from'])
                            break # One IP per hop
                if hops: break
        return hops

    hops_v = extract_hops(res_tv)
    hops_i = extract_hops(res_ti)
    
    # C. Map to ASNs
    all_ips = list(set(hops_v + hops_i))
    ip_map = resolve_asns(all_ips)
    
    path_v = ips_to_as_path(hops_v, ip_map)
    path_i = ips_to_as_path(hops_i, ip_map)
    
    # D. Logic
    verdict = "INCONCLUSIVE"
    notes = "Analysis failed"
    peers_cf = False
    divergent = False

    # Check Cloudflare Peering
    if CLOUDFLARE_ASN in path_v:
        # If CF is in path, check if it's adjacent to Target?
        # Since probe is IN Target, path[0] should be Target or Upstream.
        peers_cf = True

    # Check Divergence
    # Simple check: Do they share the first upstream hop?
    if len(path_v) > 1 and len(path_i) > 1:
        if path_v[0] != path_i[0]:
            divergent = True
            notes = f"Path Divergence: Valid via AS{path_v[0]}, Invalid via AS{path_i[0]}"

    if score_v < 50.0:
        verdict = "INCONCLUSIVE"
        notes = "Control (Valid) Ping failed."
    elif divergent:
        verdict = "INCONCLUSIVE (Divergent)"
        # Note is already set
    elif score_i > 90.0:
        verdict = "VULNERABLE"
        notes = "Invalid Prefix Reachable."
    elif score_i < 10.0:
        verdict = "SECURE"
        # Determine filtering point
        if not path_i:
            notes = "Filtered locally (No trace output)"
        else:
            last_as = path_i[-1]
            if last_as == asn:
                notes = "Filtered Locally (Last hop was us)"
            else:
                notes = f"Filtered by Upstream AS{last_as}"
    else:
        verdict = "MIXED"
        notes = f"Partial block ({score_i:.1f}% reachable)"

    return {
        'asn': asn,
        'verdict': verdict,
        'notes': notes,
        'score_valid': score_v,
        'score_invalid': score_i,
        'valid_path': path_v,
        'invalid_path': path_i,
        'peers_cf': peers_cf,
        'divergent': divergent,
        'timestamp': datetime.utcnow().isoformat()
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
        
        # Filter: Already tested?
        for asn in candidates['asn']:
            if not os.path.exists(os.path.join(DIR_ATLAS, f"as_{asn}.json")):
                targets.append(int(asn))
            if len(targets) >= args.limit: break
            
    print(f"[*] Selected {len(targets)} targets for Forensic Analysis.")
    
    # 2. Resolve DNS once
    ip_v = resolve_ip(DOMAIN_VALID)
    ip_i = resolve_ip(DOMAIN_INVALID)
    if not ip_v: print("[-] DNS Fail"); return

    # 3. Loop
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
        
        # Print
        color = "\033[0m"
        if "SECURE" in data['verdict']: color = "\033[92m"
        elif "VULNERABLE" in data['verdict']: color = "\033[91m"
        elif "Divergent" in data['verdict']: color = "\033[93m"
        
        print(f"    Verdict: {color}{data['verdict']}\033[0m")
        print(f"    Notes:   {data['notes']}")
        print(f"    Path V:  {data['valid_path']}")
        print(f"    Path I:  {data['invalid_path']}")
        
        # Save JSON (Feeds into main audit script)
        with open(os.path.join(DIR_ATLAS, f"as_{asn}.json"), 'w') as f:
            json.dump(data, f, indent=2)
            
        results_summary.append(data)

    # 4. Save Summary CSV
    if results_summary:
        df = pd.DataFrame(results_summary)
        df.to_csv("forensic_results_batch.csv", index=False)
        print("\n[+] Batch results saved to forensic_results_batch.csv")

if __name__ == "__main__":
    main()
