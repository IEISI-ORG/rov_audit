import argparse
import socket
import os
import json
import yaml
import time
import requests
from datetime import datetime
from ripe.atlas.cousteau import (
    ProbeRequest, AtlasSource, Traceroute, AtlasCreateRequest, AtlasResultsRequest
)

# --- CONFIGURATION ---
SECRETS_FILE = "secrets.yaml"
DIR_ATLAS = "data/atlas"
os.makedirs(DIR_ATLAS, exist_ok=True)

DOMAIN_VALID   = "valid.rpki.isbgpsafeyet.com"
DOMAIN_INVALID = "invalid.rpki.isbgpsafeyet.com"
CLOUDFLARE_ASN = 13335

# RIPEstat API Endpoint (The native way to get ASNs)
RIPE_STAT_URL = "https://stat.ripe.net/data/network-info/data.json?resource="

def load_api_key():
    if not os.path.exists(SECRETS_FILE): return None
    try:
        with open(SECRETS_FILE, 'r') as f: return yaml.safe_load(f).get('ripe_atlas_key')
    except: return None

ATLAS_API_KEY = load_api_key()

# ==============================================================================
# 1. RIPE NATIVE RESOLVER (HTTP)
# ==============================================================================
def is_public_ip(ip):
    """Simple check to ignore RFC1918 private space seen in your screenshot."""
    if not ip: return False
    if ip.startswith('10.'): return False
    if ip.startswith('192.168.'): return False
    if ip.startswith('172.') and 16 <= int(ip.split('.')[1]) <= 31: return False
    return True

def resolve_asns_via_ripestat(ip_list):
    """
    Resolves IPs to ASNs using RIPEstat API (No Team Cymru dependency).
    Returns: Dict { '1.2.3.4': 1234 }
    """
    mapping = {}
    unique_ips = list(set(ip for ip in ip_list if is_public_ip(ip)))
    
    print(f"    - Resolving {len(unique_ips)} unique public IPs via RIPEstat...")
    
    # RIPEstat doesn't support bulk lookups well, but it's fast.
    # We do serial requests here. For massive lists, we'd use async, 
    # but for a single traceroute (15 hops), this is fine.
    for i, ip in enumerate(unique_ips):
        try:
            resp = requests.get(f"{RIPE_STAT_URL}{ip}", timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                asns = data.get('data', {}).get('asns', [])
                if asns:
                    mapping[ip] = int(asns[0]) # Take primary ASN
            
            # Be polite to the API
            time.sleep(0.1)
        except Exception:
            pass
            
    return mapping

# ==============================================================================
# 2. RIPE ATLAS UTILS
# ==============================================================================
def resolve_target(domain):
    try: return socket.gethostbyname(domain)
    except: return None

def find_probes(asn):
    filters = {"asn_v4": asn, "status": 1}
    try: return [p["id"] for p in ProbeRequest(**filters)]
    except: return []

def create_trace_request(probe_ids, target_ip, description):
    # Only need 1 probe for a path check, but 3 gives redundancy
    subset = probe_ids[:3] 
    
    trace = Traceroute(
        af=4,
        target=target_ip,
        description=description,
        protocol="ICMP",
        is_oneoff=True,
        max_hops=25
    )
    
    source = AtlasSource(type="probes", value=",".join(map(str, subset)), requested=len(subset))
    
    request = AtlasCreateRequest(
        start_time=datetime.utcnow(),
        key=ATLAS_API_KEY,
        measurements=[trace],
        sources=[source],
        is_oneoff=True
    )
    
    (success, response) = request.create()
    return response["measurements"][0] if success else None

def get_trace_results(msm_id):
    print(f"    - Waiting for Trace {msm_id}...")
    for _ in range(24): # Wait 4 mins
        time.sleep(10)
        success, res = AtlasResultsRequest(msm_id=msm_id).create()
        if success and len(res) > 0: return res
    return []

# ==============================================================================
# 3. PATH ANALYZER
# ==============================================================================
def extract_path_ips(results):
    """Extracts IPs from the traceroute result."""
    if not results: return []
    
    # We aggregate all hops from all probes to get a full picture
    path_ips = []
    
    # Sort results by probe_id to keep it orderly
    for result in results:
        # result['result'] is the list of hops
        for hop in result.get('result', []):
            for packet in hop.get('result', []):
                if 'from' in packet:
                    path_ips.append(packet['from'])
                    # We take the first valid IP per hop per probe to keep it linear
                    break 
    return path_ips

# ==============================================================================
# 4. MAIN AUDIT
# ==============================================================================
def audit_path(target_asn, proxy_asn):
    if not ATLAS_API_KEY: print("[!] No API Key"); return

    print(f"[*] Path Audit: Target AS{target_asn} via Customer AS{proxy_asn}")
    
    # 1. Resolve
    ip_v, ip_i = resolve_target(DOMAIN_VALID), resolve_target(DOMAIN_INVALID)
    if not ip_v: print("[-] DNS Error"); return

    # 2. Find Probes
    probes = find_probes(proxy_asn)
    if not probes: print(f"[-] No probes in AS{proxy_asn}"); return
    print(f"    - Found {len(probes)} probes.")

    # 3. Trace
    print("    - Launching Traceroutes...")
    id_v = create_trace_request(probes, ip_v, f"RPKI Valid - AS{target_asn} via AS{proxy_asn}")
    id_i = create_trace_request(probes, ip_i, f"RPKI Invalid - AS{target_asn} via AS{proxy_asn}")
    
    if not id_v or not id_i: return

    print("    - Sleeping 45s for execution...")
    time.sleep(45)

    res_v = get_trace_results(id_v)
    res_i = get_trace_results(id_i)

    # 4. Process Hops
    ips_v = extract_path_ips(res_v)
    ips_i = extract_path_ips(res_i)

    # 5. Resolve ASNs (Native RIPEstat)
    all_ips = list(set(ips_v + ips_i))
    ip_map = resolve_asns_via_ripestat(all_ips)

    def to_as_path(ip_list):
        path = []
        prev = None
        for ip in ip_list:
            asn = ip_map.get(ip)
            if asn and asn != prev:
                path.append(asn)
                prev = asn
        return path

    as_path_v = to_as_path(ips_v)
    as_path_i = to_as_path(ips_i)

    # 6. Analyze
    reached_cf_v = CLOUDFLARE_ASN in as_path_v
    reached_cf_i = CLOUDFLARE_ASN in as_path_i
    
    # Did the valid path actually traverse the Target ASN?
    # Or did the Customer peer directly with Cloudflare/IXP?
    target_in_path = target_asn in as_path_v
    
    print("\n" + "="*60)
    print("PATH ANALYSIS RESULTS")
    print("="*60)
    print(f"Valid Path ASNs:   {as_path_v}")
    print(f"Invalid Path ASNs: {as_path_i}")
    print("-" * 60)

    verdict = "INCONCLUSIVE"
    notes = ""

    if target_asn != proxy_asn and not target_in_path:
        verdict = "INVALID TEST (Bypassed)"
        notes = f"Traffic bypassed AS{target_asn}. Likely direct peering."
    elif not reached_cf_v:
        verdict = "INCONCLUSIVE (Unreachable)"
        notes = "Valid path failed to reach Cloudflare."
    else:
        # Valid worked and went through target
        if reached_cf_i:
            verdict = "VULNERABLE (Leaking)"
            notes = f"AS{target_asn} forwarded invalid route to Cloudflare."
        else:
            verdict = "SECURE (Filtered)"
            # Find drop point
            last_asn = as_path_i[-1] if as_path_i else proxy_asn
            notes = f"Traffic died at AS{last_asn}"

    color = "\033[90m"
    if "SECURE" in verdict: color = "\033[92m"
    elif "VULNERABLE" in verdict: color = "\033[91m"
    elif "INVALID" in verdict: color = "\033[93m"
    
    print(f"{color}[*] VERDICT: {verdict}\033[0m")
    print(f"    Notes: {notes}")

    # 7. Save
    data = {
        "asn": target_asn,
        "proxy_asn": proxy_asn,
        "timestamp": datetime.utcnow().isoformat(),
        "verdict": verdict,
        "notes": notes,
        "valid_path": as_path_v,
        "invalid_path": as_path_i,
        "hop_details": ip_map
    }
    
    outfile = os.path.join(DIR_ATLAS, f"as_{target_asn}_via_{proxy_asn}_trace.json")
    with open(outfile, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"[+] Saved to {outfile}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("target_asn", type=int)
    parser.add_argument("--proxy-asn", type=int, required=True)
    args = parser.parse_args()
    audit_path(args.target_asn, args.proxy_asn)
