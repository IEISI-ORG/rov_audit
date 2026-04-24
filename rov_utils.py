import pandas as pd
import json
import os
import csv
import sys
import requests
import glob
import gzip
import time
import socket
import re
from collections import defaultdict, Counter
from io import StringIO, BytesIO

# --- SHARED CONFIGURATION ---
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'}

# Paths
DIR_DATA = "data"
DIR_PARSED = "data/parsed"
DIR_APNIC = "data/apnic"
DIR_ATLAS = "data/atlas"
DIR_APNIC_TS = "data/apnic/timeseries"
FILE_RELATIONSHIPS = "output/relationships.csv"
FILE_CONES = "final_as_rank.csv"
FILE_GRAPH = "data/downstream_graph.json"
FILE_AUDIT_FINAL = "rov_audit_v21_final.csv"
FILE_PACKED_ASN = "data/as_data.jsonl.gz"

# URLs
URL_ASNS_CSV = "https://bgp.tools/asns.csv"
# ... (rest of URLs)

# ... (other functions)

def load_all_asn_data() -> dict:
    """Load all ASN data from either packed JSONL or individual JSON files."""
    data = {}
    # 1. Try Packed File First (Fast)
    if os.path.exists(FILE_PACKED_ASN):
        print(f"    - Loading ASN data from packed file...", end=" ", flush=True)
        try:
            with gzip.open(FILE_PACKED_ASN, 'rt', encoding='utf-8') as f:
                for line in f:
                    d = json.loads(line)
                    data[d['asn']] = d
            print(f"OK ({len(data):,} records)")
            return data
        except Exception as e:
            print(f"FAIL ({e})")
    
    # 2. Fallback to individual files
    print(f"    - Loading ASN data from individual files...", end=" ", flush=True)
    files = glob.glob(os.path.join(DIR_PARSED, "as_*.json"))
    for f in files:
        try:
            with open(f, 'r') as h:
                d = json.load(h)
                data[d['asn']] = d
        except: pass
    print(f"OK ({len(data):,} records)")
    return data

URL_ROV_TAGS = "https://bgp.tools/tags/rpkirov.csv"
URL_CLOUDFLARE_CSV = "https://raw.githubusercontent.com/cloudflare/isbgpsafeyet.com/master/data/operators.csv"
URL_IPTOASN_V4 = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"
URL_IPTOASN_V6 = "https://iptoasn.com/data/ip2asn-v6.tsv.gz"
URL_APNIC_TS = "https://stats.labs.apnic.net/cgi-bin/rpki-json-table.pl"

# Tier 1 Definition (Authoritative List)
TIER_1_ASNS = {
    3356, 1299, 174, 2914, 3257, 6762, 6939, 6453, 3491, 1239, 701, 6461, 5511, 6830, 4637,
    7018, 3320, 12956, 1273, 7922, 209, 2828, 4134, 4809, 4837, 9929, 9808
}

# ASNs that are known to be secure but might be flagged due to testing (e.g., Cloudflare leaks invalids for testing)
HARDCODED_SECURE = {13335}

def ensure_dirs():
    """Ensure all required data directories exist."""
    for d in [DIR_DATA, DIR_PARSED, DIR_APNIC, DIR_ATLAS, DIR_APNIC_TS]:
        os.makedirs(d, exist_ok=True)

def fetch_csv(url: str, name: str) -> pd.DataFrame:
    """Fetch a CSV from a URL with standard headers."""
    print(f"    - Fetching {name}...", end=" ", flush=True)
    try:
        resp = requests.get(url, headers=HEADERS, timeout=30)
        resp.raise_for_status()
        print(f"OK ({len(resp.content)//1024} KB)")
        return pd.read_csv(StringIO(resp.text))
    except Exception as e:
        print(f"FAIL ({e})")
        return pd.DataFrame()

def fill_missing_cc_cymru(meta: dict) -> tuple[dict, int]:
    """Fallback: Uses Team Cymru Bulk Whois for ASNs that have no IP announcements."""
    missing_asns = []
    for asn, data in meta.items():
        if data.get('cc') == 'XX' or not data.get('cc'):
            json_path = os.path.join(DIR_PARSED, f"as_{asn}.json")
            if os.path.exists(json_path):
                try:
                    with open(json_path, 'r') as f:
                        local_d = json.load(f)
                    if local_d.get('cc') and local_d['cc'] != 'XX':
                        meta[asn]['cc'] = local_d['cc']
                        continue
                except: pass
            missing_asns.append(asn)

    if not missing_asns:
        return meta, 0

    print(f"    - Cymru Fallback: resolving {len(missing_asns)} ASNs...", end=" ", flush=True)
    fixed = 0
    chunk_size = 1000
    for i in range(0, len(missing_asns), chunk_size):
        chunk = missing_asns[i:i+chunk_size]
        query = "begin\nverbose\n" + "\n".join([f"AS{x}" for x in chunk]) + "\nend\n"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(15)
            s.connect(("whois.cymru.com", 43))
            s.sendall(query.encode('utf-8'))
            buffer = b""
            while True:
                data = s.recv(4096)
                if not data: break
                buffer += data
            s.close()
            
            for line in buffer.decode('utf-8', errors='ignore').splitlines():
                parts = [p.strip() for p in line.split('|')]
                if len(parts) >= 2 and parts[0].isdigit():
                    asn = int(parts[0])
                    cc = parts[1].upper()
                    if len(cc) == 2 and cc != "XX":
                        if asn in meta:
                            meta[asn]['cc'] = cc
                            fixed += 1
                            json_path = os.path.join(DIR_PARSED, f"as_{asn}.json")
                            file_data = {'asn': asn, 'cc': cc}
                            if os.path.exists(json_path):
                                try:
                                    with open(json_path, 'r') as f:
                                        file_data = json.load(f)
                                        file_data['cc'] = cc
                                except: pass
                            with open(json_path, 'w') as f:
                                json.dump(file_data, f, indent=2)
        except: pass
    print(f"Fixed {fixed}.")
    return meta, fixed

def load_metadata() -> tuple[dict, set]:
    """Load ASN names and countries from multiple sources."""
    print("[1] Loading Metadata & Geography...")
    meta = {}
    df = fetch_csv(URL_ASNS_CSV, "BGP.Tools ASN Names")
    if not df.empty:
        df.columns = [c.strip().lower() for c in df.columns]
        for _, row in df.iterrows():
            s = str(row.get('asn','')).upper().replace('AS','')
            if s.isdigit():
                meta[int(s)] = {'name': str(row.get('name','Unknown')), 'cc': 'XX'}

    asn_countries = defaultdict(list)
    for url, label in [(URL_IPTOASN_V4, "IPv4"), (URL_IPTOASN_V6, "IPv6")]:
        print(f"    - Fetching {label} Geo...", end=" ", flush=True)
        try:
            resp = requests.get(url, headers=HEADERS, timeout=30)
            with gzip.open(BytesIO(resp.content), 'rt') as f:
                count = 0
                for line in f:
                    parts = line.split('\t')
                    if len(parts) < 4: continue
                    asn_str, cc = parts[2], parts[3]
                    if asn_str.isdigit() and len(cc) == 2:
                        asn_countries[int(asn_str)].append(cc)
                        count += 1
                print(f"OK ({count:,} rows)")
        except: print("FAIL")

    for asn, ccs in asn_countries.items():
        primary_cc = Counter(ccs).most_common(1)[0][0].upper()
        if asn in meta: meta[asn]['cc'] = primary_cc
        else: meta[asn] = {'name': 'Unknown', 'cc': primary_cc}

    meta, _ = fill_missing_cc_cymru(meta)
    final_ccs = {d['cc'] for d in meta.values() if d['cc'] != 'XX'}
    print(f"    - Total ASNs: {len(meta):,}, Unique Countries: {len(final_ccs)}")
    return meta, final_ccs

def sync_apnic_data(countries: set, force: bool = False):
    """Sync APNIC RPKI scores for a set of countries."""
    print(f"[Sync] APNIC RPKI Data ({len(countries)} Countries)...")
    pattern = re.compile(r'>AS(\d+)<.*?\{v:\s*([\d\.]+)', re.IGNORECASE)
    updated, cached = 0, 0
    CACHE_TTL = 86400
    for cc in countries:
        file_path = os.path.join(DIR_APNIC, f"{cc}.json")
        if not force and os.path.exists(file_path):
            if (time.time() - os.path.getmtime(file_path)) < CACHE_TTL:
                cached += 1
                continue
        try:
            time.sleep(0.05)
            resp = requests.get(f"https://stats.labs.apnic.net/rpki/{cc}", headers=HEADERS, timeout=15)
            if resp.status_code == 200:
                scores = {}
                matches = pattern.findall(resp.text)
                for a, v in matches: scores[int(a)] = float(v)
                with open(file_path, 'w') as f: json.dump(scores, f)
                updated += 1
            else:
                with open(file_path, 'w') as f: json.dump({}, f)
        except: pass
    print(f"    - Result: {updated} Fetched, {cached} Cached.")

def _fetch_apnic_ts_rates(asn: int, cc: str) -> list[float]:
    """Fetch last 90 days of 7-day filter_rate for one ASN."""
    APNIC_TS_TTL = 86400 * 7
    cache = os.path.join(DIR_APNIC_TS, f"{asn}.json")
    if os.path.exists(cache) and (time.time() - os.path.getmtime(cache)) < APNIC_TS_TTL:
        try:
            with open(cache) as f: return json.load(f)
        except: pass
    try:
        resp = requests.get(f"{URL_APNIC_TS}?x={cc}{asn}", headers=HEADERS, timeout=15)
        if resp.status_code == 200:
            rows = resp.json().get('data', [])
            rates = [r['7']['filter_rate'] for r in rows if '7' in r]
            if rates:
                with open(cache, 'w') as f: json.dump(rates, f)
                return rates
    except: pass
    return []

def sync_apnic_timeseries(apnic_map: dict, meta: dict) -> dict:
    """Fetch 90-day time series. Returns {asn: (stdev, min90, max90, is_volatile)}."""
    import statistics
    APNIC_TS_SCORE_MIN = 60.0
    APNIC_VOLATILE_STDEV = 20.0
    APNIC_REGRESSION_THRESHOLD = 30.0 # Drop from max in 90 days

    # Candidates: High current score OR existing history we want to keep fresh
    candidates = {asn for asn, score in apnic_map.items() if score >= APNIC_TS_SCORE_MIN}
    for f in glob.glob(os.path.join(DIR_APNIC_TS, "*.json")):
        try:
            asn_str = os.path.basename(f).replace(".json", "")
            if asn_str.isdigit():
                candidates.add(int(asn_str))
        except: pass

    if not candidates: return {}
    print(f"[Sync] APNIC Time Series ({len(candidates)} ASNs)...")
    result, fetched = {}, 0
    for asn in candidates:
        cc = meta.get(asn, {}).get('cc', '')
        if not cc: continue
        rates = _fetch_apnic_ts_rates(asn, cc)
        if len(rates) < 14: continue
        
        # Current and 90-day window
        current = rates[-1]
        rates_90 = rates[-90:]
        sd = statistics.stdev(rates_90)
        mn90, mx90 = min(rates_90), max(rates_90)
        historical_max = max(rates)
        
        # Volatility & Regression Criteria
        crossed_threshold = (mx90 >= 95.0 and mn90 < 60.0)
        regression = (historical_max - current) > APNIC_REGRESSION_THRESHOLD
        is_volatile = (sd > APNIC_VOLATILE_STDEV or crossed_threshold or regression)
        
        result[asn] = (round(sd, 1), round(mn90, 1), round(mx90, 1), is_volatile, regression)
        fetched += 1
    print(f"    - Result: {fetched} Analysed, {len(candidates)-fetched} Skipped.")
    return result

def load_security_status() -> tuple[set, set, dict]:
    """Load ROV tags, Cloudflare safe list, and APNIC scores."""
    print("[2] Loading Security Data...")
    rov_set, cf_set = set(), set()
    df_rov = fetch_csv(URL_ROV_TAGS, "BGP.Tools ROV Tags")
    if not df_rov.empty:
        col = next((c for c in df_rov.columns if 'asn' in c.lower()), df_rov.columns[0])
        df_rov['x'] = df_rov[col].astype(str).str.upper().str.replace('AS','', regex=False)
        rov_set = set(df_rov[df_rov['x'].str.isnumeric()]['x'].astype(int))
    df_cf = fetch_csv(URL_CLOUDFLARE_CSV, "Cloudflare Safe List")
    if not df_cf.empty and 'asn' in df_cf.columns:
        for v in df_cf['asn']:
            if str(v).isdigit(): cf_set.add(int(v))
    apnic_map = {}
    for f in glob.glob(os.path.join(DIR_APNIC, "*.json")):
        try:
            with open(f) as h:
                for k,v in json.load(h).items(): apnic_map[int(k)] = v
        except: pass
    print(f"    - Security Data: {len(rov_set)} ROV Tags, {len(cf_set)} CF-Safe, {len(apnic_map)} APNIC scores")
    return rov_set, cf_set, apnic_map

def load_topology() -> tuple[dict, dict, dict]:
    """Load topology from Go output and build_topology JSON."""
    cones = {}
    if os.path.exists(FILE_CONES):
        print(f"    - Loading Cones from {FILE_CONES}...", end=" ", flush=True)
        df = pd.read_csv(FILE_CONES)
        asn_col = 'ASN' if 'ASN' in df.columns else 'asn'
        cone_col = 'Cone_Size' if 'Cone_Size' in df.columns else 'cone'
        if asn_col in df.columns and cone_col in df.columns:
            for _, row in df.iterrows():
                cones[int(row[asn_col])] = int(row[cone_col])
        print(f"OK ({len(cones)} ASNs)")
    downstream = {}
    if os.path.exists(FILE_GRAPH):
        print(f"    - Loading Graph from {FILE_GRAPH}...", end=" ", flush=True)
        with open(FILE_GRAPH, 'r') as f:
            downstream = {int(k): v for k, v in json.load(f).items()}
        print(f"OK")
    upstreams = defaultdict(set)
    for p, customers in downstream.items():
        for c in customers:
            upstreams[int(c)].add(int(p))
    return cones, downstream, upstreams

def load_atlas_verdicts() -> tuple[set, set, dict]:
    """Load RIPE Atlas active measurement results."""
    print("[3] Loading Atlas Verification Results...")
    secure, vulnerable, raw = set(), set(), {}
    for f in glob.glob(os.path.join(DIR_ATLAS, "*.json")):
        try:
            with open(f) as h:
                d = json.load(h)
            verdict = d.get('verdict', '')
            if not verdict: continue
            asn = d.get('asn')
            if asn is None:
                m = re.search(r'as_(\d+)', os.path.basename(f))
                if m: asn = int(m.group(1))
            if asn is None: continue
            asn = int(asn)
            raw[asn] = verdict
            if 'VULNERABLE' in verdict:
                vulnerable.add(asn)
                secure.discard(asn)
            elif 'SECURE' in verdict and asn not in vulnerable:
                secure.add(asn)
        except: pass
    print(f"    - Atlas Data: {len(secure)} Secure, {len(vulnerable)} Vulnerable")
    return secure, vulnerable, raw

def load_atlas_boundaries() -> dict:
    """
    Analyzes Atlas invalid paths to identify the 'Hard Boundary' ASNs 
    that are actively filtering. Returns a mapping of boundary_asn -> count of blocks.
    """
    print("[3.5] Analyzing Atlas Hard Boundaries...")
    boundaries = Counter()
    for f in glob.glob(os.path.join(DIR_ATLAS, "*.json")):
        try:
            with open(f) as h:
                d = json.load(h)
            
            # If it's SECURE and has an invalid path that died
            verdict = d.get('verdict', '')
            invalid_path = d.get('invalid_path', [])
            score_i = d.get('score_invalid', 100.0)
            
            if "SECURE" in verdict and score_i < 10.0 and invalid_path:
                # The last ASN in the invalid path is the one that dropped it (or passed it to a dropper)
                # But more accurately, if it died after AS-X, and AS-X is NOT the destination,
                # then AS-X or its immediate next hop is the boundary.
                last_hop = invalid_path[-1]
                boundaries[last_hop] += 1
        except: pass
    
    print(f"    - Found {len(boundaries)} filtering boundary ASNs via Atlas.")
    return dict(boundaries)

def load_signing_stats() -> dict:
    """Load ROA signing percentages from JSON cache."""
    data = load_all_asn_data()
    signing_data = {asn: d.get('roa_signed_pct', 0.0) for asn, d in data.items()}
    return signing_data

def calculate_cone_health(root_asn: int, downstream: dict, roa_map: dict) -> tuple[int, int]:
    """BFS to find unique downstream ASNs and count unsigned ones. Returns (unsigned, total)."""
    queue = [root_asn]
    seen = {root_asn}
    unsigned_customers, total_customers, idx = 0, 0, 0
    while idx < len(queue):
        curr = queue[idx]
        idx += 1
        children = downstream.get(curr, [])
        for child in children:
            if child not in seen:
                seen.add(child)
                queue.append(child)
                total_customers += 1
                if roa_map.get(child, 0.0) < 10.0:
                    unsigned_customers += 1
    return unsigned_customers, total_customers

def load_upstreams_from_cache(target_asns: list) -> Counter:
    """Read local JSON files for target ASNs to find who feeds them."""
    dependencies = Counter()
    for asn in target_asns:
        json_path = os.path.join(DIR_PARSED, f"as_{asn}.json")
        if os.path.exists(json_path):
            try:
                with open(json_path, 'r') as f:
                    data = json.load(f)
                    upstreams = data.get('upstreams', [])
                    for u in upstreams:
                        dependencies[int(u)] += 1
            except: pass
    return dependencies

def classify_verdict(verdict: str) -> str:
    """Categorize a verdict string into high-level status."""
    v = str(verdict).upper()
    # Regressions and Unreliable states are always treated as VULNERABLE
    if any(x in v for x in ["(REG)", "REGRESSED", "UNRELIABLE", "UNPROT"]):
        return "VULNERABLE"
    if any(x in v for x in ["ACTIVE", "PASSIVE", "PROTECTOR", "VOLATILE"]):
        return "SECURE"
    if "PARTIAL" in v:
        return "PARTIAL"
    if any(x in v for x in ["VULNERABLE", "VULN"]):
        return "VULNERABLE"
    return "UNKNOWN"

def is_secure(verdict: str) -> bool:
    return classify_verdict(verdict) == "SECURE"

def is_vulnerable(verdict: str) -> bool:
    return classify_verdict(verdict) == "VULNERABLE"

def is_partial(verdict: str) -> bool:
    return classify_verdict(verdict) == "PARTIAL"

def assign_verdict(asn: int, is_safe: bool, cone: int, parents: list, dirty_feeds: int, volatile: bool, atlas_v: str = "") -> str:
    """Standardized logic for assigning safety verdicts."""
    if asn in HARDCODED_SECURE:
        return "ACTIVE LOCAL ROV (Hardcoded)"
    if asn in TIER_1_ASNS:
        return "CORE: ACTIVE PROTECTOR" if is_safe else "CORE: UNPROTECTED"
    if atlas_v:
        if 'VULNERABLE' in atlas_v: return "VULNERABLE (Atlas Verified)"
        if 'SECURE' in atlas_v: return "ACTIVE (Atlas Verified)"
    if not parents:
        return "Unverified (Transit/Peer?)" if cone > 0 else "NOT ROUTED"
    total_feeds = len(parents)
    if cone == 0: # STUB
        if dirty_feeds == 0:
            if not is_safe:
                return "STUB: PASSIVE (Clean Pipe)"
            return "STUB: VOLATILE" if volatile else "STUB: ACTIVE LOCAL ROV"
        elif is_safe:
            return "STUB: VOLATILE"
        else:
            return "STUB: UNRELIABLE" if volatile else "STUB: VULNERABLE"
    else: # TRANSIT
        if dirty_feeds == 0:
            if not is_safe:
                return "PASSIVE (Clean Pipe)"
            return "VOLATILE" if volatile else "ACTIVE LOCAL ROV"
        elif dirty_feeds < total_feeds:
            return "PARTIAL: VULNERABLE (Mixed)"
        elif is_safe:
            return "VOLATILE" 
        else:
            return "UNRELIABLE" if volatile else "VULNERABLE"
    return "Unknown"
