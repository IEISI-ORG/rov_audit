import pandas as pd
import json
import os
import csv
import sys
import requests
import glob
import gzip
import time
import re
import socket
from collections import defaultdict, Counter
from io import StringIO, BytesIO

# --- CONFIGURATION ---
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'}

# Inputs
FILE_GO_RELATIONSHIPS = "output/relationships.csv"
DIR_APNIC = "data/apnic"
DIR_ATLAS = "data/atlas"
DIR_APNIC_TS = "data/apnic/timeseries"
os.makedirs(DIR_APNIC, exist_ok=True)
os.makedirs(DIR_APNIC_TS, exist_ok=True)

# Volatility detection: fetch 90 days of the 7-day sliding window per ASN.
# An ASN is flagged volatile if stdev > 20 pp OR the range crosses the 95% threshold
# in either direction (peaked above then crashed, or is climbing toward it).
APNIC_TS_TTL = 86400 * 7          # re-fetch time series weekly
APNIC_TS_SCORE_MIN = 60.0          # only fetch TS for ASNs scoring >= this
APNIC_VOLATILE_STDEV = 20.0        # stdev threshold (percentage points over 90 days)
URL_APNIC_TS = "https://stats.labs.apnic.net/cgi-bin/rpki-json-table.pl"

# URLs
URL_ASNS_CSV = "https://bgp.tools/asns.csv"
URL_ROV_TAGS = "https://bgp.tools/tags/rpkirov.csv"
URL_CLOUDFLARE_CSV = "https://raw.githubusercontent.com/cloudflare/isbgpsafeyet.com/master/data/operators.csv"
URL_IPTOASN_V4 = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"
URL_IPTOASN_V6 = "https://iptoasn.com/data/ip2asn-v6.tsv.gz"

# Tier 1 Definition
TIER_1_FIREWALL = {
    3356, 1299, 174, 2914, 3257, 6762, 6939, 6453, 3491, 1239, 701, 6461, 5511, 6830, 4637,
    7018, 3320, 12956, 1273, 7922, 209, 2828, 4134, 4809, 4837, 9929, 9808
}

def fetch_csv(url, name):
    print(f"    - Fetching {name}...", end=" ")
    try:
        resp = requests.get(url, headers=HEADERS)
        resp.raise_for_status()
        print(f"OK ({len(resp.content)//1024} KB)")
        return pd.read_csv(StringIO(resp.text))
    except Exception as e:
        print(f"FAIL ({e})")
        return pd.DataFrame()

# ==============================================================================
# 1. METADATA & GEO (TRIPLE SOURCE)
# ==============================================================================

def fill_missing_cc_cymru(meta):
    """
    Fallback: Uses Team Cymru Bulk Whois for ASNs that have no IP announcements.
    UPDATED: Now caches the result to data/parsed/as_XXXX.json to prevent re-querying.
    """
    # 1. Identify targets (XX in meta)
    # Optimization: Check if we ALREADY have a CC in the local JSON cache that meta missed
    # (This happens if you ran this script previously)
    missing_asns = []
    
    for asn, data in meta.items():
        if data['cc'] == 'XX':
            # Check local JSON first
            json_path = os.path.join("data/parsed", f"as_{asn}.json")
            if os.path.exists(json_path):
                try:
                    with open(json_path, 'r') as f:
                        local_d = json.load(f)
                    if local_d.get('cc') and local_d['cc'] != 'XX':
                        # Cache Hit! Use it.
                        meta[asn]['cc'] = local_d['cc']
                        continue
                except: pass
            
            # Still missing? Add to query list.
            missing_asns.append(asn)

    if not missing_asns: 
        return meta, 0

    print(f"    - Cymru Fallback: resolving {len(missing_asns)} 'XX' ASNs...", end=" ")
    
    # Chunking (1000 per request)
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
            
            # Parse & Cache
            for line in buffer.decode('utf-8', errors='ignore').splitlines():
                parts = [p.strip() for p in line.split('|')]
                if len(parts) >= 2 and parts[0].isdigit():
                    asn = int(parts[0])
                    cc = parts[1].upper()
                    
                    if len(cc) == 2 and cc != "XX":
                        if asn in meta:
                            meta[asn]['cc'] = cc
                            fixed += 1
                            
                            # --- CACHE WRITE START ---
                            # Save to JSON so we don't query this again next run
                            json_path = os.path.join("data/parsed", f"as_{asn}.json")
                            file_data = {'asn': asn} # Default
                            
                            if os.path.exists(json_path):
                                try:
                                    with open(json_path, 'r') as f:
                                        file_data = json.load(f)
                                except: pass
                            
                            file_data['cc'] = cc
                            
                            try:
                                with open(json_path, 'w') as f:
                                    json.dump(file_data, f, indent=2)
                            except: pass
                            # --- CACHE WRITE END ---

        except Exception as e:
            # print(f"Cymru Error: {e}") 
            pass
    
    print(f"Fixed {fixed} entries (Saved to JSON).")
    return meta, fixed

def load_metadata():
    print("[1/6] Loading Metadata & Geography...")
    meta = {}

    # A. Names
    df = fetch_csv(URL_ASNS_CSV, "BGP.Tools ASN Names")
    if not df.empty:
        df.columns = [c.strip().lower() for c in df.columns]
        for _, row in df.iterrows():
            s = str(row.get('asn','')).upper().replace('AS','')
            if s.isdigit():
                meta[int(s)] = {'name': str(row.get('name','Unknown')), 'cc': 'XX'}

    # B. Countries (IPtoASN - Primary Source)
    asn_countries = defaultdict(list)
    for url, label in [(URL_IPTOASN_V4, "IPv4"), (URL_IPTOASN_V6, "IPv6")]:
        print(f"    - Fetching {label} Geo...", end=" ")
        try:
            resp = requests.get(url, headers=HEADERS)
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

    # Apply IPtoASN
    unique_ccs = set()
    for asn, ccs in asn_countries.items():
        primary_cc = Counter(ccs).most_common(1)[0][0].upper()
        unique_ccs.add(primary_cc)
        if asn in meta: meta[asn]['cc'] = primary_cc
        else: meta[asn] = {'name': 'Unknown', 'cc': primary_cc}

    # C. Countries (Cymru - The Cleanup)
    meta, fixed_count = fill_missing_cc_cymru(meta)
    
    # Collect final list of countries for APNIC Sync
    final_ccs = set(d['cc'] for d in meta.values() if d['cc'] != 'XX')
    print(f"    - Final Geo-Map: {len(final_ccs)} Countries.")
    
    return meta, final_ccs

# ==============================================================================
# 2. APNIC SYNC + VOLATILITY
# ==============================================================================
def _fetch_apnic_ts_rates(asn, cc):
    """Fetch last 90 days of 7-day filter_rate for one ASN. Cached APNIC_TS_TTL."""
    cache = os.path.join(DIR_APNIC_TS, f"{asn}.json")
    if os.path.exists(cache) and (time.time() - os.path.getmtime(cache)) < APNIC_TS_TTL:
        with open(cache) as f:
            return json.load(f)
    try:
        resp = requests.get(f"{URL_APNIC_TS}?x={cc}{asn}", headers=HEADERS, timeout=10)
        if resp.status_code == 200:
            rows = resp.json().get('data', [])
            rates = [r['7']['filter_rate'] for r in rows[-90:] if '7' in r]
            with open(cache, 'w') as f:
                json.dump(rates, f)
            return rates
    except:
        pass
    return []

def sync_apnic_timeseries(apnic_map, meta):
    """Fetch 90-day time series for ASNs scoring >= APNIC_TS_SCORE_MIN.
    Returns {asn: (stdev, min90, max90, is_volatile)}."""
    import statistics
    candidates = {asn for asn, score in apnic_map.items() if score >= APNIC_TS_SCORE_MIN}
    if not candidates:
        return {}
    print(f"[2b/6] Syncing APNIC Time Series ({len(candidates)} ASNs >= {APNIC_TS_SCORE_MIN:.0f}%)...")
    result, fetched = {}, 0
    for asn in candidates:
        cc = meta.get(asn, {}).get('cc', '')
        if not cc:
            continue
        rates = _fetch_apnic_ts_rates(asn, cc)
        if len(rates) < 14:
            continue
        sd = statistics.stdev(rates)
        mn, mx = min(rates), max(rates)
        # Volatile if stdev exceeds threshold OR score crossed 95% boundary in either direction
        crossed_threshold = (mx >= 95.0 and mn < 60.0)
        result[asn] = (round(sd, 1), round(mn, 1), round(mx, 1), sd > APNIC_VOLATILE_STDEV or crossed_threshold)
        fetched += 1
    cached = len(candidates) - fetched
    print(f"    - Time Series: {fetched} Fetched/Computed, {cached} Cached/Skipped")
    return result

def sync_apnic_data(countries):
    print(f"[2/6] Syncing APNIC RPKI Data ({len(countries)} Countries)...")
    pattern = re.compile(r'>AS(\d+)<.*?\{v:\s*([\d\.]+)', re.IGNORECASE)
    updated, cached = 0, 0
    
    # Cache Check Logic
    CACHE_TTL = 86400
    
    for cc in countries:
        file_path = os.path.join(DIR_APNIC, f"{cc}.json")
        if os.path.exists(file_path):
            if (time.time() - os.path.getmtime(file_path)) < CACHE_TTL:
                cached += 1
                continue
        
        try:
            time.sleep(0.1)
            resp = requests.get(f"https://stats.labs.apnic.net/rpki/{cc}", headers=HEADERS, timeout=10)
            if resp.status_code == 200:
                scores = {}
                matches = pattern.findall(resp.text)
                for a, v in matches: scores[int(a)] = float(v)
                if scores:
                    with open(file_path, 'w') as f: json.dump(scores, f)
                    updated += 1
            else:
                with open(file_path, 'w') as f: json.dump({}, f)
        except: pass
    print(f"    - Sync: {updated} Fetched, {cached} Cached.")

def load_security_status():
    print("[3/6] Loading Security Data...")
    rov_set, cf_set = set(), set()
    
    # BGP Tools
    df = fetch_csv(URL_ROV_TAGS, "ROV Tags")
    if not df.empty:
        col = next((c for c in df.columns if 'asn' in c.lower()), df.columns[0])
        df['x'] = df[col].astype(str).str.upper().str.replace('AS','', regex=False)
        rov_set = set(df[df['x'].str.isnumeric()]['x'].astype(int))

    # Cloudflare
    df_cf = fetch_csv(URL_CLOUDFLARE_CSV, "Cloudflare List")
    if not df_cf.empty and 'asn' in df_cf.columns:
        for v in df_cf['asn']:
            if str(v).isdigit(): cf_set.add(int(v))

    # APNIC
    apnic_map = {}
    for f in glob.glob(os.path.join(DIR_APNIC, "*.json")):
        try:
            with open(f) as h:
                for k,v in json.load(h).items(): apnic_map[int(k)] = v
        except: pass
    
    print(f"    - Loaded: {len(rov_set)} Tagged, {len(cf_set)} CF-Safe, {len(apnic_map)} APNIC")
    return rov_set, cf_set, apnic_map

# ==============================================================================
# 3. TOPOLOGY
# ==============================================================================
def build_topology_from_go():
    print("[4/6] Building Topology (RIS)...")
    if not os.path.exists(FILE_GO_RELATIONSHIPS):
        print(f"[!] Error: {FILE_GO_RELATIONSHIPS} not found."); sys.exit(1)

    adj = defaultdict(set)
    with open(FILE_GO_RELATIONSHIPS, 'r') as f:
        reader = csv.reader(f)
        next(reader, None)
        for row in reader:
            if len(row) < 3: continue
            adj[int(row[0])].add(int(row[1]))
            adj[int(row[1])].add(int(row[0]))
    
    degrees = {k: len(v) for k,v in adj.items()}
    upstream_map = defaultdict(set)
    downstream_map = defaultdict(set)
    
    with open(FILE_GO_RELATIONSHIPS, 'r') as f:
        reader = csv.reader(f)
        next(reader, None)
        seen = set()
        for row in reader:
            if len(row) < 3: continue
            as1, as2 = int(row[0]), int(row[1])
            pair = tuple(sorted((as1, as2)))
            if pair in seen: continue
            seen.add(pair)

            d1, d2 = degrees[as1], degrees[as2]
            provider, customer = None, None
            if d1 > d2 * 4.0: provider, customer = as1, as2
            elif d2 > d1 * 4.0: provider, customer = as2, as1
            
            if customer in TIER_1_FIREWALL: continue
            if provider:
                upstream_map[customer].add(provider)
                downstream_map[provider].add(customer)

    return upstream_map, downstream_map

def calculate_cones(downstream_map):
    print("[5/6] Calculating Cone Sizes...")
    cone_sizes = {}
    memo = {}
    def get_cone(asn):
        if asn in memo: return memo[asn]
        c = set()
        for child in downstream_map.get(asn, []):
            c.add(child)
            c.update(get_cone(child))
        memo[asn] = c
        return c
    for asn in downstream_map: cone_sizes[asn] = len(get_cone(asn))
    return cone_sizes

# ==============================================================================
# 3b. ATLAS VERIFICATION (highest-priority data source)
# ==============================================================================
def load_atlas_verdicts():
    """Load RIPE Atlas active measurement results. These override all passive sources."""
    print("[*] Loading Atlas Verification Results...")
    secure, vulnerable, raw = set(), set(), {}
    for f in glob.glob(os.path.join(DIR_ATLAS, "*.json")):
        try:
            with open(f) as h:
                d = json.load(h)
            verdict = d.get('verdict', '')
            if not verdict:
                continue
            asn = d.get('asn')
            if asn is None:
                m = re.search(r'as_(\d+)', os.path.basename(f))
                if m:
                    asn = int(m.group(1))
            if asn is None:
                continue
            asn = int(asn)
            raw[asn] = verdict
            if 'VULNERABLE' in verdict:
                vulnerable.add(asn)
                secure.discard(asn)
            elif 'SECURE' in verdict and asn not in vulnerable:
                secure.add(asn)
        except:
            pass
    print(f"    - Loaded: {len(secure)} Atlas-Secure, {len(vulnerable)} Atlas-Vulnerable")
    return secure, vulnerable, raw

# ==============================================================================
# 4. AUDIT
# ==============================================================================
def analyze():
    meta, countries = load_metadata()
    sync_apnic_data(countries)
    rov_set, cf_set, apnic_map = load_security_status()
    atlas_secure, atlas_vulnerable, atlas_raw = load_atlas_verdicts()
    ts_map = sync_apnic_timeseries(apnic_map, meta)  # {asn: (stdev, min90, max90, volatile)}
    upstreams, downstreams = build_topology_from_go()
    cones = calculate_cones(downstreams)

    print("[6/6] Generating Audit...")
    results = []

    all_asns = set(meta.keys()) | set(cones.keys()) | set(upstreams.keys())
    safe_asns = set()
    for asn in all_asns:
        if (asn in rov_set) or (asn in cf_set) or (apnic_map.get(asn, -1) >= 95.0):
            safe_asns.add(asn)

    # Atlas overrides passive sources — apply after passive safe_asns is built
    safe_asns -= atlas_vulnerable
    safe_asns |= atlas_secure

    # Volatile APNIC-only networks: if not backed by bgp.tools tag or Cloudflare,
    # remove from safe_asns — a score that swings wildly cannot be trusted
    for asn, (sd, mn, mx, volatile) in ts_map.items():
        if volatile and asn in safe_asns and asn not in rov_set and asn not in cf_set:
            safe_asns.discard(asn)

    stats = {'stub': 0, 'unrouted': 0}

    for asn in all_asns:
        name = meta.get(asn, {}).get('name', 'Unknown')
        cc = meta.get(asn, {}).get('cc', 'XX')
        cone = cones.get(asn, 0)
        parents = upstreams.get(asn, [])
        score = apnic_map.get(asn, -1)
        is_safe = asn in safe_asns
        
        verdict = "Unknown"
        dirty_ups = 0

        ts = ts_map.get(asn)
        apnic_stdev       = ts[0] if ts else -1.0
        apnic_min90       = ts[1] if ts else -1.0
        apnic_max90       = ts[2] if ts else -1.0
        volatile          = ts[3] if ts else False

        if asn in TIER_1_FIREWALL:
            verdict = "CORE: PROTECTED" if is_safe else "CORE: UNPROTECTED"
        elif not parents:
            if cone > 0: verdict = "Unverified (Transit/Peer?)"
            else:
                verdict = "NOT ROUTED"
                stats['unrouted'] += 1
        else:
            dirty_ups = sum(1 for p in parents if p not in safe_asns)
            total = len(parents)

            if cone == 0:
                stats['stub'] += 1
                if dirty_ups == 0:
                    verdict = "STUB: SECURE UNSTABLE" if volatile else "STUB: SECURE STABLE"
                elif is_safe:
                    verdict = "STUB: SECURE UNSTABLE"
                else:
                    verdict = "STUB: VULNERABLE UNSTABLE" if volatile else "STUB: VULNERABLE STABLE"
            else:
                if dirty_ups == 0:
                    verdict = "SECURE UNSTABLE" if volatile else "SECURE STABLE"
                elif dirty_ups < total:
                    verdict = "VULNERABLE UNSTABLE"        # mixed feeds — ambiguous by definition
                elif is_safe:
                    verdict = "SECURE UNSTABLE"            # tagged safe but unverified locally
                else:
                    verdict = "VULNERABLE UNSTABLE" if volatile else "VULNERABLE STABLE"

        # Atlas always wins — active measurement overrides all passive verdicts.
        # "Verified ROV" is reserved exclusively for Atlas-confirmed ROV.
        atlas_v = atlas_raw.get(asn)
        if atlas_v:
            if 'VULNERABLE' in atlas_v:
                verdict = "VULNERABLE (Atlas Verified)"
            elif 'SECURE' in atlas_v:
                verdict = "SECURE (Verified ROV)"

        results.append({
            'asn': asn, 'name': name, 'cc': cc, 'cone': cone,
            'verdict': verdict, 'apnic_score': score,
            'dirty_feeds': dirty_ups, 'total_feeds': len(parents),
            'atlas_verdict': atlas_v or '',
            'apnic_stdev': apnic_stdev, 'apnic_min90': apnic_min90, 'apnic_max90': apnic_max90,
        })

    df = pd.DataFrame(results)
    
    print("\n" + "="*80)
    print("NO-SCRAPE GLOBAL AUDIT (V20 - CC FIXED)")
    print("="*80)
    
    q_vuln_transit = len(df[df['verdict'] == "VULNERABLE (No Coverage)"])
    print(f"Total Networks:          {len(df):,}")
    print(f"Vulnerable Providers:    {q_vuln_transit:,}")
    print(f"ASNs Fixed via Cymru:    (See log above)")
    
    filename = "rov_audit_v20_final.csv"
    df.sort_values(by='cone', ascending=False).to_csv(filename, index=False)
    print(f"\n[+] Saved to {filename}")

if __name__ == "__main__":
    analyze()
