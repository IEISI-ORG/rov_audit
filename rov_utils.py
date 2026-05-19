import pandas as pd
import json
import os
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
DIR_TAGS = "data/tags"
DIR_RRC = "output"          # parent dir; each collector writes to output/rrcNN/
FILE_RELATIONSHIPS = "output/relationships.csv"   # legacy single-collector path
FILE_CONES = "final_as_rank.csv"

# RIPE RIS Route Collectors used for multi-vantage topology inference.
#
# Selection rationale (2026-04-26):
#   rrc00  Amsterdam    RIPE-NCC Multihop  114 peers  — primary (legacy), EU bias
#   rrc14  Palo Alto    PAIX                23 peers  — North America West Coast
#   rrc19  Johannesburg NAP Africa JB       71 peers  — Africa
#   rrc23  Singapore    Equinix SG          65 peers  — Asia-Pacific
#   rrc24  Montevideo   LACNIC Multihop     29 peers  — South America / LACNIC
#
# Four distinct regions (EU, NA, AF, APAC, AMER) — dropping the second EU
# collector (rrc12/DE-CIX) in favour of NA and Africa gives better geographic
# spread for cross-regional consensus.
#
# A provider-customer link confirmed in ≥2 distinct regions is treated as real
# transit (4× ratio).  A link seen in only 1 region is suspect IXP peering (8×).
#
# Add collectors here to increase coverage; remove to reduce download size.
# Must stay in sync with RRCS= in do_data_gathering.
RRC_COLLECTORS: dict[str, dict] = {
    "rrc00": {"region": "EU",   "location": "Amsterdam",    "type": "multihop"},
    "rrc14": {"region": "NA",   "location": "Palo Alto",    "type": "ixp",  "ixp": "PAIX"},
    "rrc19": {"region": "AF",   "location": "Johannesburg", "type": "ixp",  "ixp": "NAP Africa JB"},
    "rrc23": {"region": "APAC", "location": "Singapore",    "type": "ixp",  "ixp": "Equinix SG"},
    "rrc24": {"region": "AMER", "location": "Montevideo",   "type": "multihop"},
}

# Minimum number of DISTINCT REGIONS that must see a link before it is treated
# as confirmed transit.  1 = any single collector suffices (current behaviour);
# 2 = must appear at both a European and at least one non-European collector.
RRC_CONFIRM_REGIONS = 2

# Stricter degree ratio applied to single-region links (suspect IXP peering).
# Normal ratio is PROVIDER_RATIO (4×); single-region links need 8× evidence.
RRC_SINGLE_REGION_RATIO = 8.0
FILE_GRAPH = "data/downstream_graph.json"
FILE_AUDIT_FINAL = "rov_audit_v22_final.csv"
FILE_PACKED_ASN = "data/as_data.jsonl.gz"

# URLs
# bgp.tools API docs: https://bgp.tools/kb/api
# User-Agent required; bulk tag CSVs at /tags/<tag>.csv; full table at /table.jsonl
URL_ASNS_CSV = "https://bgp.tools/asns.csv"
# ... (rest of URLs)

# bgp.tools classification tags — all available at https://bgp.tools/tags/<key>.csv
# Each CSV has format: AS<number>,Organization Name
# 7-day TTL applies; cached under data/tags/
BGPTOOLS_TAGS: dict[str, str] = {
    "cdn":     "CDN",                    # Content delivery networks (non-transit context)
    "ddosm":   "DDoS Mitigation",        # Scrubbing / DDoS protection providers
    "gov":     "Government",             # Government / defence networks
    "uni":     "University/Research",    # Academic and research networks
    "mobile":  "Mobile Operator",        # Cellular / mobile carriers
    "corp":    "Corporate",              # Enterprise stub networks
    "anycast": "Anycast Service",        # Anycast infrastructure (DNS, etc.)
    "vpn":     "VPN Provider",           # Commercial VPN services
    "icrit":   "Internet Critical Infra",# NICs, root servers, IXP-adjacent
    "tor":     "Tor Exit",               # Tor exit nodes
    "vpsh":    "VPS Hosting",            # Virtual private server / hosting
    "satnet":  "Satellite Network",      # Satellite broadband
    "dsl":     "DSL/Broadband",          # Residential broadband providers
    "biznet":  "Business ISP",           # Business-focused ISPs
    "perso":   "Personal/Hobbyist",      # Personal ASNs (BGP experimenters)
}

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

# ===========================================================================
# AUTHORITATIVE CLASSIFICATION CONSTANTS
# These are the single source of truth for both Python scripts and Go tools.
# The Go equivalents live in constants.go (isTier1 / isNonTransit).
# The sync test in tests/test_gao_rexford.py will fail if they diverge.
# ===========================================================================

# Networks that are never a customer of anyone else (valley-free topology peaks).
# Verified 2026-04-26: all confirmed to have zero providers in downstream_graph.json.
# Removed AS1239 (Sprint/Cogent legacy — 0 direct customers, cone=302)
# Removed AS2828 (Verizon Business/MCI legacy — 0 direct customers, cone=4812)
TIER_1_ASNS: set[int] = {
    3356, 1299, 174, 2914, 3257, 6762, 6939, 6453, 3491, 701, 6461, 5511, 6830, 4637,
    7018, 3320, 12956, 1273, 7922, 209, 4134, 4809, 4837, 9929, 9808
}

# ASNs excluded from provider-customer inference in the topology builder.
# Includes DNS root servers (sourced from bgp.tools icrit tag, 2026-04-26),
# RIRs, IXP route servers, and anycast/CDN infrastructure.
# WARNING: do NOT add CDN-tagged ASNs in bulk — some CDNs (e.g. OVH AS16276)
# also sell BGP transit and must NOT be excluded.
# Go equivalent: isNonTransit() in constants.go
NON_TRANSIT_ASNS: set[int] = {
    213241,  # TECHIT.BE — IXP Route Server
    13335,   # Cloudflare — CDN/Anycast (non-transit for topology)
    3333,    # RIPE NCC
    4608,    # APNIC (refuses ROV to avoid member lockout)
    4777,    # APNIC (refuses ROV to avoid member lockout)
    394353,  # USC/ISI — B-Root
    2149,    # Cogent Communications — C-Root
    10886,   # University of Maryland — D-Root
    21556,   # NASA Ames Research Center — E-Root
    3557,    # ISC — F-Root
    5927,    # US Dept of Defense — G-Root
    1508,    # US Army Research Lab — H-Root
    29216,   # Netnod — I-Root
    26415,   # VeriSign — A-Root & J-Root
    25152,   # RIPE NCC — K-Root
    20144,   # ICANN — L-Root
    7500,    # WIDE Project — M-Root
    112,     # AS112 Project — RFC 7534 blackhole for private PTR
}

# Minimum degree ratio for provider-customer inference (must match PROVIDER_RATIO in constants.go).
PROVIDER_RATIO: float = 4.0

# AS13335 (Cloudflare) deliberately accepts RPKI-invalid routes on test infrastructure
# so researchers can verify their ROV posture. Hardcoding prevents false VULNERABLE verdicts.
HARDCODED_SECURE: set[int] = {13335}

def ensure_dirs():
    """Ensure all required data directories exist."""
    for d in [DIR_DATA, DIR_PARSED, DIR_APNIC, DIR_ATLAS, DIR_APNIC_TS, DIR_TAGS]:
        os.makedirs(d, exist_ok=True)


def fetch_bgp_tools_tags(force: bool = False) -> dict[int, list[str]]:
    """
    Download classification tags from bgp.tools and return {asn: [tag, ...]}.

    Each tag CSV has format: AS<number>,Organization Name
    Results are cached under data/tags/ with a 7-day TTL.
    On network failure, stale cache is used silently.

    Available tags and their meaning are in BGPTOOLS_TAGS.
    Note: tags are classification labels only — do NOT use cdn/ddosm to auto-expand
    IS_NON_TRANSIT without manual review, since some CDNs (e.g. OVH AS16276)
    also sell BGP transit.
    """
    os.makedirs(DIR_TAGS, exist_ok=True)
    CACHE_TTL = 86400 * 7
    tag_map: dict[int, list[str]] = defaultdict(list)

    print(f"[Tags] Fetching {len(BGPTOOLS_TAGS)} bgp.tools classification tags...")
    fetched, cached, failed = 0, 0, 0

    for tag in BGPTOOLS_TAGS:
        cache_path = os.path.join(DIR_TAGS, f"{tag}.csv")
        use_cache = (
            not force
            and os.path.exists(cache_path)
            and (time.time() - os.path.getmtime(cache_path)) < CACHE_TTL
        )

        raw_lines: list[str] = []

        if use_cache:
            with open(cache_path) as fh:
                raw_lines = fh.readlines()
            cached += 1
        else:
            url = f"https://bgp.tools/tags/{tag}.csv"
            try:
                resp = requests.get(url, headers=HEADERS, timeout=30)
                resp.raise_for_status()
                raw_lines = resp.text.splitlines()
                with open(cache_path, "w") as fh:
                    fh.write(resp.text)
                fetched += 1
            except Exception:
                failed += 1
                if os.path.exists(cache_path):
                    with open(cache_path) as fh:
                        raw_lines = fh.readlines()

        for line in raw_lines:
            line = line.strip()
            if not line or not line.upper().startswith("AS"):
                continue
            asn_str = line.split(",")[0][2:]  # strip "AS" prefix
            try:
                tag_map[int(asn_str)].append(tag)
            except ValueError:
                pass

    total_assignments = sum(len(v) for v in tag_map.values())
    print(
        f"    - Tags: {fetched} fetched, {cached} cached, {failed} failed | "
        f"{total_assignments:,} assignments across {len(tag_map):,} ASNs"
    )
    return dict(tag_map)

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
    CACHE_TTL = 86400 * 7 # 7-day TTL
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

APNIC_MIN_SAMPLES = 30           # minimum seen+filtered for a valid daily rate
APNIC_REGRESSION_CURRENT_MIN_SAMPLES = 100  # minimum n for 'current' in regression detection

def _fetch_apnic_ts_rates(asn: int, cc: str) -> list:
    """Fetch full timeseries for one ASN.

    Returns list of [rate, samples] pairs, one per calendar day.
    rate is None when no window has sufficient samples (network too sparse).

    Window selection per day (shortest window with >= APNIC_MIN_SAMPLES):
      7-day  → best temporal resolution, but sparse for small networks
      14-day → fallback
      28-day → fallback
      112-day → last resort
    Old-format caches (plain floats, no sample counts) are re-fetched on
    next TTL expiry; until then they are returned as-is in legacy mode.
    """
    APNIC_TS_TTL = 86400 * 7
    cache = os.path.join(DIR_APNIC_TS, f"{asn}.json")
    if os.path.exists(cache) and (time.time() - os.path.getmtime(cache)) < APNIC_TS_TTL:
        try:
            with open(cache) as f:
                data = json.load(f)
            if data and isinstance(data[0], list):
                return data          # new format: [[rate, samples], ...]
            if data and isinstance(data[0], (int, float)):
                return data          # old format: [float, ...] — caller detects via isinstance
        except: pass
    try:
        resp = requests.get(f"{URL_APNIC_TS}?x={cc}{asn}", headers=HEADERS, timeout=15)
        if resp.status_code == 200:
            rows = resp.json().get('data', [])
            result = []
            for r in rows:
                chosen_rate, chosen_n = None, 0
                for window in ('7', '14', '28', '112'):
                    w = r.get(window)
                    if not w:
                        continue
                    n = w['seen'] + w['filtered']
                    if n >= APNIC_MIN_SAMPLES:
                        chosen_rate, chosen_n = w['filter_rate'], n
                        break
                result.append([chosen_rate, chosen_n])
            valid = [x for x in result if x[0] is not None]
            if len(valid) >= 14:
                with open(cache, 'w') as f:
                    json.dump(result, f)
                return result
    except: pass
    return []

def sync_apnic_timeseries(apnic_map: dict, meta: dict) -> dict:
    """Fetch 90-day time series. Returns {asn: (stdev, min90, max90, is_volatile)}."""
    import statistics
    APNIC_TS_SCORE_MIN = 60.0
    APNIC_VOLATILE_STDEV = 20.0
    APNIC_REGRESSION_THRESHOLD = 30.0 # >30-point drop from 1-year max to current

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
    result, fetched, skipped_sparse = {}, 0, 0
    for asn in candidates:
        cc = meta.get(asn, {}).get('cc', '')
        if not cc: continue
        raw = _fetch_apnic_ts_rates(asn, cc)
        if not raw: continue

        # Normalise: new format [[rate, samples], ...] or old format [float, ...]
        if raw and isinstance(raw[0], list):
            # New format — extract only data points with sufficient samples
            rates = [r[0] for r in raw if r[0] is not None]
            # For regression: 'current' must come from a recent data point with enough
            # samples to be statistically reliable.  A point that barely clears the
            # APNIC_MIN_SAMPLES floor (e.g. 31 samples from a large transit ASN) is
            # noise, not a meaningful current measurement.  Look for the most recent
            # point in the last 30 calendar days where n >= APNIC_REGRESSION_CURRENT_MIN_SAMPLES.
            recent_reliable = [r for r in raw[-30:] if r[0] is not None
                               and r[1] >= APNIC_REGRESSION_CURRENT_MIN_SAMPLES]
            current_for_regression = recent_reliable[-1][0] if recent_reliable else None
        else:
            # Old-format cache (plain floats, no sample counts).
            # Treat all points as valid until cache expires and is re-fetched.
            rates = [v for v in raw if isinstance(v, (int, float))]
            current_for_regression = rates[-1] if rates else None

        if len(rates) < 14:
            skipped_sparse += 1
            continue

        # Stats use all valid data points (90-day window)
        rates_90 = rates[-90:]
        sd = statistics.stdev(rates_90)
        mn90, mx90 = min(rates_90), max(rates_90)
        # Use 1-year lookback, not all-time max.  All-time max over 6 years of
        # APNIC data includes early measurement noise spikes that never reflected
        # real ROV deployment.  A genuine regression is "was high in the past
        # year, now dropped" — not "peaked once in 2020".
        rates_1yr = rates[-365:] if len(rates) >= 365 else rates
        historical_max = max(rates_1yr)

        # Volatility & Regression Criteria
        # Regression requires a reliable recent 'current' (n >= APNIC_REGRESSION_CURRENT_MIN_SAMPLES
        # within the last 30 days).  If no such point exists the current state cannot be
        # determined from APNIC data alone — skip regression rather than use a marginal
        # low-sample reading as a false low-water-mark.
        crossed_threshold = (mx90 >= 95.0 and mn90 < 60.0)
        regression = (current_for_regression is not None
                      and (historical_max - current_for_regression) > APNIC_REGRESSION_THRESHOLD)
        is_volatile = (sd > APNIC_VOLATILE_STDEV or crossed_threshold or regression)

        result[asn] = (round(sd, 1), round(mn90, 1), round(mx90, 1), is_volatile, regression)
        fetched += 1
    print(f"    - Result: {fetched} Analysed, {skipped_sparse} Sparse/skipped, "
          f"{len(candidates)-fetched-skipped_sparse} No data.")
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

ATLAS_TTL_DAYS = 7  # Results older than this are discarded and re-queued

def load_atlas_verdicts() -> tuple[set, set, dict, set]:
    """Load RIPE Atlas active measurement results.

    Returns (secure, vulnerable, raw, stale) where:
      stale  — ASNs whose cached result has expired and should be re-tested.
               These are NOT added to secure/vulnerable so stale data never
               influences the current audit.
    """
    from datetime import datetime, timezone
    print("[3] Loading Atlas Verification Results...")
    secure, vulnerable, raw, stale = set(), set(), {}, set()
    now = datetime.now(timezone.utc)

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

            # TTL check using the timestamp embedded in the result file.
            # Fall back to file mtime if timestamp is absent (legacy files).
            ts_str = d.get('timestamp')
            if ts_str:
                try:
                    last_test = datetime.fromisoformat(ts_str)
                    age_days = (now - last_test).total_seconds() / 86400
                except Exception:
                    age_days = 0
            else:
                age_days = (now.timestamp() - os.path.getmtime(f)) / 86400

            if age_days > ATLAS_TTL_DAYS:
                stale.add(asn)
                continue  # expired — don't use; will be re-queued

            raw[asn] = verdict
            v = verdict.upper()
            # New taxonomy: "SECURE (Upstream Filtered)" means the target
            # forwarded invalid prefixes — it is NOT doing ROV itself.
            if 'VULNERABLE' in v or v == 'SECURE (UPSTREAM FILTERED)':
                vulnerable.add(asn)
                secure.discard(asn)
            elif 'SECURE' in v and asn not in vulnerable:
                secure.add(asn)
        except: pass

    print(f"    - Atlas Data: {len(secure)} Secure, {len(vulnerable)} Vulnerable, "
          f"{len(stale)} Stale (queued for re-test)")
    return secure, vulnerable, raw, stale

def load_atlas_boundaries() -> dict:
    """
    Analyzes Atlas probe_details to identify ASNs actively filtering
    RPKI-invalid prefixes (the 'hard boundary').  Only uses fresh results
    (within ATLAS_TTL_DAYS); stale files are skipped.
    Returns boundary_asn -> count of blocks observed.
    """
    from datetime import datetime, timezone
    print("[3.5] Analyzing Atlas Hard Boundaries...")
    boundaries = Counter()
    now = datetime.now(timezone.utc)
    for f in glob.glob(os.path.join(DIR_ATLAS, "*.json")):
        try:
            with open(f) as h:
                d = json.load(h)

            ts_str = d.get('timestamp')
            if ts_str:
                try:
                    age_days = (now - datetime.fromisoformat(ts_str)).total_seconds() / 86400
                    if age_days > ATLAS_TTL_DAYS:
                        continue
                except Exception:
                    pass

            verdict = d.get('verdict', '')
            if "SECURE" not in verdict:
                continue

            for probe in d.get('probe_details', []):
                boundary = probe.get('boundary')
                if boundary and "SECURE" in probe.get('verdict', ''):
                    boundaries[boundary] += 1
        except:
            pass

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
    if any(x in v for x in ["(REG)", "REGRESSED", "UNRELIABLE", "UNPROT", "INCONSISTENT"]):
        return "VULNERABLE"
    if any(x in v for x in ["ACTIVE", "PASSIVE", "PROTECTOR", "VOLATILE", "FORTUITOUS"]):
        return "SECURE"
    if "PARTIAL" in v:
        return "PARTIAL"
    if any(x in v for x in ["VULNERABLE", "VULN"]):
        return "VULNERABLE"
    return "UNKNOWN"

def cone_quality(asn: int, downstream: dict, providers_of: dict) -> tuple[int, float, float]:
    """
    Measure whether a network's cone is real transit or IXP phantom inflation.

    Returns (direct_customers, excl_pct, avg_providers_per_customer) where:
      excl_pct   = % of direct customers that have ≤ 2 total providers
                   (high = captive customers = real transit)
      avg_prov   = average number of providers per direct customer
                   (low = captive customers; high ≥ 8 = IXP phantom)

    Phantom detection rule: excl_pct < CONE_QUALITY_THRESHOLD (5%)
    A legitimate transit provider has captive downstream customers.
    An IXP participant has peers who each have 5-20 other providers.

    NOTE: Tier 1s are exempt from this filter — their low exclusivity is
    expected because Tier 2 customers legitimately multi-home to several T1s.
    """
    customers = downstream.get(asn, [])
    if not customers:
        return 0, 0.0, 0.0
    total = len(customers)
    excl = sum(1 for c in customers if len(providers_of.get(c, set())) <= 2)
    avg_p = sum(len(providers_of.get(c, set())) for c in customers) / total
    return total, round(excl / total * 100, 1), round(avg_p, 1)


# Networks whose claimed cone size passes quality validation.
# Used by reports to exclude IXP phantom inflation.
CONE_QUALITY_THRESHOLD = 5.0  # min excl_pct to be counted as real transit


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
