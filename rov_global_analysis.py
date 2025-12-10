import pandas as pd
import json
import os
import glob
import requests
from io import StringIO

# --- CONFIGURATION ---
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'}
DIR_JSON = "data/parsed"
DIR_APNIC = "data/apnic"
DIR_HTML = "data/html" # Needed to check cache existence
URL_ASNS_CSV = "https://bgp.tools/asns.csv"
URL_ROV_TAGS = "https://bgp.tools/tags/rpkirov.csv"

# Expanded "Global Core" list (Tier 1s + Massive Tier 2s)
KNOWN_TIER_1 = {
    # --- The Big Ones (Standard Tier 1s) ---
    3356,  # Lumen (Level 3)
    1299,  # Arelion (Telia)
    174,   # Cogent
    2914,  # NTT
    3257,  # GTT
    6762,  # TIM (Sparkle)
    6453,  # TATA
    3491,  # PCCW
    1239,  # T-Mobile (Sprint)
    6461,  # Zayo
    5511,  # Orange
    6830,  # Liberty Global
    4637,  # Telstra
    701,   # Verizon (UUNET)

    # --- Missing Giants (Added) ---
    7018,  # AT&T (Massive US Core)
    3320,  # Deutsche Telekom (DTAG - Massive EU Core)
    12956, # Telefonica (huge in S.America/EU)
    1273,  # Vodafone
    7922,  # Comcast (technically T2, but functionally Core)
    209,   # Lumen (Qwest legacy)
    2828,  # Verizon APAC

    # --- The Chinese Core (Critical for Global Routing) ---
    4134,  # China Telecom Backbone
    4809,  # China Telecom CN2
    4837,  # China Unicom
    9929,  # China Unicom Industrial
    9808,  # China Mobile

    # --- The "Honorary" Tier 1 (Massive Peering) ---
    6939,  # Hurricane Electric (The biggest IPv6 network)
}

def load_all_data():
    print("[*] Loading Data...")

    # A. Metadata
    print("    - ASN Metadata...", end=" ")
    try:
        resp = requests.get(URL_ASNS_CSV, headers=HEADERS)
        meta_df = pd.read_csv(StringIO(resp.text))
        meta_df.columns = [c.strip().lower() for c in meta_df.columns]
        meta_map = {}
        for _, row in meta_df.iterrows():
            s = str(row.get('asn','')).upper().replace('AS','')
            if s.isdigit():
                meta_map[int(s)] = {'name': str(row.get('name','Unknown')), 'cc': str(row.get('country','XX')).upper()}
        print(f"OK ({len(meta_map)})")
    except Exception as e:
        print(f"FAIL ({e})")
        return None

    # B. ROV Tags (FIXED LOADER)
    print("    - ROV Tags...", end=" ")
    try:
        resp = requests.get(URL_ROV_TAGS, headers=HEADERS)
        # Try reading without header first to detect format
        lines = resp.text.splitlines()
        # Look for a line that looks like a header
        if "ASN" in lines[0].upper():
            tag_df = pd.read_csv(StringIO(resp.text))
        else:
            tag_df = pd.read_csv(StringIO(resp.text), header=None)
            
        # Find the column with ASNs
        asn_col = None
        for col in tag_df.columns:
            # Check first few values
            sample = str(tag_df[col].iloc[0]).upper()
            if sample.startswith("AS") or (sample.isdigit() and int(sample) < 400000):
                asn_col = col
                break
        
        if asn_col is not None:
            tag_df['asn_clean'] = tag_df[asn_col].astype(str).str.upper().str.replace('AS','',regex=False)
            tagged_set = set(tag_df[tag_df['asn_clean'].str.isnumeric()]['asn_clean'].astype(int))
            print(f"OK ({len(tagged_set)})")
        else:
            print("FAIL (Col not found)")
            tagged_set = set()
    except Exception as e:
        print(f"FAIL ({e})")
        tagged_set = set()

    # C. APNIC
    print("    - APNIC Cache...", end=" ")
    apnic_map = {}
    for f in glob.glob(os.path.join(DIR_APNIC, "*.json")):
        try:
            with open(f, 'r') as h:
                d = json.load(h)
                for k,v in d.items(): apnic_map[int(k)] = v
        except: pass
    print(f"OK ({len(apnic_map)})")

    # D. Connectivity
    print("    - Connectivity Cache...", end=" ")
    conn_map = {}
    for f in glob.glob(os.path.join(DIR_JSON, "*.json")):
        try:
            with open(f, 'r') as h:
                d = json.load(h)
                if d.get('asn'):
                    conn_map[int(d['asn'])] = {
                        'upstreams': d.get('upstreams', []),
                        'cone': d.get('cone_size', 0),
                        'is_tier1': d.get('is_tier1', False)
                    }
        except: pass
    print(f"OK ({len(conn_map)})")

    return meta_map, tagged_set, apnic_map, conn_map

def analyze():
    data = load_all_data()
    if not data: return
    meta_map, tagged_set, apnic_map, conn_map = data

    # 1. Define Safe Upstreams
    safe_asns = set()
    for asn in meta_map.keys():
        if (asn in tagged_set) or (apnic_map.get(asn, -1) >= 95.0):
            safe_asns.add(asn)

    results = []
    
    print(f"[*] Analyzing {len(meta_map)} ASNs against {len(conn_map)} known connectivity graphs...")

    for asn, meta in meta_map.items():
        conn = conn_map.get(asn) # None if not scraped
        score = apnic_map.get(asn, -1)
        is_tagged = asn in tagged_set
        
        is_safe_self = (is_tagged or score >= 90.0)
        
        verdict = "Unknown"
        dirty_ups = 0
        total_ups = 0
        
        # LOGIC TREE
        if asn in KNOWN_TIER_1 or (conn and conn['is_tier1']):
            # Tier 1 Logic
            if is_safe_self: verdict = "CORE: PROTECTED"
            else: verdict = "CORE: UNPROTECTED"
            total_ups = 0
            
        elif not conn:
            # We haven't scraped it yet
            if is_safe_self: verdict = "Safe (Unknown Upstreams)"
            else: verdict = "Unverified (Unknown Upstreams)"
            
        else:
            # We HAVE data
            total_ups = len(conn['upstreams'])
            if total_ups == 0:
                verdict = "IXP / Peer / Stub"
            else:
                for u in conn['upstreams']:
                    if u not in safe_asns: dirty_ups += 1
                
                if dirty_ups == 0:
                    verdict = "SECURE (Full Coverage)"
                elif is_safe_self:
                    verdict = "SECURE (Active Local ROV)"
                elif (total_ups - dirty_ups) > 0:
                    verdict = "PARTIAL (Mixed Feeds)"
                else:
                    verdict = "VULNERABLE (No Coverage)"

        results.append({
            'asn': asn,
            'name': meta['name'],
            'cone': conn['cone'] if conn else 0,
            'verdict': verdict,
            'dirty': dirty_ups,
            'total': total_ups
        })

    df = pd.DataFrame(results)
    
    # Stats
    print("\n" + "="*60)
    print("GLOBAL AUDIT RESULTS")
    print("="*60)
    print(f"Total ASNs in DB:     {len(df):,}")
    print(f"ASNs with Graph Data: {len(conn_map):,}")
    
    # Question A
    q_a = len(df[df['verdict'] == "SECURE (Full Coverage)"])
    print(f"[A] Full Upstream Coverage: {q_a:,}")
    
    # Question B
    q_b = len(df[df['verdict'] == "VULNERABLE (No Coverage)"])
    print(f"[B] Completely Vulnerable:  {q_b:,}")

    # Question C
    print("\n[C] TIER 1 STATUS")
    t1_df = df[df['verdict'].str.contains("CORE")]
    for _, row in t1_df.iterrows():
        status = "PASS" if "PROTECTED" in row['verdict'] and "UN" not in row['verdict'] else "FAIL"
        print(f"    AS{row['asn']:<6} {status}  {row['name']}")

    df.sort_values(by='cone', ascending=False).to_csv("rov_global_audit_v2.csv", index=False)
    print("\n[+] Saved full audit to rov_global_audit_v2.csv")

if __name__ == "__main__":
    analyze()
