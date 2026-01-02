import pandas as pd
import json
import os
import glob
import argparse
from collections import defaultdict

# --- CONFIGURATION ---
DIR_JSON = "data/parsed"
FILE_AUDIT = "rov_audit_v19_final.csv" # Or your latest version
FILE_GRAPH = "data/downstream_graph.json"

def load_data():
    print("[*] Loading Data Sets...")
    
    # 1. Load Verdicts
    if not os.path.exists(FILE_AUDIT):
        print(f"[!] {FILE_AUDIT} not found.")
        return None, None, None
        
    df = pd.read_csv(FILE_AUDIT, low_memory=False)
    # Normalize
    df['cone'] = pd.to_numeric(df['cone'], errors='coerce').fillna(0).astype(int)
    
    # 2. Load ROA Signing Stats & Graph from JSONs
    # We need to scan JSONs because the CSV might not have the signing % column
    print(f"    - Scanning JSON cache for ROA stats...", end=" ")
    
    roa_map = {} # asn -> % signed
    
    files = glob.glob(os.path.join(DIR_JSON, "*.json"))
    for f in files:
        try:
            with open(f, 'r') as h:
                d = json.load(h)
                asn = d.get('asn')
                if asn:
                    # Default to 0.0 if missing
                    roa_map[asn] = d.get('roa_signed_pct', 0.0)
        except: pass
    print(f"OK ({len(roa_map)} records)")

    # 3. Load Topology Graph
    print(f"    - Loading Topology...", end=" ")
    if os.path.exists(FILE_GRAPH):
        with open(FILE_GRAPH, 'r') as f:
            topology = json.load(f)
    else:
        print("FAIL (Graph missing)")
        topology = {}
    print(f"OK")

    return df, roa_map, topology

def get_recursive_unsigned_count(asn, topology, roa_map, memo):
    if asn in memo: return memo[asn]
    
    children = topology.get(str(asn), [])
    if not children:
        return 0, 0 # unsigned_cnt, total_cnt
    
    # Get direct children status
    unsigned = 0
    total = 0
    
    # We use a set to avoid double counting if the graph has cycles/multihoming issues
    # (Though we usually want unique ASNs in the cone)
    # The topology file is Parent->[Children].
    # To do this efficiently for the whole graph, we need the "Unique Cone" list.
    # Calculating full unique cones for 100k ASNs is slow (O(N^2)). 
    # Let's approximate using Direct + Depth 1 or rely on pre-calculated cones?
    
    # Better approach: We iterate the CSV (which is sorted by Cone Size).
    # We only calculate this expensive metric for the top 500 providers.
    return 0, 0

def calculate_cone_health(root_asn, topology, roa_map):
    """
    BFS to find all unique downstream ASNs and count how many are unsigned.
    """
    queue = [root_asn]
    seen = set()
    seen.add(root_asn)
    
    unsigned_customers = 0
    total_customers = 0
    
    # Iterate (BFS)
    idx = 0
    while idx < len(queue):
        curr = queue[idx]
        idx += 1
        
        children = topology.get(str(curr), [])
        for child in children:
            if child not in seen:
                seen.add(child)
                queue.append(child)
                
                # Check Child Status
                total_customers += 1
                # If < 10% signed, we consider them "Unsigned"
                if roa_map.get(child, 0.0) < 10.0:
                    unsigned_customers += 1
                    
    return unsigned_customers, total_customers

def analyze():
    df, roa_map, topology = load_data()
    if df is None: return

    # Enrich DataFrame
    df['signed_pct'] = df['asn'].map(roa_map).fillna(0.0)
    
    # ---------------------------------------------------------
    # 1. GLASS HOUSES
    # ---------------------------------------------------------
    print("\n" + "="*80)
    print("1. THE GLASS HOUSES (Secure Providers, Unsigned Routes)")
    print("   Networks that filter others but leave themselves exposed.")
    print("-" * 80)
    print(f"{'ASN':<8} | {'CC':<2} | {'Cone':<8} | {'Signed%':<8} | {'Name'}")
    print("-" * 80)
    
    is_secure = df['verdict'].str.contains("SECURE") | df['verdict'].str.contains("PROTECTED")
    glass = df[is_secure & (df['signed_pct'] < 10.0)].sort_values(by='cone', ascending=False)
    
    for _, r in glass.head(15).iterrows():
        print(f"AS{r['asn']:<6} | {r['cc']:<2} | {r['cone']:<8} | \033[91m{r['signed_pct']:>5.1f}%\033[0m  | {r['name'][:40]}")

    # ---------------------------------------------------------
    # 2. SCREAMING INTO THE VOID
    # ---------------------------------------------------------
    print("\n" + "="*80)
    print("2. SCREAMING INTO THE VOID (Fully Signed, Vulnerable Upstreams)")
    print("   Good citizens whose protection is nullified by their providers.")
    print("-" * 80)
    print(f"{'ASN':<8} | {'CC':<2} | {'Cone':<8} | {'Signed%':<8} | {'Name'}")
    print("-" * 80)
    
    is_vuln = df['verdict'].str.contains("VULNERABLE") | df['verdict'].str.contains("UNPROTECTED")
    screaming = df[is_vuln & (df['signed_pct'] > 95.0)].sort_values(by='cone', ascending=False)
    
    for _, r in screaming.head(15).iterrows():
        print(f"AS{r['asn']:<6} | {r['cc']:<2} | {r['cone']:<8} | \033[92m{r['signed_pct']:>5.1f}%\033[0m  | {r['name'][:40]}")

    # ---------------------------------------------------------
    # 3. ROA EVANGELISM TARGETS (Cone Effort)
    # ---------------------------------------------------------
    print("\n" + "="*80)
    print("3. ROA EVANGELISM TARGETS (Providers with the most Unsigned Customers)")
    print("   If these ISPs pushed for ROA adoption, global security would spike.")
    print("-" * 80)
    print(f"{'ASN':<8} | {'CC':<2} | {'Cone':<8} | {'Unsigned':<8} | {'% Bad':<6} | {'Name'}")
    print("-" * 80)
    
    # Filter: Only check providers with Cone > 50 to save time
    providers = df[df['cone'] > 50].copy()
    
    evangelism_list = []
    
    print(f"    (Calculating deep cone metrics for {len(providers)} providers... this may take a moment)")
    
    for i, row in providers.iterrows():
        asn = int(row['asn'])
        u_cnt, t_cnt = calculate_cone_health(asn, topology, roa_map)
        
        if t_cnt > 0:
            bad_pct = (u_cnt / t_cnt) * 100.0
            evangelism_list.append({
                'asn': asn,
                'cc': row['cc'],
                'name': row['name'],
                'cone': row['cone'], # This is the scraped/topo cone
                'unsigned_customers': u_cnt,
                'bad_pct': bad_pct
            })
            
    # Sort by Raw Count of Unsigned Customers
    evangelism_list.sort(key=lambda x: x['unsigned_customers'], reverse=True)
    
    for item in evangelism_list[:25]:
        color = "\033[91m" if item['bad_pct'] > 50 else "\033[93m"
        print(f"AS{item['asn']:<6} | {item['cc']:<2} | {item['cone']:<8} | {item['unsigned_customers']:<8} | {color}{item['bad_pct']:>5.1f}%\033[0m | {item['name'][:35]}")

    # Save to CSV
    out_df = pd.DataFrame(evangelism_list)
    out_df.to_csv("roa_strategy_report.csv", index=False)
    print(f"\n[+] Full strategy report saved to roa_strategy_report.csv")

if __name__ == "__main__":
    analyze()
