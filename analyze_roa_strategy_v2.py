import pandas as pd
import json
import os
import glob
import argparse

# --- CONFIGURATION ---
DIR_JSON = "data/parsed"
FILE_AUDIT = "rov_audit_v19_final.csv" 
FILE_GRAPH = "data/downstream_graph.json"

def load_data():
    print("[*] Loading V19 Data Sets...")
    
    if not os.path.exists(FILE_AUDIT):
        print(f"[!] {FILE_AUDIT} not found.")
        return None, None, None
        
    df = pd.read_csv(FILE_AUDIT, low_memory=False)
    df['cone'] = pd.to_numeric(df['cone'], errors='coerce').fillna(0).astype(int)
    
    # Load ROA Stats
    print(f"    - Scanning JSON cache for ROA stats...", end=" ")
    roa_map = {} 
    files = glob.glob(os.path.join(DIR_JSON, "*.json"))
    for f in files:
        try:
            with open(f, 'r') as h:
                d = json.load(h)
                if d.get('asn'):
                    roa_map[d['asn']] = d.get('roa_signed_pct', 0.0)
        except: pass
    print(f"OK ({len(roa_map)} records)")

    # Load Topology
    print(f"    - Loading Topology...", end=" ")
    if os.path.exists(FILE_GRAPH):
        with open(FILE_GRAPH, 'r') as f:
            topology = json.load(f)
    else:
        topology = {}
    print(f"OK")

    return df, roa_map, topology

def calculate_cone_health(root_asn, topology, roa_map):
    """BFS to find unique downstream ASNs and count unsigned ones."""
    queue = [root_asn]
    seen = set()
    seen.add(root_asn)
    
    unsigned_customers = 0
    total_customers = 0
    
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
                # If < 10% signed, we consider them "Unsigned/Exposed"
                if roa_map.get(child, 0.0) < 10.0:
                    unsigned_customers += 1
                    
    return unsigned_customers, total_customers

def analyze():
    df, roa_map, topology = load_data()
    if df is None: return

    df['signed_pct'] = df['asn'].map(roa_map).fillna(0.0)
    
    # ---------------------------------------------------------
    # 1. GLASS HOUSES
    # ---------------------------------------------------------
    print("\n" + "="*95)
    print("1. THE GLASS HOUSES (Secure Providers, Unsigned Routes)")
    print("-" * 95)
    print(f"{'ASN':<8} | {'CC':<2} | {'Cone':<8} | {'Signed%':<8} | {'Name'}")
    print("-" * 95)
    
    is_secure = df['verdict'].str.contains("SECURE") | df['verdict'].str.contains("PROTECTED")
    glass = df[is_secure & (df['signed_pct'] < 10.0)].sort_values(by='cone', ascending=False)
    
    for _, r in glass.head(15).iterrows():
        print(f"AS{r['asn']:<6} | {r['cc']:<2} | {r['cone']:<8} | \033[91m{r['signed_pct']:>5.1f}%\033[0m  | {r['name'][:45]}")

    # ---------------------------------------------------------
    # 2. SCREAMING INTO THE VOID
    # ---------------------------------------------------------
    print("\n" + "="*95)
    print("2. SCREAMING INTO THE VOID (Fully Signed, Vulnerable Upstreams)")
    print("-" * 95)
    print(f"{'ASN':<8} | {'CC':<2} | {'Cone':<8} | {'Signed%':<8} | {'Name'}")
    print("-" * 95)
    
    is_vuln = df['verdict'].str.contains("VULNERABLE") | df['verdict'].str.contains("UNPROTECTED")
    screaming = df[is_vuln & (df['signed_pct'] > 95.0)].sort_values(by='cone', ascending=False)
    
    for _, r in screaming.head(15).iterrows():
        print(f"AS{r['asn']:<6} | {r['cc']:<2} | {r['cone']:<8} | \033[92m{r['signed_pct']:>5.1f}%\033[0m  | {r['name'][:45]}")

    # ---------------------------------------------------------
    # 3. ROA EVANGELISM TARGETS (Weighted)
    # ---------------------------------------------------------
    print("\n" + "="*95)
    print("3. WEIGHTED EVANGELISM TARGETS")
    print("   Metric = (Provider Cone Size) * (Count of Unsigned Customers)")
    print("   Highlighting massive providers with dirty customer bases.")
    print("-" * 95)
    print(f"{'ASN':<8} | {'CC':<2} | {'Cone':<8} | {'Unsigned':<8} | {'Impact Score':<14} | {'Name'}")
    print("-" * 95)
    
    # Filter: Only check providers with Cone > 50
    providers = df[df['cone'] > 50].copy()
    
    evangelism_list = []
    
    print(f"    (Calculating weighted metrics for {len(providers)} providers...)\r")
    
    for i, row in providers.iterrows():
        asn = int(row['asn'])
        u_cnt, t_cnt = calculate_cone_health(asn, topology, roa_map)
        
        if t_cnt > 0:
            # WEIGHTED SCORE
            impact_score = row['cone'] * u_cnt
            
            evangelism_list.append({
                'asn': asn,
                'cc': row['cc'],
                'name': row['name'],
                'cone': row['cone'],
                'unsigned_customers': u_cnt,
                'impact_score': impact_score
            })
            
    # Sort by Weighted Score
    evangelism_list.sort(key=lambda x: x['impact_score'], reverse=True)
    
    for item in evangelism_list[:25]:
        score_str = f"{item['impact_score']:,}"
        print(f"AS{item['asn']:<6} | {item['cc']:<2} | {item['cone']:<8} | {item['unsigned_customers']:<8} | {score_str:<14} | {item['name'][:35]}")

    # Save
    out_df = pd.DataFrame(evangelism_list)
    out_df.to_csv("roa_strategy_weighted.csv", index=False)
    print(f"\n[+] Saved strategy to roa_strategy_weighted.csv")

if __name__ == "__main__":
    analyze()
