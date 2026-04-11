import json
import pandas as pd
import os

# --- CONFIGURATION ---
FILE_AUDIT_CSV = "rov_audit_v12.csv" # Your latest audit report
FILE_GRAPH = "data/downstream_graph.json"
FILE_META = "data/asn_meta.json"

def analyze_cones():
    print("[*] Loading Topology and Audit Data...")
    
    # 1. Load Graph
    if not os.path.exists(FILE_GRAPH):
        print("[!] Run build_topology.py first!")
        return
    
    with open(FILE_GRAPH) as f: downstream_map = json.load(f)
    with open(FILE_META) as f: meta_map = json.load(f)
    
    # 2. Load Verdicts from CSV
    # We map ASN -> Status (0=Secure, 1=Vulnerable, 2=Dead)
    df = pd.read_csv(FILE_AUDIT_CSV)
    status_map = {}
    
    for _, row in df.iterrows():
        v = str(row['verdict'])
        if "SECURE" in v or "PROTECTED" in v: status = "SECURE"
        elif "VULNERABLE" in v or "UNPROTECTED" in v: status = "VULNERABLE"
        elif "DEAD" in v: status = "DEAD"
        else: status = "UNKNOWN"
        status_map[row['asn']] = status

    # 3. Calculate Cone Hygiene (Recursive)
    # We use memoization to speed up the tree walk
    memo = {}

    def get_cone_stats(asn, path=None):
        if path is None: path = set()
        
        # Avoid loops (BGP allows loops)
        if asn in path: return {'s': 0, 'v': 0, 'u': 0, 'total': 0}
        if str(asn) in memo: return memo[str(asn)]
        
        # Self Status
        my_status = status_map.get(asn, "UNKNOWN")
        stats = {'s': 0, 'v': 0, 'u': 0, 'total': 0}
        
        if my_status == "SECURE": stats['s'] = 1
        elif my_status == "VULNERABLE": stats['v'] = 1
        elif my_status == "UNKNOWN": stats['u'] = 1
        
        if my_status != "DEAD":
            stats['total'] = 1
        
        # Recurse Downstreams
        children = downstream_map.get(str(asn), [])
        
        # Optimization: Only recurse if we have children
        if children:
            new_path = path.copy()
            new_path.add(asn)
            
            for child in children:
                # We only count a child if we actually have data for it (it exists in our audit)
                if child in status_map:
                    c_stats = get_cone_stats(child, new_path)
                    stats['s'] += c_stats['s']
                    stats['v'] += c_stats['v']
                    stats['u'] += c_stats['u']
                    stats['total'] += c_stats['total']
        
        memo[str(asn)] = stats
        return stats

    print("[*] Calculating Cone Hygiene for all providers...")
    results = []
    
    # Only analyze ASNs that actually have downstreams (Providers)
    targets = [asn for asn in downstream_map.keys()]
    total = len(targets)
    
    for i, asn_str in enumerate(targets):
        if i % 100 == 0: print(f"    Processed {i}/{total}...", end="\r")
        
        asn = int(asn_str)
        stats = get_cone_stats(asn)
        
        total_observed = stats['total']
        if total_observed < 5: continue # Skip tiny cones to reduce noise
        
        secure_pct = (stats['s'] / total_observed) * 100
        vuln_pct = (stats['v'] / total_observed) * 100
        
        # Get Meta
        name = meta_map.get(str(asn), {}).get('name', 'Unknown')
        cc = meta_map.get(str(asn), {}).get('cc', 'XX')
        real_cone = meta_map.get(str(asn), {}).get('cone', 0)
        
        results.append({
            'asn': asn,
            'name': name,
            'cc': cc,
            'real_cone_size': real_cone,
            'observed_tree_size': total_observed,
            'secure_pct': secure_pct,
            'vulnerable_pct': vuln_pct,
            'vuln_count': stats['v']
        })

    # 4. Reporting
    res_df = pd.DataFrame(results)
    
    print("\n" + "="*90)
    print("TOP 50 'CLEANEST' ECOSYSTEMS (Highest % Secure Downstreams, Min 50 Obs)")
    print("="*90)
    print(f"{'ASN':<8} | {'CC':<2} | {'Tree Size':<10} | {'% Secure':<8} | {'Name'}")
    print("-" * 90)
    
    clean = res_df[res_df['observed_tree_size'] > 50].sort_values(by='secure_pct', ascending=False).head(50)
    for _, r in clean.iterrows():
        print(f"AS{r['asn']:<6} | {r['cc']:<2} | {r['observed_tree_size']:<10} | \033[92m{r['secure_pct']:.1f}%\033[0m    | {r['name'][:40]}")

    print("\n" + "="*90)
    print("TOP 50 'TOXIC' ECOSYSTEMS (Highest % Vulnerable Downstreams, Min 50 Obs)")
    print("="*90)
    
    dirty = res_df[res_df['observed_tree_size'] > 50].sort_values(by='vulnerable_pct', ascending=False).head(50)
    for _, r in dirty.iterrows():
        print(f"AS{r['asn']:<6} | {r['cc']:<2} | {r['observed_tree_size']:<10} | \033[91m{r['vulnerable_pct']:.1f}%\033[0m    | {r['name'][:40]}")

    res_df.to_csv("cone_quality_report.csv", index=False)
    print("\n[+] Detailed Cone Report saved to 'cone_quality_report.csv'")

if __name__ == "__main__":
    analyze_cones()
