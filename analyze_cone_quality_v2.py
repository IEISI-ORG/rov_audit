import json
import pandas as pd
import os
import sys
import collections

# --- CONFIGURATION ---
FILE_AUDIT_CSV = "rov_audit_v13_final.csv"
FILE_GRAPH = "data/downstream_graph.json"

# Optimization: Only analyze providers with a cone larger than this
# (Skips the 80,000+ stub networks that have no downstream impact)
MIN_REAL_CONE_SIZE = 5 

def analyze_cones():
    print("[*] Loading Topology and Audit Data...")
    
    if not os.path.exists(FILE_GRAPH):
        print(f"[!] Error: {FILE_GRAPH} not found.")
        return
    
    if not os.path.exists(FILE_AUDIT_CSV):
        print(f"[!] Error: {FILE_AUDIT_CSV} not found.")
        return

    # 1. Load Topology
    with open(FILE_GRAPH) as f:
        downstream_map = json.load(f)
        # Ensure keys are ints for easier lookup
        downstream_adj = {int(k): [int(x) for x in v] for k,v in downstream_map.items()}

    # 2. Load Audit Data
    print("    - Parsing CSV verdicts...")
    df = pd.read_csv(FILE_AUDIT_CSV)
    
    # Maps for O(1) lookup
    status_map = {}
    meta_map = {}
    
    # We also create a list of "Targets" to analyze (Providers with cone > X)
    targets = []

    for _, row in df.iterrows():
        asn = int(row['asn'])
        v = str(row['verdict']).upper()
        
        # Status
        if "SECURE" in v or "PROTECTED" in v: status = "SECURE"
        elif "VULNERABLE" in v or "UNPROTECTED" in v: status = "VULNERABLE"
        elif "DEAD" in v: status = "DEAD"
        else: status = "UNKNOWN"
        
        status_map[asn] = status
        
        # Meta
        cone = int(row['cone'])
        meta_map[asn] = {
            'name': row['name'],
            'cc': row['cc'],
            'cone': cone
        }
        
        # Filter: Only analyze relevant providers
        if cone >= MIN_REAL_CONE_SIZE:
            targets.append(asn)

    print(f"    - Found {len(targets)} providers with Cone > {MIN_REAL_CONE_SIZE} to analyze.")

    # 3. Aggregation Engine (BFS for Uniqueness)
    print("[*] Calculating Unique Downstream Compositions...")
    
    results = []
    total_tasks = len(targets)
    
    for i, root_asn in enumerate(targets):
        if i % 50 == 0: print(f"    Processed {i}/{total_tasks}...", end="\r")
        
        # BFS to find ALL unique descendants
        queue = collections.deque([root_asn])
        seen_cone = set() # This prevents double counting!
        
        # We don't count the root itself in the percentages usually, 
        # but for "Ecosystem" quality, we care about what they serve.
        # Let's count descendants only.
        
        while queue:
            current = queue.popleft()
            
            # Get children
            children = downstream_adj.get(current, [])
            
            for child in children:
                if child not in seen_cone:
                    seen_cone.add(child)
                    queue.append(child)
        
        # Now we have a unique set of customers (seen_cone)
        # Tally their status
        total_observed = len(seen_cone)
        if total_observed == 0: continue

        s_cnt = 0
        v_cnt = 0
        u_cnt = 0
        
        for cust_asn in seen_cone:
            st = status_map.get(cust_asn, "UNKNOWN")
            if st == "SECURE": s_cnt += 1
            elif st == "VULNERABLE": v_cnt += 1
            elif st != "DEAD": u_cnt += 1 # Ignore dead in denominator? 
            # Actually keep dead in counts or ignore? 
            # If we exclude dead, recalculate total
        
        # Re-calculate total excluding dead for percentages
        valid_total = s_cnt + v_cnt + u_cnt
        if valid_total == 0: continue

        res = {
            'asn': root_asn,
            'name': meta_map[root_asn]['name'],
            'cc': meta_map[root_asn]['cc'],
            'real_cone': meta_map[root_asn]['cone'],
            'observed_cone': valid_total, # Unique active descendants
            'secure_cnt': s_cnt,
            'vuln_cnt': v_cnt,
            'secure_pct': (s_cnt / valid_total) * 100.0,
            'vuln_pct': (v_cnt / valid_total) * 100.0
        }
        results.append(res)

    # 4. Reporting
    res_df = pd.DataFrame(results)
    
    print("\n" + "="*100)
    print(f"ECOSYSTEM QUALITY REPORT (Unique Descendants Analysis)")
    print("="*100)
    
    # A. CLEANEST
    print("\n[TOP 20 'CLEAN' ECOSYSTEMS] (Highest % Secure Downstreams, Min 50 Customers)")
    print(f"{'ASN':<8} | {'CC':<2} | {'Cust.':<8} | {'% Secure':<8} | {'Name'}")
    print("-" * 100)
    
    clean = res_df[res_df['observed_cone'] > 50].sort_values(by=['secure_pct', 'observed_cone'], ascending=[False, False]).head(20)
    for _, r in clean.iterrows():
        print(f"AS{r['asn']:<6} | {r['cc']:<2} | {r['observed_cone']:<8} | \033[92m{r['secure_pct']:.1f}%\033[0m    | {r['name'][:45]}")

    # B. TOXIC
    print("\n[TOP 20 'TOXIC' ECOSYSTEMS] (Highest % Vulnerable Downstreams, Min 50 Customers)")
    print(f"{'ASN':<8} | {'CC':<2} | {'Cust.':<8} | {'% Vuln':<8} | {'Name'}")
    print("-" * 100)
    
    dirty = res_df[res_df['observed_cone'] > 50].sort_values(by=['vuln_pct', 'observed_cone'], ascending=[False, False]).head(20)
    for _, r in dirty.iterrows():
        print(f"AS{r['asn']:<6} | {r['cc']:<2} | {r['observed_cone']:<8} | \033[91m{r['vuln_pct']:.1f}%\033[0m    | {r['name'][:45]}")

    # C. MASSIVE VULNERABILITY
    print("\n[LARGEST VULNERABLE FOOTPRINTS] (Highest Count of Vulnerable Downstreams)")
    print(f"{'ASN':<8} | {'CC':<2} | {'Vuln #':<8} | {'% Vuln':<8} | {'Name'}")
    print("-" * 100)
    
    impact = res_df.sort_values(by='vuln_cnt', ascending=False).head(20)
    for _, r in impact.iterrows():
        print(f"AS{r['asn']:<6} | {r['cc']:<2} | {r['vuln_cnt']:<8} | {r['vuln_pct']:.1f}%     | {r['name'][:45]}")

    filename = "cone_quality_report_v3.csv"
    res_df.sort_values(by='observed_cone', ascending=False).to_csv(filename, index=False)
    print(f"\n[+] Report saved to {filename}")

if __name__ == "__main__":
    analyze_cones()
