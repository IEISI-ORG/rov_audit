import pandas as pd
import json
import os
import glob
import argparse
import sys

# --- CONFIGURATION ---
DIR_JSON = "data/parsed"
FILE_AUDIT = "rov_audit_v20_final.csv"
FILE_GRAPH = "data/downstream_graph.json"

def print_header(title):
    print("\n" + "="*100)
    print(f" {title}")
    print("="*100)

def load_data():
    print("[*] Loading Datasets...")
    
    if not os.path.exists(FILE_AUDIT) or not os.path.exists(FILE_GRAPH):
        print("[!] Missing input files. Run audit/topology scripts first.")
        return None, None, None

    # 1. Load Verdicts (Provider ROV Status)
    df = pd.read_csv(FILE_AUDIT, low_memory=False)
    # Map ASN -> Verdict
    rov_status_map = df.set_index('asn')['verdict'].to_dict()
    name_map = df.set_index('asn')['name'].to_dict()
    cc_map = df.set_index('asn')['cc'].to_dict()
    
    # 2. Load Topology
    with open(FILE_GRAPH, 'r') as f:
        topology = json.load(f)

    # 3. Load ROA Signing Stats (Customer Health)
    # We need to scan JSONs because CSV usually aggregates logic, 
    # but we stored specific ROA % in the JSONs.
    print("    - Scanning JSON cache for ROA Signing Stats...", end=" ")
    roa_map = {} 
    
    # Optimization: If you have a CSV with this, load it. 
    # Otherwise, fast scan JSONs.
    files = glob.glob(os.path.join(DIR_JSON, "*.json"))
    for f in files:
        try:
            with open(f, 'r') as h:
                d = json.load(h)
                asn = d.get('asn')
                if asn:
                    roa_map[asn] = d.get('roa_signed_pct', 0.0)
        except: pass
    print(f"OK ({len(roa_map)} records)")

    return rov_status_map, topology, roa_map, name_map, cc_map

def calculate_cone_roa_health(root_asn, topology, roa_map):
    """
    Recursive (Memoized) calculation of Cone ROA Health.
    Returns: (Total Customers, Weighted ROA Sum, Fully Signed Count, Unsigned Count)
    """
    # Simple BFS to get unique cone
    queue = [str(root_asn)]
    seen = set()
    seen.add(str(root_asn))
    
    unique_customers = []
    
    idx = 0
    while idx < len(queue):
        curr = queue[idx]
        idx += 1
        
        children = topology.get(curr, [])
        for child in children:
            child_str = str(child)
            if child_str not in seen:
                seen.add(child_str)
                queue.append(child_str)
                unique_customers.append(int(child))
    
    if not unique_customers:
        return 0, 0, 0, 0

    total_cust = len(unique_customers)
    roa_sum = 0
    fully_signed = 0
    unsigned = 0
    
    for c in unique_customers:
        score = roa_map.get(c, 0.0)
        roa_sum += score
        if score >= 90.0: fully_signed += 1
        if score < 10.0: unsigned += 1
        
    avg_roa = roa_sum / total_cust
    return total_cust, avg_roa, fully_signed, unsigned

def analyze():
    rov_map, topology, roa_map, names, ccs = load_data()
    if not rov_map: return

    print("[*] Calculating Cone Health for Providers...")
    
    results = []
    
    # We iterate topology keys (Providers)
    # Filter for significant cones (>20) to reduce noise
    providers = [int(k) for k in topology.keys()]
    
    count = 0
    for asn in providers:
        count += 1
        if count % 100 == 0: print(f"    - Processing {count}/{len(providers)}...", end="\r")
        
        # 1. Get Provider ROV Status (The Shield)
        verdict = rov_map.get(asn, "Unknown")
        is_secure = "ACTIVE" in verdict or "PASSIVE" in verdict or "PROTECTOR" in verdict
        is_vuln = "VULNERABLE" in verdict or "UNPROTECTED" in verdict
        
        # 2. Get Customer ROA Health (The Identity)
        total, avg_roa, full_cnt, zero_cnt = calculate_cone_roa_health(asn, topology, roa_map)
        
        if total < 20: continue # Skip small cones
        
        # 3. Classify Scenario
        scenario = "Unknown"
        if is_secure:
            if avg_roa < 30: scenario = "WASTED PROTECTION (Glass House Cone)"
            elif avg_roa > 70: scenario = "HERD IMMUNITY (Ideal)"
            else: scenario = "SECURE (Transitioning)"
        elif is_vuln:
            if avg_roa > 70: scenario = "UNPROTECTED CAPITAL (Tragedy)"
            elif avg_roa < 30: scenario = "THE SWAMP (Wild West)"
            else: scenario = "VULNERABLE (Mixed)"
            
        results.append({
            'asn': asn,
            'name': names.get(asn, 'Unknown'),
            'cc': ccs.get(asn, 'XX'),
            'cone_size': total,
            'prov_rov_status': "SECURE" if is_secure else "VULNERABLE",
            'cone_avg_roa': avg_roa,
            'cone_fully_signed_pct': (full_cnt / total) * 100,
            'cone_unsigned_pct': (zero_cnt / total) * 100,
            'scenario': scenario
        })

    df = pd.DataFrame(results)
    
    # ---------------------------------------------------------
    # REPORT 1: THE TRAGEDY (High Signing, Low Protection)
    # ---------------------------------------------------------
    print_header("SCENARIO A: 'UNPROTECTED CAPITAL' (The Tragedy)")
    print("These providers are VULNERABLE, but their customers are TRYING (High ROA Signing).")
    print("If these Providers flip the switch, massive value is secured instantly.")
    print("-" * 100)
    print(f"{'ASN':<8} | {'CC':<2} | {'Cone':<8} | {'Cone ROA%':<10} | {'Name'}")
    print("-" * 100)
    
    tragedy = df[df['scenario'].str.contains("TRAGEDY")].sort_values(by='cone_size', ascending=False).head(20)
    for _, r in tragedy.iterrows():
        print(f"AS{r['asn']:<6} | {r['cc']:<2} | {r['cone_size']:<8} | \033[92m{r['cone_avg_roa']:>5.1f}%\033[0m      | {r['name'][:45]}")

    # ---------------------------------------------------------
    # REPORT 2: WASTED PROTECTION
    # ---------------------------------------------------------
    print_header("SCENARIO B: 'WASTED PROTECTION' (Glass House Cones)")
    print("These Providers are SECURE, but their customers haven't signed ROAs.")
    print("The hardware is ready, but the paperwork is missing.")
    print("-" * 100)
    print(f"{'ASN':<8} | {'CC':<2} | {'Cone':<8} | {'Cone ROA%':<10} | {'Name'}")
    print("-" * 100)
    
    wasted = df[df['scenario'].str.contains("WASTED")].sort_values(by='cone_size', ascending=False).head(20)
    for _, r in wasted.iterrows():
        print(f"AS{r['asn']:<6} | {r['cc']:<2} | {r['cone_size']:<8} | \033[91m{r['cone_avg_roa']:>5.1f}%\033[0m      | {r['name'][:45]}")

    # ---------------------------------------------------------
    # STATS SUMMARY
    # ---------------------------------------------------------
    print_header("GLOBAL CORRELATION SUMMARY")
    
    # Avg ROA % for Secure Providers vs Vulnerable Providers
    avg_roa_secure = df[df['prov_rov_status'] == "SECURE"]['cone_avg_roa'].mean()
    avg_roa_vuln = df[df['prov_rov_status'] == "VULNERABLE"]['cone_avg_roa'].mean()
    
    print(f"Average Customer ROA Signing % behind SECURE Providers:     {avg_roa_secure:.1f}%")
    print(f"Average Customer ROA Signing % behind VULNERABLE Providers: {avg_roa_vuln:.1f}%")
    
    if avg_roa_secure > avg_roa_vuln:
        print("\n[INSIGHT] Secure Providers tend to have more responsible customers.")
    else:
        print("\n[INSIGHT] ROA Signing is uncorrelated with Provider Security.")

    # Save
    df.sort_values(by='cone_size', ascending=False).to_csv("rov_vs_roa_matrix.csv", index=False)
    print("\n[+] Data saved to rov_vs_roa_matrix.csv")

if __name__ == "__main__":
    analyze()
