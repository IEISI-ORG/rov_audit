import pandas as pd
import json
import os
import glob
import argparse

# --- CONFIGURATION ---
DIR_JSON = "data/parsed"
FILE_AUDIT = "rov_audit_v20_final.csv"
FILE_GRAPH = "data/downstream_graph.json"

# Thresholds
MIN_CONE = 20        # Ignore tiny networks
HIGH_SIGNING = 60.0  # % of customers signing ROAs to be considered "Good"

def load_data():
    print("[*] Loading Data...")
    df = pd.read_csv(FILE_AUDIT, low_memory=False)
    
    with open(FILE_GRAPH, 'r') as f:
        topology = json.load(f)

    roa_map = {} 
    files = glob.glob(os.path.join(DIR_JSON, "*.json"))
    for f in files:
        try:
            with open(f, 'r') as h:
                d = json.load(h)
                if d.get('asn'): roa_map[d['asn']] = d.get('roa_signed_pct', 0.0)
        except: pass

    return df, roa_map, topology

def calculate_cone_roa(root_asn, topology, roa_map):
    queue = [str(root_asn)]
    seen = {str(root_asn)}
    customers = []
    
    idx = 0
    while idx < len(queue):
        curr = queue[idx]
        idx += 1
        children = topology.get(curr, [])
        for child in children:
            if child not in seen:
                seen.add(child)
                queue.append(child)
                customers.append(int(child))
    
    if not customers: return 0.0
    
    total_roa = sum(roa_map.get(c, 0.0) for c in customers)
    return total_roa / len(customers)

def analyze():
    df, roa_map, topology = load_data()
    
    results = []
    print("[*] Classifying Quadrants...")
    
    # Analyze Providers
    providers = df[df['cone'] >= MIN_CONE].copy()
    
    count = 0
    for idx, row in providers.iterrows():
        asn = int(row['asn'])
        count += 1
        if count % 100 == 0: print(f"    - Processing {count}/{len(providers)}...", end="\r")
        
        avg_roa = calculate_cone_roa(asn, topology, roa_map)
        
        # Determine Axes
        is_secure = "SECURE" in str(row['verdict']) or "PROTECTED" in str(row['verdict'])
        is_high_sign = avg_roa >= HIGH_SIGNING
        
        # Determine Quadrant
        quadrant = ""
        description = ""
        
        if is_secure and is_high_sign:
            quadrant = "Q1: GOLD STANDARD"
            description = "Secure Provider + Diligent Customers"
        elif not is_secure and is_high_sign:
            quadrant = "Q2: THE VICTIMS"
            description = "Vulnerable Provider + Diligent Customers"
        elif is_secure and not is_high_sign:
            quadrant = "Q3: WASTED TECH"
            description = "Secure Provider + Lazy Customers"
        else:
            quadrant = "Q4: THE SWAMP"
            description = "Vulnerable Provider + Lazy Customers"
            
        results.append({
            'asn': asn,
            'name': row['name'],
            'cc': row['cc'],
            'cone': row['cone'],
            'verdict': row['verdict'],
            'customer_avg_signing': avg_roa,
            'quadrant': quadrant,
            'description': description
        })

    out = pd.DataFrame(results)
    
    # --- REPORTING ---
    print("\n" + "="*100)
    print(f"THE ROV QUADRANT ANALYSIS (Threshold: >{HIGH_SIGNING}% Signing)")
    print("="*100)
    
    counts = out['quadrant'].value_counts()
    total = len(out)
    
    print(f"Total Providers Analyzed: {total}")
    print("-" * 60)
    print(f"\033[92m{counts.get('Q1: GOLD STANDARD', 0):>5} ({counts.get('Q1: GOLD STANDARD', 0)/total*100:>4.1f}%) - Q1: Ideal State\033[0m")
    print(f"\033[93m{counts.get('Q2: THE VICTIMS', 0):>5} ({counts.get('Q2: THE VICTIMS', 0)/total*100:>4.1f}%) - Q2: High Value Targets (Sales List)\033[0m")
    print(f"\033[96m{counts.get('Q3: WASTED TECH', 0):>5} ({counts.get('Q3: WASTED TECH', 0)/total*100:>4.1f}%) - Q3: Education Needed\033[0m")
    print(f"\033[91m{counts.get('Q4: THE SWAMP', 0):>5} ({counts.get('Q4: THE SWAMP', 0)/total*100:>4.1f}%) - Q4: Total Failure\033[0m")

    # Show the "Missing" Scenario A (Q2)
    print("\n" + "="*80)
    print("TOP Q2: THE VICTIMS (Customers are ready, Provider is failing)")
    print("-" * 80)
    q2 = out[out['quadrant'] == "Q2: THE VICTIMS"].sort_values(by='cone', ascending=False).head(20)
    if q2.empty:
        print("No providers found in Q2 with current thresholds.")
    else:
        for _, r in q2.iterrows():
            print(f"AS{r['asn']:<6} | {r['cc']:<2} | {r['cone']:<8} | {r['customer_avg_signing']:>5.1f}% | {r['name'][:40]}")

    # Save
    out.to_csv("rov_quadrant_analysis.csv", index=False)
    print(f"\n[+] Saved to rov_quadrant_analysis.csv")

if __name__ == "__main__":
    analyze()
