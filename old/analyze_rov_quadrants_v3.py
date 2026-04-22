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
HIGH_SIGNING = 60.0  # Threshold for "Good" customer hygiene

def load_data():
    print("[*] Loading Data...")
    if not os.path.exists(FILE_AUDIT):
        print(f"[!] {FILE_AUDIT} not found.")
        return None, None, None

    df = pd.read_csv(FILE_AUDIT, low_memory=False)
    df['cone'] = pd.to_numeric(df['cone'], errors='coerce').fillna(0).astype(int)
    
    with open(FILE_GRAPH, 'r') as f:
        topology = json.load(f)

    print("    - Scanning JSON cache for ROA stats...", end=" ")
    roa_map = {} 
    files = glob.glob(os.path.join(DIR_JSON, "*.json"))
    for f in files:
        try:
            with open(f, 'r') as h:
                d = json.load(h)
                if d.get('asn'): roa_map[d['asn']] = d.get('roa_signed_pct', 0.0)
        except: pass
    print(f"OK ({len(roa_map)} records)")

    return df, roa_map, topology

def calculate_cone_roa(root_asn, topology, roa_map):
    """Calculates average ROA signing % of all downstream customers."""
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
    if df is None: return
    
    results = []
    print("[*] Classifying Quadrants (this takes a moment)...")
    
    providers = df[df['cone'] >= MIN_CONE].copy()
    
    count = 0
    for idx, row in providers.iterrows():
        asn = int(row['asn'])
        count += 1
        if count % 200 == 0: print(f"    - Processing {count}/{len(providers)}...", end="\r")
        
        avg_roa = calculate_cone_roa(asn, topology, roa_map)
        
        is_secure = "SECURE" in str(row['verdict']) or "PROTECTED" in str(row['verdict'])
        is_high_sign = avg_roa >= HIGH_SIGNING
        
        if is_secure and is_high_sign:
            quadrant = "Q1: GOLD STANDARD"
        elif not is_secure and is_high_sign:
            quadrant = "Q2: THE VICTIMS"
        elif is_secure and not is_high_sign:
            quadrant = "Q3: WASTED TECH"
        else:
            quadrant = "Q4: THE SWAMP"
            
        results.append({
            'Quadrant': quadrant,
            'ASN': asn,
            'CC': row['cc'],
            'Cone': row['cone'],
            'Percentile': avg_roa,
            'Name': row['name']
        })

    out_df = pd.DataFrame(results)
    
    # --- REPORTING ---
    print("\n" + "="*110)
    print(f"ROV STRATEGIC QUADRANT REPORT")
    print("="*110)
    
    # Definitions
    definitions = {
        "Q1: GOLD STANDARD": "IDEAL STATE: Secure Provider + Responsible Customers.\n   The system is working as intended.",
        "Q2: THE VICTIMS":   "SCREAMING INTO THE VOID: Customers have signed ROAs (>60%), but Provider is LEAKING.\n   These providers are negating their customers' hard work.",
        "Q3: WASTED TECH":   "GLASS HOUSES: Provider filters invalids, but Customers (<60%) haven't signed ROAs.\n   The provider's security hardware is idle because customers are lazy.",
        "Q4: THE SWAMP":     "TOTAL FAILURE: Vulnerable Provider + Unsigned Customers.\n   The 'Wild West' of the internet."
    }

    q_order = [
        ("Q1: GOLD STANDARD", "\033[92m"), # Green
        ("Q2: THE VICTIMS",   "\033[93m"), # Yellow
        ("Q3: WASTED TECH",   "\033[96m"), # Cyan
        ("Q4: THE SWAMP",     "\033[91m")  # Red
    ]
    
    for q_name, color in q_order:
        print(f"\n{color}=== {q_name} ===\033[0m")
        print(f"   {definitions[q_name]}")
        print("-" * 110)
        print(f"{'ASN':<8} | {'CC':<2} | {'Cone':<8} | {'% Sign':<6} | {'Name'}")
        print("-" * 110)

        subset = out_df[out_df['Quadrant'] == q_name].sort_values(by='Cone', ascending=False).head(5)
        
        for _, row in subset.iterrows():
            print(f"AS{row['ASN']:<6} | {row['CC']:<2} | {row['Cone']:<8} | {row['Percentile']:>5.1f}% | {row['Name'][:55]}")

    filename = "rov_quadrant_top5_v3.csv"
    out_df.sort_values(by=['Quadrant', 'Cone'], ascending=[True, False]).to_csv(filename, index=False)
    print(f"\n[+] Full quadrant data saved to {filename}")

if __name__ == "__main__":
    analyze()
