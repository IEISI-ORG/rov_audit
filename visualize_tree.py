import json
import argparse
import os
import pandas as pd

# --- CONFIGURATION ---
FILE_GRAPH = "data/downstream_graph.json"
FILE_META = "data/asn_meta.json"
FILE_AUDIT_CSV = "rov_audit_v12.csv"

def load_db():
    if not os.path.exists(FILE_GRAPH): return None, None, None
    
    with open(FILE_GRAPH) as f: downstream = json.load(f)
    with open(FILE_META) as f: meta = json.load(f)
    
    df = pd.read_csv(FILE_AUDIT_CSV)
    status = {}
    for _, r in df.iterrows():
        v = str(r['verdict'])
        if "SECURE" in v or "PROTECTED" in v: s = "SECURE"
        elif "VULNERABLE" in v: s = "VULNERABLE"
        elif "DEAD" in v: s = "DEAD"
        else: s = "UNKNOWN"
        status[r['asn']] = s
        
    return downstream, meta, status

def print_tree(asn, downstream, meta, status, prefix="", level=0, max_depth=2):
    if level > max_depth:
        print(f"{prefix}└── ... (Depth Limit)")
        return

    # Get Info
    asn_str = str(asn)
    name = meta.get(asn_str, {}).get('name', 'Unknown')
    stat = status.get(asn, "UNKNOWN")
    
    # Color
    color = "\033[0m"
    if stat == "SECURE": color = "\033[92m" # Green
    elif stat == "VULNERABLE": color = "\033[91m" # Red
    elif stat == "DEAD": color = "\033[90m" # Grey
    
    # Print Node
    print(f"{prefix}{color}AS{asn} [{stat}] {name}\033[0m")
    
    # Children
    children = downstream.get(asn_str, [])
    # Sort children: Vulnerable first (to highlight problems), then by size
    # We don't have size readily available here without lookups, so just sort by ASN
    children.sort()
    
    count = len(children)
    for i, child in enumerate(children):
        is_last = (i == count - 1)
        connector = "└── " if is_last else "├── "
        new_prefix = prefix + ("    " if is_last else "│   ")
        
        # Recurse
        print_tree(child, downstream, meta, status, prefix + connector, level + 1, max_depth)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Visualize the Downstream Cone of an ASN")
    parser.add_argument("asn", type=int)
    parser.add_argument("--depth", type=int, default=2, help="How deep to visualize (default 2)")
    args = parser.parse_args()
    
    d, m, s = load_db()
    if not d:
        print("[!] Run build_topology.py first.")
    else:
        print(f"\n[*] Visualizing Cone for AS{args.asn} (Max Depth: {args.depth})\n")
        print_tree(args.asn, d, m, s, max_depth=args.depth)
