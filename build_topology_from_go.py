import json
import glob
import os
import csv
import sys
from collections import defaultdict

# --- CONFIGURATION ---
DIR_JSON = "data/parsed"
DIR_DATA = "data"
FILE_GO_RELATIONSHIPS = "output/relationships.csv" # Output from your Go bgp-extractor

# Tier 1 Firewall (Breaking cycles)
TIER_1_FIREWALL = {
    3356, 1299, 174, 2914, 3257, 6762, 6939, 6453, 3491, 1239, 701, 6461, 5511, 6830, 4637,
    7018, 3320, 12956, 1273, 7922, 209, 2828, 4134, 4809, 4837, 9929, 9808
}

def load_scraped_metadata():
    print("    - Loading scraped metadata (JSON)...")
    meta_map = {}
    files = glob.glob(os.path.join(DIR_JSON, "*.json"))
    for f in files:
        try:
            with open(f, 'r') as h:
                data = json.load(h)
                asn = data.get('asn')
                if asn:
                    meta_map[asn] = {
                        'name': data.get('name', 'Unknown'),
                        'cc': data.get('cc', 'XX'),
                        'cone': data.get('cone_size', 0)
                    }
        except: pass
    return meta_map

def load_go_relationships():
    """
    Parses the CSV from the Go tool.
    Format: From_ASN, To_ASN, Type, Count
    """
    print(f"    - Loading Raw Graph from {FILE_GO_RELATIONSHIPS}...")
    if not os.path.exists(FILE_GO_RELATIONSHIPS):
        print(f"[!] Error: {FILE_GO_RELATIONSHIPS} not found.")
        print("    Did you run the Go bgp-extractor?")
        return None, None

    adj = defaultdict(set)
    degrees = defaultdict(int)
    
    with open(FILE_GO_RELATIONSHIPS, 'r') as f:
        reader = csv.reader(f)
        next(reader, None) # Skip header
        
        for row in reader:
            if len(row) < 3: continue
            
            # Go CSV: From, To, Type, Count
            as1, as2, rel_type = int(row[0]), int(row[1]), row[2]
            
            # Calculate Degree (Total unique neighbors)
            # We treat the raw CSV as an undirected graph for degree calculation
            adj[as1].add(as2)
            adj[as2].add(as1)
    
    # Finalize degrees
    for asn, neighbors in adj.items():
        degrees[asn] = len(neighbors)
        
    return adj, degrees

def build_topology():
    print("[*] Building Topology from RIPE RIS (Go Output)...")
    
    # 1. Load Data
    meta_map = load_scraped_metadata()
    adj, degrees = load_go_relationships()
    
    if not adj: return

    print(f"    - Calculated Node Degrees for {len(degrees)} ASNs.")

    # 2. Build Directed Graph (Provider -> Customer)
    # We apply the "Valley-Free" heuristic here:
    # If A connects to B, and Degree(A) >> Degree(B), then A is Provider.
    
    downstream_map = defaultdict(list)
    stats = {'total': 0, 'kept': 0, 'dropped_peer': 0, 'dropped_t1': 0}
    
    # Iterate over unique links
    processed_links = set()
    
    # adj contains {asn: {neighbor, neighbor...}}
    for as1, neighbors in adj.items():
        for as2 in neighbors:
            # Dedupe: Process pair (min, max) only once
            pair_key = tuple(sorted((as1, as2)))
            if pair_key in processed_links: continue
            processed_links.add(pair_key)
            
            stats['total'] += 1
            
            d1 = degrees[as1]
            d2 = degrees[as2]
            
            provider = None
            customer = None
            
            # --- HEURISTIC: Who is the Provider? ---
            # Provider must be at least 4x bigger than Customer to be transit.
            # Otherwise, assume Peering (no cone inheritance).
            RATIO = 4.0
            
            if d1 > (d2 * RATIO):
                provider, customer = as1, as2
            elif d2 > (d1 * RATIO):
                provider, customer = as2, as1
            else:
                stats['dropped_peer'] += 1
                continue # Likely Peering
            
            # --- RULE: TIER 1 PROTECTION ---
            if customer in TIER_1_FIREWALL:
                stats['dropped_t1'] += 1
                continue
                
            # Valid Link found
            downstream_map[provider].append(customer)
            stats['kept'] += 1

    print(f"    - Graph Built.")
    print(f"      Total Unique Links: {stats['total']:,}")
    print(f"      Kept (Transit):     {stats['kept']:,}")
    print(f"      Dropped (Peering):  {stats['dropped_peer']:,}")
    print(f"      Dropped (T1 Loops): {stats['dropped_t1']:,}")

    # 3. Save
    with open(os.path.join(DIR_DATA, "downstream_graph.json"), 'w') as f:
        json.dump(downstream_map, f)
    
    # Merge new ASNs into meta (if we found ASNs in Go that weren't scraped)
    new_asns = 0
    for asn in degrees.keys():
        if asn not in meta_map:
            meta_map[asn] = {'name': 'Unknown (RIS)', 'cc': 'XX', 'cone': 0}
            new_asns += 1
            
    with open(os.path.join(DIR_DATA, "asn_meta.json"), 'w') as f:
        json.dump(meta_map, f)
        
    print(f"    - Added {new_asns} unscraped ASNs to metadata.")
    print("[+] Topology saved to 'data/downstream_graph.json'")

if __name__ == "__main__":
    build_topology()
