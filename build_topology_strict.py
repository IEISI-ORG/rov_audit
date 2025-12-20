import json
import glob
import os
from collections import defaultdict

# --- CONFIGURATION ---
DIR_JSON = "data/parsed"
DIR_DATA = "data"

# "The Core" - These should NEVER appear as children in our dependency graph
# Breaking links to these ASNs prevents infinite loops in the cone calculation.
TIER_1_FIREWALL = {
    3356, 1299, 174, 2914, 3257, 6762, 6939, 6453, 3491, 1239, 701, 6461, 5511, 6830, 4637,
    7018, 3320, 12956, 1273, 7922, 209, 2828, 4134, 4809, 4837, 9929, 9808
}

def build_topology():
    print("[*] Building STRICT Topology (Breaking Cycles)...")
    
    # 1. Load Metadata (We need Cone Sizes for logic)
    print("    - Loading metadata phase...")
    meta_map = {}
    files = glob.glob(os.path.join(DIR_JSON, "*.json"))
    
    # We store raw links first: (parent, child)
    raw_links = []
    
    for f in files:
        try:
            with open(f, 'r') as h:
                data = json.load(h)
                asn = data.get('asn')
                if not asn: continue
                
                # Get Stats
                # Use the 'upstream_count_summary' if available, else calc list length
                # We use these to estimate "Gravity"
                meta_map[asn] = {
                    'name': data.get('name', 'Unknown'),
                    'cc': data.get('cc', 'XX'),
                    'cone': data.get('cone_size', 0),
                    'is_tier1': data.get('is_tier1', False)
                }
                
                # In parsed JSON, 'upstreams' are the PARENTS of 'asn'
                # So the link is: Upstream -> ASN
                for p in data.get('upstreams', []):
                    raw_links.append((int(p), asn))
                    
        except: pass

    print(f"    - Loaded {len(meta_map)} ASNs.")
    print(f"    - Processing {len(raw_links)} raw relationships...")

    # 2. Build Graph with Strict Rules
    downstream_map = defaultdict(list)
    stats = {'total': 0, 'kept': 0, 'dropped_t1': 0, 'dropped_peer': 0, 'dropped_gravity': 0}
    
    for parent, child in raw_links:
        stats['total'] += 1
        
        # --- RULE 1: TIER 1 FIREWALL ---
        # A Tier 1 cannot be a child. They are the top of the food chain.
        if child in TIER_1_FIREWALL:
            stats['dropped_t1'] += 1
            continue

        # Get Cone Sizes (Gravity)
        cone_p = meta_map.get(parent, {}).get('cone', 0)
        cone_c = meta_map.get(child, {}).get('cone', 0)

        # --- RULE 2: GIANT PEERING FILTER ---
        # If both are huge (Cone > 5000), they are likely peers, not customer/provider.
        # Exception: If one is TRULY massive (Level3) and the other is just "big" (Comcast), we might keep it.
        # But generally, avoid linking Giants.
        if cone_p > 5000 and cone_c > 5000:
            # Let's check ratio. If Parent is 10x bigger, maybe it's real.
            # If closer, drop it.
            if cone_p < (cone_c * 5):
                stats['dropped_peer'] += 1
                continue

        # --- RULE 3: GRAVITY CHECK ---
        # Parent should generally be bigger than child.
        # Allow some noise, but if Parent is tiny (Cone 5) and Child is big (Cone 1000), it's wrong.
        if cone_c > (cone_p * 2) and cone_c > 100:
            stats['dropped_gravity'] += 1
            continue

        # If we passed all checks, link is valid
        downstream_map[parent].append(child)
        stats['kept'] += 1

    print(f"    - Topology Cleaned.")
    print(f"      Total Links: {stats['total']}")
    print(f"      Kept:        {stats['kept']}")
    print(f"      Dropped (T1 Protection): {stats['dropped_t1']}")
    print(f"      Dropped (Giant Peers):   {stats['dropped_peer']}")
    print(f"      Dropped (Gravity Inv):   {stats['dropped_gravity']}")

    # 3. Save
    with open(os.path.join(DIR_DATA, "downstream_graph.json"), 'w') as f:
        json.dump(downstream_map, f)
    
    # Save meta for the analyzer
    with open(os.path.join(DIR_DATA, "asn_meta.json"), 'w') as f:
        json.dump(meta_map, f)
        
    print("[+] Strict Topology saved to 'data/downstream_graph.json'")

if __name__ == "__main__":
    build_topology()
