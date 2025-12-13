import json
import glob
import os
from collections import defaultdict

# --- CONFIGURATION ---
DIR_JSON = "data/parsed"
DIR_DATA = "data"

# Known Tier 1s (to protect them from being misclassified as children of stubs)
KNOWN_GIANTS = {3356, 1299, 174, 2914, 3257, 6762, 6939, 6453, 3491, 1239, 701, 6461, 5511, 6830, 4637}

def build_topology():
    print("[*] Building Topology with Gravity Checks...")
    
    # 1. Load All Metadata First (We need Cone Sizes for sanity checks)
    print("    - Loading metadata phase...")
    meta_map = {}
    temp_relationships = [] # Stores (child, parent) tuples
    
    files = glob.glob(os.path.join(DIR_JSON, "*.json"))
    
    for f in files:
        try:
            with open(f, 'r') as h:
                data = json.load(h)
                asn = data.get('asn')
                if not asn: continue
                
                # Load Meta
                meta_map[asn] = {
                    'name': data.get('name', 'Unknown'),
                    'cc': data.get('cc', 'XX'),
                    'cone': data.get('cone_size', 0),
                    'is_tier1': data.get('is_tier1', False)
                }
                
                # Store raw relationship for processing
                # data['upstreams'] means: data['asn'] IS DOWNSTREAM OF upstream
                for u in data.get('upstreams', []):
                    temp_relationships.append((asn, int(u)))
        except: pass

    print(f"    - Metadata loaded for {len(meta_map)} ASNs.")
    print(f"    - Processing {len(temp_relationships)} raw relationships...")

    # 2. Build Graph with Sanity Checks
    downstream_map = defaultdict(list)
    dropped_links = 0
    
    for child, parent in temp_relationships:
        # Get Cone Sizes (Default to 0 if unknown)
        cone_c = meta_map.get(child, {}).get('cone', 0)
        cone_p = meta_map.get(parent, {}).get('cone', 0)
        
        # --- GRAVITY CHECK ---
        # A link is suspicious if the Child is massive and the Parent is tiny.
        # Example: Child=174 (Cone 57000), Parent=3 (Cone 5) -> IMPOSSIBLE.
        
        is_impossible = False
        
        # Rule 1: A Giant cannot be downstream of a Stub
        if child in KNOWN_GIANTS and cone_p < 500:
            is_impossible = True
            
        # Rule 2: Generic Cone Logic (Child is 10x bigger than Parent, and Parent is small)
        elif cone_c > 5000 and cone_p < 100:
            is_impossible = True
            
        if is_impossible:
            # print(f"      [!] Pruning Impossible Link: AS{parent} (Cone {cone_p}) -> AS{child} (Cone {cone_c})")
            dropped_links += 1
            continue
            
        # If valid, add to inverted map (Parent -> [Children])
        downstream_map[parent].append(child)

    print(f"    - Graph built. Pruned {dropped_links} impossible links.")
    print(f"    - Identified {len(downstream_map)} valid upstream providers.")

    # 3. Save
    with open(os.path.join(DIR_DATA, "downstream_graph.json"), 'w') as f:
        json.dump(downstream_map, f)
        
    with open(os.path.join(DIR_DATA, "asn_meta.json"), 'w') as f:
        json.dump(meta_map, f)
        
    print("[+] Topology saved successfully.")

if __name__ == "__main__":
    build_topology()
