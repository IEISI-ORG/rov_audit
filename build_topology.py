import json
import glob
import os
from collections import defaultdict

DIR_JSON = "data/parsed"
DIR_DATA = "data"

def build_topology():
    print("[*] Inverting Network Graph (Upstreams -> Downstreams)...")
    
    # Structure: parent_asn -> list of child_asns
    downstream_map = defaultdict(list)
    
    # Metadata map for quick lookups later
    meta_map = {}
    
    files = glob.glob(os.path.join(DIR_JSON, "*.json"))
    print(f"    - Processing {len(files)} JSON files...")
    
    count = 0
    for f in files:
        try:
            with open(f, 'r') as h:
                data = json.load(h)
                asn = data.get('asn')
                
                if not asn: continue
                
                # Store Meta
                meta_map[asn] = {
                    'name': data.get('name', 'Unknown'),
                    'cc': data.get('cc', 'XX'),
                    'cone': data.get('cone_size', 0)
                }
                
                # Invert Relationships
                # If 'asn' says 'u' is an upstream, then 'asn' is a downstream of 'u'
                for u in data.get('upstreams', []):
                    downstream_map[int(u)].append(asn)
                    
            count += 1
        except: pass

    print(f"    - Graph built. Identified {len(downstream_map)} upstream providers.")

    # Save
    with open(os.path.join(DIR_DATA, "downstream_graph.json"), 'w') as f:
        json.dump(downstream_map, f)
        
    with open(os.path.join(DIR_DATA, "asn_meta.json"), 'w') as f:
        json.dump(meta_map, f)
        
    print("[+] Topology saved to 'data/downstream_graph.json'")

if __name__ == "__main__":
    build_topology()
