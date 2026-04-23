import json
import os
import glob
from collections import Counter
import pandas as pd

DIR_ATLAS = "data/atlas"

def analyze_boundaries():
    print("[*] Analyzing Atlas results for Hard ROV Boundaries...")
    
    # Maps boundary ASN -> List of ASNs it protected
    protected_by = {}
    # Count of times an ASN was the "Last Hop" for an invalid packet
    last_hop_counts = Counter()
    
    files = glob.glob(os.path.join(DIR_ATLAS, "as_*.json"))
    
    for f in files:
        try:
            with open(f) as h:
                data = json.load(h)
            
            asn = data.get('asn')
            verdict = data.get('verdict', '')
            notes = data.get('notes', '')
            invalid_path = data.get('invalid_path', [])
            
            # Look for "Filtered by Upstream ASXXXX"
            if "Filtered by Upstream AS" in notes:
                # Extract the ASN from notes
                try:
                    boundary_asn = int(notes.split("AS")[-1].strip())
                    last_hop_counts[boundary_asn] += 1
                    if boundary_asn not in protected_by:
                        protected_by[boundary_asn] = []
                    protected_by[boundary_asn].append(asn)
                except: continue
            
            # If it was filtered locally (last hop was the target)
            elif "Filtered Locally" in notes:
                last_hop_counts[asn] += 1
                
        except Exception as e:
            print(f"[!] Error parsing {f}: {e}")

    if not last_hop_counts:
        print("[-] No hard boundaries identified in Atlas data yet.")
        return

    print(f"\n{'BOUNDARY ASN':<15} | {'HITS':<6} | {'PROTECTED ASNs'}")
    print("-" * 80)
    
    results = []
    for boundary, count in last_hop_counts.most_common():
        protected = ", ".join([f"AS{x}" for x in protected_by.get(boundary, [boundary])])
        print(f"AS{boundary:<13} | {count:<6} | {protected}")
        results.append({
            'boundary_asn': boundary,
            'hit_count': count,
            'protected_list': protected_by.get(boundary, [boundary])
        })
        
    # Save results
    with open("rov_hard_boundaries.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Identified {len(last_hop_counts)} hard boundaries. Saved to rov_hard_boundaries.json")

if __name__ == "__main__":
    analyze_boundaries()
