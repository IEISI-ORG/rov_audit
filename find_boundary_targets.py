import pandas as pd
import rov_utils
import os

def find_boundary_candidates():
    print("[*] Identifying ROV Boundary Candidates...")
    
    # 1. Load Audit Data
    if not os.path.exists(rov_utils.FILE_AUDIT_FINAL):
        print(f"[!] Error: {rov_utils.FILE_AUDIT_FINAL} not found.")
        return
    
    df = pd.read_csv(rov_utils.FILE_AUDIT_FINAL)
    
    # 2. Load Topology
    cones, downstream, upstreams = rov_utils.load_topology()
    
    # Create a lookup for verdict by ASN
    verdict_map = pd.Series(df.verdict.values, index=df.asn).to_dict()
    
    candidates = []
    
    for asn, parents in upstreams.items():
        # Target ASN must be VULNERABLE or Unverified
        verdict = verdict_map.get(asn, "Unknown")
        if not ("VULNERABLE" in verdict or "Unverified" in verdict):
            continue
            
        # Target must have at least one SECURE parent
        secure_parents = []
        for p in parents:
            p_verdict = verdict_map.get(p, "Unknown")
            if "SECURE" in p_verdict or "CORE: PROTECTED" in p_verdict:
                secure_parents.append(p)
        
        if secure_parents:
            candidates.append({
                'asn': asn,
                'cone': cones.get(asn, 0),
                'verdict': verdict,
                'secure_parents': secure_parents,
                'parent_count': len(parents)
            })

    # Sort by cone size (High impact first)
    candidates_df = pd.DataFrame(candidates).sort_values(by='cone', ascending=False)
    
    print(f"\nFound {len(candidates_df)} Boundary Candidates.")
    print("="*90)
    print(f"{'ASN':<8} | {'Cone':<8} | {'Verdict':<25} | {'Secure Parents'}")
    print("-" * 90)
    
    for _, row in candidates_df.head(20).iterrows():
        parents_str = ", ".join([f"AS{p}" for p in row['secure_parents'][:3]])
        if len(row['secure_parents']) > 3: parents_str += "..."
        print(f"AS{row['asn']:<6} | {row['cone']:<8} | {row['verdict']:<25} | {parents_str}")

    candidates_df.to_csv("boundary_candidates.csv", index=False)
    print(f"\n[+] Saved candidates to boundary_candidates.csv")

if __name__ == "__main__":
    find_boundary_candidates()
