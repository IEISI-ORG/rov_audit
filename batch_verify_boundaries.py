import pandas as pd
import subprocess
import os
import time

CANDIDATES_FILE = "boundary_candidates.csv"
DIR_ATLAS = "data/atlas"
SCRIPT = "verify_forensic_path_v2.py"

def batch_test(limit=20):
    if not os.path.exists(CANDIDATES_FILE):
        print(f"[!] {CANDIDATES_FILE} not found. Run find_boundary_targets.py first.")
        return

    df = pd.read_csv(CANDIDATES_FILE)
    
    # Filter out already tested with the NEW format (we'll check for 'invalid_path' in the JSON)
    to_test = []
    for asn in df['asn']:
        json_path = os.path.join(DIR_ATLAS, f"as_{asn}.json")
        needs_test = True
        if os.path.exists(json_path):
            try:
                with open(json_path, 'r') as f:
                    import json
                    data = json.load(f)
                    if 'invalid_path' in data:
                        needs_test = False
            except: pass
        
        if needs_test:
            to_test.append(asn)
        
        if len(to_test) >= limit:
            break

    print(f"[*] Starting batch test of {len(to_test)} ASNs...")
    
    for asn in to_test:
        print(f"\n[>] Testing AS{asn}...")
        try:
            # Run the forensic script
            result = subprocess.run(["python3", SCRIPT, "--target", str(asn)], capture_output=True, text=True)
            print(result.stdout)
            if result.stderr:
                print(f"[!] Error: {result.stderr}")
        except Exception as e:
            print(f"[!] Failed to run test for AS{asn}: {e}")
        
        # Brief sleep to avoid hitting API rate limits too hard
        time.sleep(5)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, default=10)
    args = parser.parse_args()
    batch_test(limit=args.limit)
