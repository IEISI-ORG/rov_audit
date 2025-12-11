import pandas as pd
import os
import argparse
import glob
import sys

# --- CONFIGURATION ---
DIR_ATLAS = "data/atlas"

def get_tested_asns():
    """Returns a set of ASNs that already have JSON results in data/atlas/."""
    tested = set()
    files = glob.glob(os.path.join(DIR_ATLAS, "as_*.json"))
    for f in files:
        try:
            base = os.path.basename(f)
            # Extract 1234 from as_1234.json
            asn_part = base.replace("as_", "").replace(".json", "")
            if asn_part.isdigit():
                tested.add(int(asn_part))
        except: pass
    return tested

def find_column(df, keywords):
    """
    Scans dataframe columns to find one that matches a list of keywords.
    Returns the actual column name or None.
    """
    # 1. Exact match attempt
    for col in df.columns:
        if col.lower() in keywords:
            return col
    
    # 2. Partial match attempt
    for col in df.columns:
        for kw in keywords:
            if kw in col.lower():
                return col
    return None

def main():
    parser = argparse.ArgumentParser(description="Find high-value RIPE Atlas targets from an audit CSV.")
    parser.add_argument("csv_file", help="Path to the CSV file (e.g., rov_audit_v10.csv)")
    parser.add_argument("--limit", type=int, default=20, help="Number of targets to display (default: 20)")
    args = parser.parse_args()

    if not os.path.exists(args.csv_file):
        print(f"[!] Error: File not found: {args.csv_file}")
        sys.exit(1)

    print(f"[*] Reading {args.csv_file}...")
    try:
        df = pd.read_csv(args.csv_file)
    except Exception as e:
        print(f"[!] Failed to read CSV: {e}")
        sys.exit(1)

    # --- DYNAMIC COLUMN MAPPING ---
    # We look for columns based on common keywords
    col_asn = find_column(df, ['asn', 'asn_int'])
    col_cone = find_column(df, ['cone', 'cone_size', 'customer_cone'])
    col_verdict = find_column(df, ['verdict', 'status', 'classification'])
    col_name = find_column(df, ['name', 'description', 'org'])

    # Validation
    if not col_asn:
        print("[!] Error: Could not identify an 'ASN' column in the CSV.")
        sys.exit(1)
    
    if not col_cone:
        print("[!] Warning: No 'Cone' column found. Assuming all are targets.")
        # Create a dummy column if missing so logic doesn't break
        df['cone_dummy'] = 1
        col_cone = 'cone_dummy'

    if not col_verdict:
        print("[!] Error: No 'Verdict' or 'Status' column found. Cannot filter for vulnerable hosts.")
        sys.exit(1)

    print(f"    Mapped Columns: ASN='{col_asn}', Cone='{col_cone}', Verdict='{col_verdict}'")

    # --- FILTERING LOGIC ---
    
    # 1. Filter for Transit Providers (Cone > 0)
    # Ensure cone is numeric
    df[col_cone] = pd.to_numeric(df[col_cone], errors='coerce').fillna(0)
    targets = df[df[col_cone] > 0].copy()
    
    # 2. Filter for "No ROV Info"
    # Looking for keywords like "VULNERABLE", "Unverified", "No Coverage"
    # We define what we consider a "Target"
    target_keywords = ["VULNERABLE", "Unverified", "No Coverage", "Missing Data"]
    
    # Create a regex pattern: "VULNERABLE|Unverified|No Coverage" case insensitive
    pattern = "|".join(target_keywords)
    targets = targets[targets[col_verdict].astype(str).str.contains(pattern, case=False, na=False)]
    
    # 3. Filter out already tested
    tested_asns = get_tested_asns()
    
    # Ensure ASN col is int for comparison
    targets[col_asn] = pd.to_numeric(targets[col_asn], errors='coerce').fillna(0).astype(int)
    
    # Exclude tested
    targets = targets[~targets[col_asn].isin(tested_asns)]
    
    # 4. Sort by Cone Size (High impact first)
    targets = targets.sort_values(by=col_cone, ascending=False)
    
    # --- OUTPUT ---
    count = len(targets)
    print(f"[*] Found {count} potential targets (Transit providers with no verified ROV).")
    print(f"    (Excluded {len(tested_asns)} already tested ASNs)")
    
    if count == 0:
        print("[*] No targets found! Good job?")
        sys.exit(0)

    print(f"\nTOP {args.limit} TARGETS FOR RIPE ATLAS:")
    print("="*90)
    
    # Dynamic header format
    print(f"{'ASN':<8} | {'Cone':<8} | {'Verdict':<35} | {'Name'}")
    print("-" * 90)
    
    for _, row in targets.head(args.limit).iterrows():
        asn_val = f"AS{row[col_asn]}"
        cone_val = str(int(row[col_cone]))
        verdict_val = str(row[col_verdict])[:35]
        name_val = str(row[col_name])[:35] if col_name else "Unknown"
        
        print(f"{asn_val:<8} | {cone_val:<8} | {verdict_val:<35} | {name_val}")

    # Helpful hint
    next_asn = targets.iloc[0][col_asn]
    print("\n[>] To test the top target:")
    print(f"    python3 verify_asn_with_atlas_v4.py {next_asn}")

if __name__ == "__main__":
    main()
