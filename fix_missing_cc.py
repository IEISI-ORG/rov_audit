import pandas as pd
import socket
import os
import json
import time
import argparse

# --- CONFIGURATION ---
INPUT_CSV = "rov_audit_v18_final.csv"
DIR_JSON = "data/parsed"

def get_xx_targets(csv_file):
    print(f"[*] Scanning {csv_file} for missing Country Codes...")
    if not os.path.exists(csv_file):
        print("    [!] File not found.")
        return []
    
    df = pd.read_csv(csv_file, low_memory=False)
    # Find rows where CC is XX
    missing = df[df['cc'] == 'XX']['asn'].unique().tolist()
    
    # Also verify we have a JSON file for them (we can only fix what we have parsed)
    valid_targets = []
    for asn in missing:
        if os.path.exists(os.path.join(DIR_JSON, f"as_{asn}.json")):
            valid_targets.append(int(asn))
            
    print(f"    - Found {len(valid_targets)} ASNs with 'XX' country code.")
    return valid_targets

def query_team_cymru(asn_list):
    """
    Performs a bulk WHOIS lookup against Team Cymru.
    """
    if not asn_list: return {}
    
    print(f"[*] Querying Team Cymru for {len(asn_list)} ASNs...")
    
    # Chunking (Cymru handles large lists, but let's be safe with 1000 at a time)
    chunk_size = 1000
    results = {}
    
    for i in range(0, len(asn_list), chunk_size):
        chunk = asn_list[i:i + chunk_size]
        
        # Format: "begin\nverbose\nAS123\nAS456\nend"
        query = "begin\nverbose\n" + "\n".join([f"AS{x}" for x in chunk]) + "\nend\n"
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(15)
            s.connect(("whois.cymru.com", 43))
            s.sendall(query.encode('utf-8'))
            
            buffer = b""
            while True:
                data = s.recv(4096)
                if not data: break
                buffer += data
            s.close()
            
            # Parse Response
            # Format: 12345   | US | ARIN | 2000-01-01 | DESCRIPTION
            lines = buffer.decode('utf-8', errors='ignore').splitlines()
            for line in lines:
                parts = [p.strip() for p in line.split('|')]
                if len(parts) >= 2 and parts[0].isdigit():
                    asn = int(parts[0])
                    cc = parts[1].strip().upper()
                    if len(cc) == 2 and cc != "XX":
                        results[asn] = cc
                        
            print(f"    - Processed chunk {i}-{i+len(chunk)}. Found {len(results)} mappings so far...", end="\r")
            time.sleep(0.5)
            
        except Exception as e:
            print(f"    [!] Error in chunk {i}: {e}")

    print(f"\n    - Lookup complete. Retrieved {len(results)} Country Codes.")
    return results

def update_json_cache(mapping):
    print("[*] Patching Local JSON Cache...")
    count = 0
    
    for asn, cc in mapping.items():
        json_path = os.path.join(DIR_JSON, f"as_{asn}.json")
        if os.path.exists(json_path):
            try:
                with open(json_path, 'r') as f:
                    data = json.load(f)
                
                # UPDATE THE CC
                data['cc'] = cc
                
                with open(json_path, 'w') as f:
                    json.dump(data, f, indent=2)
                count += 1
            except: pass
            
    print(f"[+] Successfully patched {count} JSON files.")

def main():
    # 1. Find targets
    targets = get_xx_targets(INPUT_CSV)
    if not targets:
        print("[*] No 'XX' countries found. Your data is clean!")
        return

    # 2. Lookup
    mapping = query_team_cymru(targets)
    
    # 3. Patch
    if mapping:
        update_json_cache(mapping)
        print("\n[SUCCESS] Fix applied.")
        print("1. Run 'python3 rov_no_scrape_v17.py' (Fast Metadata Reload)")
        print("2. Run 'python3 rov_global_audit_v18.py' to generate the fixed CSV.")
    else:
        print("[-] Could not resolve any CCs from Team Cymru.")

if __name__ == "__main__":
    main()
