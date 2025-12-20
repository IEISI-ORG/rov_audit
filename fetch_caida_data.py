import requests
import bz2
import os
import json
import re
from datetime import datetime

# --- CONFIGURATION ---
# CAIDA public dataset (Monthly updates)
# We use a directory listing to find the latest file, or hardcode a recent one.
# For stability, here is the current stable URL structure.
CAIDA_URL = "https://publicdata.caida.org/datasets/as-relationships/serial-2/20241201.as-rel.txt.bz2"
OUTPUT_FILE = "data/caida_relationships.json"
HEADERS = {'User-Agent': 'ResearchScript/1.0'}

def fetch_and_parse_caida():
    print("[*] Downloading CAIDA AS Relationships dataset...")
    print(f"    - Source: {CAIDA_URL}")
    
    try:
        resp = requests.get(CAIDA_URL, headers=HEADERS, stream=True)
        resp.raise_for_status()
        
        # Decompress on the fly
        print("    - Decompressing and parsing (this may take a moment)...")
        decompressed = bz2.decompress(resp.content).decode('utf-8')
        
        relationships = []
        count = 0
        
        # Parse Lines
        # Format: <provider-as>|<customer-as>|-1|source
        # -1 indicates Provider->Customer. 0 indicates Peer.
        for line in decompressed.splitlines():
            if line.startswith("#"): continue
            
            parts = line.split('|')
            if len(parts) < 3: continue
            
            asn1 = int(parts[0])
            asn2 = int(parts[1])
            rel = int(parts[2])
            
            # rel == -1 means ASN1 is Provider, ASN2 is Customer
            if rel == -1:
                relationships.append((asn1, asn2))
                count += 1
                
        print(f"    - Parsed {count:,} Provider->Customer links.")
        
        # Save
        with open(OUTPUT_FILE, 'w') as f:
            json.dump(relationships, f)
        print(f"[+] Saved CAIDA topology to {OUTPUT_FILE}")
        return True

    except Exception as e:
        print(f"[-] Error: {e}")
        return False

if __name__ == "__main__":
    os.makedirs("data", exist_ok=True)
    fetch_and_parse_caida()
