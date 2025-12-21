import requests
import json
import argparse

# --- CONFIGURATION ---
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'}

def check_apnic(asn):
    print(f"\n[1] Checking APNIC Labs for AS{asn}...")
    url = f"https://stats.labs.apnic.net/roa/AS{asn}?hf=1"
    
    try:
        resp = requests.get(url, headers=HEADERS, timeout=10)
        data = resp.json()
        
        # Get Time Series
        series = data.get('data', [])
        if not series:
            print("    [!] No data series found.")
            return
            
        latest = series[-1]
        print("    [Raw Latest Record]:")
        print(f"    {json.dumps(latest, indent=4)}")
        
        # Manual Calculation check
        # We look for these specific keys seen in your previous screenshot
        total = latest.get('ras_v4_robjs', 0)
        valid = latest.get('ras_v4_val_robjs', 0)
        
        print(f"\n    [Calculated]:")
        print(f"    Total IPv4 Routes: {total}")
        print(f"    Valid ROAs:        {valid}")
        if total > 0:
            print(f"    Signed %:          {(valid/total)*100:.2f}%")
        else:
            print(f"    Signed %:          0.00%")

    except Exception as e:
        print(f"    [!] Error: {e}")

def check_ripe(asn):
    print(f"\n[2] Checking RIPEstat for AS{asn}...")
    # This endpoint lists ALL ROAs published by the ASN
    url = f"https://stat.ripe.net/data/rpki-roas/data.json?resource={asn}"
    
    try:
        resp = requests.get(url, headers=HEADERS, timeout=10)
        data = resp.json()
        
        roas = data.get('data', {}).get('roas', [])
        count = len(roas)
        
        print(f"    [RIPE Database]:")
        print(f"    Found {count:,} published ROAs for AS{asn}.")
        
        if count > 0:
            print("    -> Example:", roas[0])
            print("\n    [CONCLUSION]: The network HAS signed ROAs.")
        else:
            print("\n    [CONCLUSION]: The network has NO signed ROAs.")
            
    except Exception as e:
        print(f"    [!] Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("asn", type=int, default=3356, nargs="?")
    args = parser.parse_args()
    
    print(f"[*] FORENSIC DATA CHECK: AS{args.asn}")
    check_apnic(args.asn)
    check_ripe(args.asn)

