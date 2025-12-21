import os
import re
import requests

# --- CONFIGURATION ---
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'}
CACHE_FILE = "data/apnic_roa/US.html"
TARGET_ASN = "6939" # Hurricane Electric

def main():
    print(f"[*] inspecting ROA data for AS{TARGET_ASN}...")
    
    html = ""
    
    # 1. Load or Download
    if os.path.exists(CACHE_FILE):
        print(f"    - Reading local cache: {CACHE_FILE}")
        with open(CACHE_FILE, 'r', encoding='utf-8') as f:
            html = f.read()
    else:
        print("    - Cache missing. Downloading US data...")
        try:
            r = requests.get("https://stats.labs.apnic.net/roa/US", headers=HEADERS)
            html = r.text
        except Exception as e:
            print(f"[!] Error: {e}")
            return

    # 2. Find the Line
    print(f"    - Scanning for AS{TARGET_ASN}...")
    found = False
    
    for line in html.splitlines():
        # Look for the ASN link
        if f">AS{TARGET_ASN}<" in line:
            print("\n[!] FOUND RAW LINE:")
            print("-" * 80)
            print(line.strip())
            print("-" * 80)
            found = True
            
            # 3. Test Tokenization
            print("\n[!] TOKENIZATION TEST:")
            # Regex to find numbers
            nums = re.findall(r'(\d+(?:\.\d+)?)', line)
            print(f"    All Numbers found: {nums}")
            
            # Remove the ASN from the list (it's usually the first number found in the link)
            clean_nums = [n for n in nums if n != TARGET_ASN]
            print(f"    Data Numbers:      {clean_nums}")
            
            if len(clean_nums) >= 4:
                print("\n[!] HYPOTHESIS CHECK:")
                print(f"    Index 0: {clean_nums[0]} (Total?)")
                print(f"    Index 1: {clean_nums[1]} (Valid?)")
                print(f"    Index 2: {clean_nums[2]} (Invalid?)")
                print(f"    Index 3: {clean_nums[3]} (Unknown?)")
                print(f"    Last:    {clean_nums[-1]} (%?)")
            break
            
    if not found:
        print("[-] ASN not found in the file. (Maybe it's listed under a different country?)")

if __name__ == "__main__":
    main()
