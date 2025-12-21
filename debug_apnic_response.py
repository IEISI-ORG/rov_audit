import requests
import json

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'application/json, text/javascript, */*; q=0.01',
    'Referer': 'https://stats.labs.apnic.net/roa'
}

url = "https://stats.labs.apnic.net/roa/AS3356?hf=1"

print(f"[*] Requesting: {url}")
try:
    resp = requests.get(url, headers=headers, timeout=10)
    print(f"[*] Status Code: {resp.status_code}")
    print(f"[*] Content-Type: {resp.headers.get('Content-Type')}")
    print(f"[*] URL: {resp.url}")
    
    print("\n[Preview First 500 chars]:")
    print(resp.text[:500])
    print("-" * 50)

    print("\n[*] Attempting JSON Decode...")
    data = resp.json()
    print("SUCCESS: JSON Decoded.")
    print(f"Data keys: {data.keys()}")

except json.JSONDecodeError:
    print("FAIL: Response is not valid JSON.")
except Exception as e:
    print(f"ERROR: {e}")
