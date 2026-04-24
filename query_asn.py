import rov_utils
import json
import sys

def query(asn):
    data = rov_utils.load_all_asn_data()
    if asn in data:
        print(json.dumps(data[asn], indent=2))
    else:
        print(f"ASN {asn} not found in packed data.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 query_asn.py <ASN>")
        sys.exit(1)
    
    asn_str = sys.argv[1].upper().replace("AS", "")
    if asn_str.isdigit():
        query(int(asn_str))
    else:
        print("Invalid ASN format.")
