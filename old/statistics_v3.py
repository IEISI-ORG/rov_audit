import pandas as pd
import argparse
import os
import sys
import requests
import gzip
from io import BytesIO

# --- CONFIGURATION ---
DEFAULT_INPUT = "rov_audit_v18_final.csv"
URL_IPTOASN = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"
HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36'}

def load_ip_counts():
    """
    Downloads IPtoASN and calculates total IPv4 addresses per ASN.
    Returns Dict: { asn_int: ip_count_int }
    """
    print(f"[*] Fetching IP Allocations from {URL_IPTOASN}...")
    asn_ip_map = {}
    
    try:
        resp = requests.get(URL_IPTOASN, headers=HEADERS)
        with gzip.open(BytesIO(resp.content), 'rt') as f:
            for line in f:
                # Format: range_start, range_end, AS_number, country_code, AS_description
                parts = line.split('\t')
                if len(parts) < 3: continue
                
                try:
                    start_ip = int(parts[0])
                    end_ip = int(parts[1])
                    asn = int(parts[2])
                    
                    # Calculate IPs in this block
                    count = end_ip - start_ip + 1
                    
                    if asn not in asn_ip_map: asn_ip_map[asn] = 0
                    asn_ip_map[asn] += count
                except: pass
                
        print(f"    - Mapped IP space for {len(asn_ip_map):,} ASNs.")
        return asn_ip_map
        
    except Exception as e:
        print(f"[!] Failed to load IP data: {e}")
        return {}

def print_header(title):
    print("\n" + "="*95)
    print(f" {title}")
    print("="*95)

def analyze(csv_file):
    if not os.path.exists(csv_file):
        print(f"[!] Error: File {csv_file} not found.")
        return

    # 1. Load Verdicts
    print(f"[*] Loading Audit Data: {csv_file}...")
    try:
        df = pd.read_csv(csv_file, low_memory=False)
    except Exception as e:
        print(f"[!] Error: {e}")
        return

    # 2. Load IP Counts
    ip_map = load_ip_counts()

    # 3. Enrich DataFrame
    # Map the calculated IPs to the ASNs in our audit
    df['ip_count'] = df['asn'].map(ip_map).fillna(0).astype(int)

    # ---------------------------------------------------------
    # ANALYSIS: VERDICT vs IMPACT
    # ---------------------------------------------------------
    print_header("GLOBAL IMPACT ANALYSIS (Unique IPs)")
    
    # Group by Verdict
    stats = df.groupby('verdict').agg(
        Networks=('asn', 'count'),
        IP_Addresses=('ip_count', 'sum')
    ).reset_index()

    # Sort
    stats = stats.sort_values(by='Networks', ascending=False)

    total_asns = len(df)
    total_ips = df['ip_count'].sum()

    print(f"{'VERDICT':<35} | {'Networks':>8} | {'% Net':>7} | {'IP Space (v4)':>15} | {'% IPs':>7}")
    print("-" * 95)

    for _, row in stats.iterrows():
        v = str(row['verdict'])
        cnt = row['Networks']
        ips = row['IP_Addresses']
        
        pct_net = (cnt / total_asns) * 100
        pct_ip = (ips / total_ips) * 100 if total_ips > 0 else 0
        
        # Color
        color = ""
        if "SECURE" in v or "PROTECTED" in v: color = "\033[92m" 
        elif "VULNERABLE" in v or "UNPROTECTED" in v: color = "\033[91m" 
        elif "DEAD" in v: color = "\033[90m" 
        elif "PARTIAL" in v: color = "\033[93m"
        reset = "\033[0m"

        print(f"{color}{v:<35}{reset} | {cnt:>8,} | {pct_net:>6.1f}% | {ips:>15,} | {pct_ip:>6.1f}%")

    # ---------------------------------------------------------
    # SUMMARY
    # ---------------------------------------------------------
    print_header("EXECUTIVE SUMMARY")
    
    # Define Categories
    df['verdict'] = df['verdict'].astype(str)
    
    is_secure = df['verdict'].str.contains("SECURE") | df['verdict'].str.contains("PROTECTED")
    is_vuln = df['verdict'].str.contains("VULNERABLE") | df['verdict'].str.contains("UNPROTECTED")
    is_partial = df['verdict'].str.contains("PARTIAL") | df['verdict'].str.contains("MIXED")
    
    # Calculate
    sec_net = df[is_secure]['asn'].count()
    sec_ip  = df[is_secure]['ip_count'].sum()
    
    vuln_net = df[is_vuln]['asn'].count()
    vuln_ip  = df[is_vuln]['ip_count'].sum()
    
    part_net = df[is_partial]['asn'].count()
    part_ip  = df[is_partial]['ip_count'].sum()

    print(f"Total Networks:   {total_asns:,}")
    print(f"Total IP Space:   {total_ips:,} (Routed IPv4 /24s equivalent: {total_ips/256:,.0f})")
    print("-" * 60)
    
    print(f"\033[92mSECURE:\033[0m     {sec_net:>8,} Networks  ({sec_ip:>15,} IPs)")
    print(f"\033[93mPARTIAL:\033[0m    {part_net:>8,} Networks  ({part_ip:>15,} IPs)")
    print(f"\033[91mVULNERABLE:\033[0m {vuln_net:>8,} Networks  ({vuln_ip:>15,} IPs)")
    
    # Calc percentages of ROUTED space (excluding dead/unrouted)
    routed_ips = sec_ip + vuln_ip + part_ip
    if routed_ips > 0:
        print("-" * 60)
        print(f"Of the active/routed internet:")
        print(f"  - {(sec_ip/routed_ips)*100:.1f}% of IP addresses are fully protected.")
        print(f"  - {(vuln_ip/routed_ips)*100:.1f}% of IP addresses are fully vulnerable.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate IP-based Impact Statistics")
    parser.add_argument("csv_file", nargs='?', default=DEFAULT_INPUT, help="Path to Audit CSV")
    args = parser.parse_args()
    
    analyze(args.csv_file)
