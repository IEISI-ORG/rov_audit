import pandas as pd
import argparse
import os
import sys

# --- CONFIGURATION ---
DEFAULT_INPUT = "rov_audit_v18_final.csv"

# --- STATIC MAPPING (ISO-2 -> RIR/Region) ---
def get_geo_info(cc):
    cc = str(cc).upper()
    
    # 0. UNKNOWN / MULTI-NATIONAL
    if cc == 'XX': 
        return "Unknown/Global", "Unknown"
    
    # 1. SPECIAL / RESERVED
    if cc == 'EU': return "Europe", "RIPE NCC"
    
    # 2. NORTH AMERICA (ARIN)
    if cc in ['US', 'CA', 'PR', 'VI', 'UM']: 
        return "Americas", "ARIN"
    
    # 3. LATIN AMERICA (LACNIC)
    if cc in ['BR', 'MX', 'AR', 'CL', 'CO', 'PE', 'VE', 'UY', 'PY', 'BO', 'EC', 'CR', 'PA', 'DO', 'GT', 'HN', 'SV', 'NI', 'CU']: 
        return "Americas", "LACNIC"
    
    # 4. EUROPE / MIDDLE EAST / RUSSIA (RIPE)
    # Common codes found in BGP data
    if cc in ['GB', 'DE', 'FR', 'NL', 'IT', 'ES', 'RU', 'UA', 'PL', 'SE', 'NO', 'FI', 'DK', 'CH', 'AT', 'BE', 'CZ', 'IE', 'RO', 'TR', 'IL', 'SA', 'AE', 'IR', 'GR', 'PT', 'HU', 'SK', 'BG', 'HR', 'RS', 'SI', 'EE', 'LV', 'LT']:
        return "Europe/ME", "RIPE NCC"
        
    # 5. ASIA / PACIFIC (APNIC)
    if cc in ['CN', 'IN', 'JP', 'KR', 'SG', 'ID', 'TH', 'MY', 'VN', 'PH', 'PK', 'BD', 'HK', 'TW', 'NP', 'LK', 'MM', 'KH']:
        return "Asia", "APNIC"
    if cc in ['AU', 'NZ', 'FJ', 'PG', 'NC', 'PF']:
        return "Pacific", "APNIC"

    # 6. AFRICA (AFRINIC)
    # Often grouped in EMEA by businesses, but for RIR stats we want them separate
    if cc in ['ZA', 'NG', 'KE', 'EG', 'MA', 'GH', 'TZ', 'UG', 'AO', 'DZ', 'SD', 'ET', 'SN', 'ZM', 'ZW']:
        return "Africa", "AFRINIC"

    # FALLBACKS (The Long Tail)
    # If we missed a specific country, we default to "Other"
    return "Other", "Other"

def print_header(title):
    print("\n" + "="*95)
    print(f" {title}")
    print("="*95)

def print_immunity_bar(label, secure_cone, total_cone, count_sec, count_total):
    if total_cone == 0:
        pct = 0.0
    else:
        pct = (secure_cone / total_cone) * 100.0
    
    # Color
    color = "\033[91m" # Red
    if pct > 60: color = "\033[93m" # Yellow
    if pct > 80: color = "\033[92m" # Green
    
    # Bar
    bar_len = 30
    filled = int(bar_len * (pct / 100))
    bar = "█" * filled + "░" * (bar_len - filled)
    
    print(f"{label:<20} | {color}{pct:>5.1f}% Protected  | [{color}{bar}\033[0m] | Networks: {count_sec}/{count_total}")

def analyze_group(df, group_name, top_n=20):
    print_header(f"ANALYSIS BY {group_name.upper()}")
    
    groups = df.groupby(group_name)
    
    summary_data = []
    
    for name, group in groups:
        total_cone = group['cone'].sum()
        if total_cone < 100: continue # Skip empty groups
        
        # Secure = Local ROV or Inherited
        secure = group[group['verdict'].str.contains("SECURE") | group['verdict'].str.contains("PROTECTED")]
        secure_cone = secure['cone'].sum()
        
        summary_data.append({
            'name': name,
            'total_cone': total_cone,
            'secure_cone': secure_cone,
            'pct': (secure_cone / total_cone) * 100,
            'count': len(group),
            'secure_count': len(secure)
        })
        
    # Sort by Total Volume (Impact)
    summary_data.sort(key=lambda x: x['total_cone'], reverse=True)
    
    for d in summary_data:
        print_immunity_bar(d['name'], d['secure_cone'], d['total_cone'], d['secure_count'], d['count'])

    # Drill Down
    print(f"\n[TOP {top_n} VULNERABLE GIANTS PER {group_name.upper()}]")
    
    for d in summary_data:
        g_name = d['name']
        print(f"\n--- {g_name} ---")
        
        subset = df[df[group_name] == g_name]
        vuln = subset[subset['verdict'].str.contains("VULNERABLE") | subset['verdict'].str.contains("UNPROTECTED")]
        
        # Sort by Cone
        vuln = vuln.sort_values(by='cone', ascending=False).head(top_n)
        
        if len(vuln) == 0:
            print("  \033[92m(All major networks secure)\033[0m")
        
        for _, r in vuln.iterrows():
            ups = f"{r['dirty_feeds']}/{r['total_feeds']}"
            print(f"  AS{r['asn']:<6} | {r['cc']} | Cone:{r['cone']:<7} | Feeds:{ups:<5} | {r['name'][:45]}")

def analyze_countries(df):
    print_header("DEEP DIVE: TOP 20 STRATEGIC COUNTRIES")
    
    # Filter for countries with significant internet presence (Cone sum)
    # Exclude XX from Country list
    df_clean = df[df['cc'] != 'XX']
    cc_stats = df_clean.groupby('cc')['cone'].sum().sort_values(ascending=False).head(20)
    top_countries = cc_stats.index.tolist()
    
    for cc in top_countries:
        subset = df[df['cc'] == cc]
        
        total_cone = subset['cone'].sum()
        secure = subset[subset['verdict'].str.contains("SECURE") | subset['verdict'].str.contains("PROTECTED")]
        secure_cone = secure['cone'].sum()
        
        print("-" * 60)
        print_immunity_bar(f"Country: {cc}", secure_cone, total_cone, len(secure), len(subset))
        
        # Top 10 Offenders
        vuln = subset[subset['verdict'].str.contains("VULNERABLE") | subset['verdict'].str.contains("UNPROTECTED")]
        vuln = vuln.sort_values(by='cone', ascending=False).head(5)
        
        if not vuln.empty:
            for _, r in vuln.iterrows():
                print(f"Vulnerable: AS{r['asn']:<6} {r['name'][:50]}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("csv_file", nargs='?', default=DEFAULT_INPUT)
    args = parser.parse_args()

    if not os.path.exists(args.csv_file):
        print("File not found.")
        return

    print(f"[*] Loading {args.csv_file}...")
    df = pd.read_csv(args.csv_file, low_memory=False)
    
    # Clean Data
    df['cone'] = pd.to_numeric(df['cone'], errors='coerce').fillna(0).astype(int)
    # We allow all cone sizes for regional stats, but maybe filter tiny stubs?
    # Let's keep Cone > 0 to filter dead/unrouted
    df = df[df['cone'] > 0]
    
    # Enrich
    print("[*] Mapping Regions & RIRs...")
    geo_data = df['cc'].apply(lambda x: get_geo_info(x))
    df['region'] = [g[0] for g in geo_data]
    df['rir'] = [g[1] for g in geo_data]

    # Analyze
    analyze_group(df, 'region', top_n=10)
    analyze_group(df, 'rir', top_n=10)
    analyze_countries(df)

if __name__ == "__main__":
    main()
