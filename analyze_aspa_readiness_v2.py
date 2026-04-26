import pandas as pd
import os
import rov_utils
from collections import Counter

def print_header(title):
    print("\n" + "="*95)
    print(f" {title}")
    print("="*95)

def analyze():
    print("[*] Loading Data for ASPA Maturity Model...")
    if not os.path.exists(rov_utils.FILE_AUDIT_FINAL):
        print(f"[!] {rov_utils.FILE_AUDIT_FINAL} not found. Run rov_no_scrape_v22.py first.")
        return

    # 1. Load Data
    df = pd.read_csv(rov_utils.FILE_AUDIT_FINAL, low_memory=False)
    asn_data = rov_utils.load_all_asn_data()
    
    # 2. Build Helper Maps
    verdict_map = df.set_index('asn')['verdict'].to_dict()
    name_map = df.set_index('asn')['name'].to_dict()
    cone_map = df.set_index('asn')['cone'].to_dict()
    
    def get_prob(asn):
        v = verdict_map.get(asn, "UNKNOWN")
        if rov_utils.is_secure(v): return 1.0 # High
        if rov_utils.is_partial(v): return 0.4 # Moderate
        return 0.05 # Low/None
    
    results = []
    provider_leverage = Counter()
    probabilistic_leverage = Counter()

    print("[*] Modeling Global ASPA Maturity...")
    
    for asn, data in asn_data.items():
        upstreams = data.get('upstreams', [])
        if not upstreams: continue
        
        # Readiness Score for this ASN to SIGN ASPA
        # 1. Are my providers secure?
        secure_upstreams = sum(1 for u in upstreams if rov_utils.is_secure(verdict_map.get(int(u), "")))
        provider_ratio = secure_upstreams / len(upstreams)
        
        # 2. Am I already good at RPKI (ROA)?
        roa_pct = data.get('roa_signed_pct', 0.0) / 100.0
        
        # Maturity = (Provider Security * 0.6) + (ROA Hygiene * 0.4)
        maturity = (provider_ratio * 0.6) + (roa_pct * 0.4)
        
        results.append({
            'asn': asn,
            'cc': data.get('cc', 'XX'),
            'name': name_map.get(asn, "Unknown"),
            'upstreams': len(upstreams),
            'secure_upstreams': secure_upstreams,
            'roa_pct': roa_pct * 100,
            'maturity': maturity * 100
        })
        
        # For the "Enforcers" analysis
        for p in upstreams:
            p_asn = int(p)
            provider_leverage[p_asn] += 1
            probabilistic_leverage[p_asn] += (1 * get_prob(p_asn))

    # --- REPORTING ---
    res_df = pd.DataFrame(results)
    
    print_header("1. THE REALITY OF ASPA ENFORCEMENT")
    total_links = sum(provider_leverage.values())
    theoretical_top100 = sum(cnt for _, cnt in provider_leverage.most_common(100))
    realistic_top100 = sum(cnt for _, cnt in probabilistic_leverage.most_common(100))
    
    print(f"Total Customer-to-Provider Links: {total_links:,}")
    print(f"Theoretical Max Protection (Top 100 Providers): {theoretical_top100:,} links ({theoretical_top100/total_links*100:.1f}%)")
    print(f"Realistic Forecast (Weighted by current ROV status): {int(realistic_top100):,} links ({realistic_top100/total_links*100:.1f}%)")
    
    gap = theoretical_top100 - realistic_top100
    print(f"\n[!] THE REALITY GAP: {int(gap):,} links are dependent on providers who currently FAIL at ROV.")
    print("    These networks cannot be expected to enforce ASPA until they fix their ROV baseline.")

    print_header("2. TOP 15 'READY-TO-SIGN' GIANTS")
    print("Networks with 100% ROA hygiene and 100% Secure Upstreams.")
    print("-" * 105)
    print(f"{'ASN':<8} | {'CC':<2} | {'Maturity':<10} | {'ROA%':<6} | {'Ups':<4} | {'Name'}")
    print("-" * 105)
    
    # Filter for giants (cone > 100) who are ready
    giants_ready = res_df[res_df['asn'].map(cone_map) > 100].sort_values(by='maturity', ascending=False)
    for _, r in giants_ready.head(15).iterrows():
        print(f"AS{int(r['asn']):<6} | {r['cc']:<2} | {r['maturity']:>8.1f}% | {r['roa_pct']:>5.1f}% | {int(r['upstreams']):<4} | {r['name'][:50]}")

    print_header("3. THE ASPA 'IMPOSSIBLES'")
    print("Networks with >10 upstreams but 0% ROA hygiene. ASPA is a distant dream for them.")
    print("-" * 105)
    print(f"{'ASN':<8} | {'CC':<2} | {'Upstreams':<10} | {'Name'}")
    print("-" * 105)
    impossibles = res_df[(res_df['upstreams'] > 10) & (res_df['roa_pct'] == 0)].sort_values(by='upstreams', ascending=False)
    for _, r in impossibles.head(10).iterrows():
        print(f"AS{int(r['asn']):<6} | {r['cc']:<2} | {int(r['upstreams']):<10} | {r['name'][:70]}")

if __name__ == "__main__":
    analyze()
