import pandas as pd
import os
import rov_utils

def analyze():
    print("[*] Loading Data for ROA Strategy Report...")
    if not os.path.exists(rov_utils.FILE_AUDIT_FINAL):
        print(f"[!] {rov_utils.FILE_AUDIT_FINAL} not found. Run rov_no_scrape_v21.py first.")
        return

    # 1. Load Audit Results
    df = pd.read_csv(rov_utils.FILE_AUDIT_FINAL, low_memory=False)
    
    # 2. Load topology and signing stats
    cones, downstream, upstreams = rov_utils.load_topology()
    roa_map = rov_utils.load_signing_stats()
    
    df['signed_pct'] = df['asn'].map(roa_map).fillna(0.0)

    # Insight 1: Glass Houses
    print("\n" + "="*95)
    print("1. THE GLASS HOUSES (Secure Providers, Unsigned Routes)")
    print("-" * 95)
    print(f"{'ASN':<8} | {'CC':<2} | {'Cone':<8} | {'Signed%':<8} | {'Name'}")
    print("-" * 95)
    
    is_secure = df['verdict'].str.contains("ACTIVE") | df['verdict'].str.contains("PASSIVE") | df['verdict'].str.contains("PROTECTOR")
    glass = df[is_secure & (df['signed_pct'] < 10.0)].sort_values(by='cone', ascending=False)
    for _, r in glass.head(15).iterrows():
        print(f"AS{r['asn']:<6} | {r['cc']:<2} | {int(r['cone']):<8} | \033[91m{r['signed_pct']:>5.1f}%\033[0m  | {r['name'][:45]}")

    # Insight 2: Screaming into the Void
    print("\n" + "="*95)
    print("2. SCREAMING INTO THE VOID (Fully Signed, Vulnerable Upstreams)")
    print("-" * 95)
    print(f"{'ASN':<8} | {'CC':<2} | {'Cone':<8} | {'Signed%':<8} | {'Name'}")
    print("-" * 95)
    
    is_vuln = df['verdict'].str.contains("VULNERABLE") | df['verdict'].str.contains("UNPROTECTED")
    screaming = df[is_vuln & (df['signed_pct'] > 95.0)].sort_values(by='cone', ascending=False)
    for _, r in screaming.head(15).iterrows():
        print(f"AS{r['asn']:<6} | {r['cc']:<2} | {int(r['cone']):<8} | \033[92m{r['signed_pct']:>5.1f}%\033[0m  | {r['name'][:45]}")

    # Insight 3: Weighted Evangelism Targets
    print("\n" + "="*95)
    print("3. WEIGHTED EVANGELISM TARGETS")
    print("   Metric = (Provider Cone Size) * (Count of Unsigned Customers)")
    print("-" * 95)
    print(f"{'ASN':<8} | {'CC':<2} | {'Cone':<8} | {'Unsigned':<8} | {'Impact Score':<14} | {'Name'}")
    print("-" * 95)
    
    providers = df[df['cone'] > 50].copy()
    evangelism_list = []
    
    for _, row in providers.iterrows():
        asn = int(row['asn'])
        u_cnt, t_cnt = rov_utils.calculate_cone_health(asn, downstream, roa_map)
        if t_cnt > 0:
            impact_score = int(row['cone']) * u_cnt
            evangelism_list.append({
                'asn': asn, 'cc': row['cc'], 'name': row['name'], 'cone': row['cone'],
                'unsigned_customers': u_cnt, 'impact_score': impact_score
            })
            
    evangelism_list.sort(key=lambda x: x['impact_score'], reverse=True)
    for item in evangelism_list[:25]:
        score_str = f"{item['impact_score']:,}"
        print(f"AS{item['asn']:<6} | {item['cc']:<2} | {int(item['cone']):<8} | {item['unsigned_customers']:<8} | {score_str:<14} | {item['name'][:35]}")

    pd.DataFrame(evangelism_list).to_csv("roa_strategy_weighted_v2.csv", index=False)
    print(f"\n[+] Saved strategy to roa_strategy_weighted_v2.csv")

if __name__ == "__main__":
    analyze()
