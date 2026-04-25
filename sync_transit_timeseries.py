import pandas as pd
import os
import rov_utils
import concurrent.futures
import time

def sync_asn(row):
    asn = int(row['asn'])
    cc = row['cc']
    if not cc or pd.isna(cc) or cc == "XX":
        return None
    
    # We use the internal fetcher which handles caching (7-day TTL)
    rates = rov_utils._fetch_apnic_ts_rates(asn, cc)
    return (asn, len(rates))

def main():
    if not os.path.exists(rov_utils.FILE_AUDIT_FINAL):
        print(f"[!] {rov_utils.FILE_AUDIT_FINAL} not found.")
        return

    df = pd.read_csv(rov_utils.FILE_AUDIT_FINAL)
    # Define transit as cone > 0
    transit_df = df[df['cone'] > 0].copy()
    
    print(f"[*] Found {len(transit_df):,} transit ASNs.")
    
    # Optional: filter out those already recently fetched if we want to save time
    # but _fetch_apnic_ts_rates already has a 7-day TTL cache check.
    
    start_time = time.time()
    processed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(sync_asn, row) for _, row in transit_df.iterrows()]
        for future in concurrent.futures.as_completed(futures):
            processed += 1
            if processed % 500 == 0:
                print(f"  Processed {processed}/{len(transit_df)}...")
            
    duration = time.time() - start_time
    print(f"\n[SUCCESS] Synced {processed} transit ASNs in {duration:.2f} seconds.")

if __name__ == "__main__":
    main()
