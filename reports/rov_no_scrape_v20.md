    [1/6] Loading Metadata & Geography...
        - Fetching BGP.Tools ASN Names... FAIL (429 Client Error: Too Many Requests for url: https://bgp.tools/asns.csv)
        - Fetching IPv4 Geo... OK (438,797 rows)
        - Fetching IPv6 Geo... OK (111,857 rows)
        - Final Geo-Map: 240 Countries.
    [2/6] Syncing APNIC RPKI Data (240 Countries)...
        - Sync: 231 Fetched, 0 Cached.
    [3/6] Loading Security Data...
        - Fetching ROV Tags... OK (37 KB)
        - Fetching Cloudflare List... OK (19 KB)
        - Loaded: 1254 Tagged, 455 CF-Safe, 19906 APNIC
    [4/6] Building Topology (RIS)...
    [5/6] Calculating Cone Sizes...
    [6/6] Generating Audit...

    ================================================================================
    NO-SCRAPE GLOBAL AUDIT (V20 - CC FIXED)
    ================================================================================
    Total Networks:          86,184
    Vulnerable Providers:    512
    ASNs Fixed via Cymru:    (See log above)

    [+] Saved to rov_audit_v20_final.csv
