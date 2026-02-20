    [*] Loading Global Audit for CI...

    ====================================================================================================
     NATIONAL ROUTING SECURITY: CI
    ====================================================================================================
    Total Networks:      18
    Total Cone Gravity:  17
    ------------------------------------------------------------
    SECURE NETWORKS:         2 (11.1%) -> Protects 58.8% of Traffic
    VULNERABLE NETWORKS:    15 (83.3%) -> Exposes  35.3% of Traffic

    ====================================================================================================
     THE CI CORE (Top 20 Networks)
    ====================================================================================================
    ASN      | Verdict                        | Cone     | APNIC% | Name
    ----------------------------------------------------------------------------------------------------
    AS29571  | SECURE (Full Coverage)         | 10       | 4%     | Unknown
    AS36974  | VULNERABLE (No Coverage)       | 6        | 0%     | Unknown
    AS37381  | PARTIAL (Mixed Feeds)          | 1        | 60%    | Unknown
    AS327746 | STUB: VULNERABLE               | 0        | -      | Unknown
    AS327773 | STUB: VULNERABLE               | 0        | -      | Unknown
    AS327974 | STUB: VULNERABLE               | 0        | -      | Unknown
    AS328290 | STUB: VULNERABLE               | 0        | -      | Unknown
    AS328355 | STUB: VULNERABLE               | 0        | -      | Unknown
    AS328025 | STUB: VULNERABLE               | 0        | -      | Unknown
    AS328193 | STUB: VULNERABLE               | 0        | -      | Unknown
    AS329602 | STUB: SECURE (Full Coverage)   | 0        | -      | Unknown
    AS329666 | STUB: VULNERABLE               | 0        | -      | Unknown
    AS329586 | STUB: VULNERABLE               | 0        | -      | Unknown
    AS328729 | STUB: VULNERABLE               | 0        | -      | Unknown
    AS328809 | STUB: VULNERABLE               | 0        | -      | Unknown
    AS329037 | STUB: VULNERABLE               | 0        | -      | Unknown
    AS37190  | STUB: VULNERABLE               | 0        | 1%     | Unknown
    AS36924  | STUB: VULNERABLE               | 0        | 0%     | Unknown

    ====================================================================================================
     TRANSIT SUPPLY CHAIN (Who provides to CI?)
    ====================================================================================================
    [*] Analyzing Upstream Supply Chain for 18 networks...
        - Analyzed connectivity for 17 networks.
    Rank | Upstream | Dependents | Global Status                  | Name
    ----------------------------------------------------------------------------------------------------
    #1   | AS29571  | 5          | SECURE (Full Coverage)         | Unknown
    #2   | AS36974  | 5          | VULNERABLE (No Coverage)       | Unknown
    #3   | AS37282  | 3          | PARTIAL (Mixed Feeds)          | Unknown
    #4   | AS6762   | 2          | CORE: PROTECTED                | Unknown
    #5   | AS5511   | 1          | CORE: PROTECTED                | Unknown
    #6   | AS174    | 1          | CORE: PROTECTED                | Unknown
    #7   | AS6453   | 1          | CORE: PROTECTED                | Unknown
    #8   | AS1273   | 1          | CORE: PROTECTED                | Unknown
    #9   | AS16637  | 1          | PARTIAL (Mixed Feeds)          | Unknown
    #10  | AS3491   | 1          | CORE: PROTECTED                | Unknown
    #11  | AS60171  | 1          | SECURE (Active Local ROV)      | Unknown
    #12  | AS205996 | 1          | PARTIAL (Mixed Feeds)          | Unknown
    #13  | AS328716 | 1          | STUB: SECURE (Full Coverage)   | Unknown
    #14  | AS30844  | 1          | PARTIAL (Mixed Feeds)          | Unknown
    #15  | AS36994  | 1          | PARTIAL (Mixed Feeds)          | Unknown
    #16  | AS37381  | 1          | PARTIAL (Mixed Feeds)          | Unknown
    #17  | AS6713   | 1          | SECURE (Active Local ROV)      | Unknown
    #18  | AS35280  | 1          | Unverified (Transit/Peer?)     | Unknown
    #19  | AS16058  | 1          | STUB: VULNERABLE               | Unknown
    #20  | AS1299   | 1          | CORE: PROTECTED                | Unknown

    ====================================================================================================
     TOP VULNERABLE CI NETWORKS
    ====================================================================================================
    ASN      | Cone     | Feeds  | Name
    --------------------------------------------------------------------------------
    AS36974  | 6        | 2/2    | Unknown
    AS327746 | 0        | 2/2    | Unknown
    AS327773 | 0        | 2/2    | Unknown
    AS327974 | 0        | 1/1    | Unknown
    AS328290 | 0        | 1/1    | Unknown
    AS328355 | 0        | 1/1    | Unknown
    AS328025 | 0        | 1/1    | Unknown
    AS328193 | 0        | 1/1    | Unknown
    AS329666 | 0        | 1/1    | Unknown
    AS329586 | 0        | 1/1    | Unknown
    AS328729 | 0        | 2/2    | Unknown
    AS328809 | 0        | 1/1    | Unknown
    AS329037 | 0        | 1/1    | Unknown
    AS37190  | 0        | 1/2    | Unknown
    AS36924  | 0        | 1/6    | Unknown
