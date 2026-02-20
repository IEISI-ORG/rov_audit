    [*] Loading Global Audit for SB...

    ====================================================================================================
     NATIONAL ROUTING SECURITY: SB
    ====================================================================================================
    Total Networks:      10
    Total Cone Gravity:  5
    ------------------------------------------------------------
    SECURE NETWORKS:         0 ( 0.0%) -> Protects 0.0% of Traffic
    VULNERABLE NETWORKS:     8 (80.0%) -> Exposes  40.0% of Traffic

    ====================================================================================================
     THE SB CORE (Top 20 Networks)
    ====================================================================================================
    ASN      | Verdict                        | Cone     | APNIC% | Name
    ----------------------------------------------------------------------------------------------------
    AS139609 | PARTIAL (Mixed Feeds)          | 3        | -      | Unknown
    AS45891  | VULNERABLE (No Coverage)       | 2        | 2%     | Unknown
    AS142279 | STUB: VULNERABLE               | 0        | -      | Unknown
    AS150349 | STUB: VULNERABLE               | 0        | -      | Unknown
    AS150403 | STUB: VULNERABLE               | 0        | -      | Unknown
    AS24013  | STUB: VULNERABLE               | 0        | -      | Unknown
    AS132468 | STUB: VULNERABLE               | 0        | 0%     | Unknown
    AS132462 | STUB: VULNERABLE               | 0        | 0%     | Unknown
    AS139277 | NOT ROUTED                     | 0        | -      | Unknown
    AS134525 | STUB: VULNERABLE               | 0        | -      | Unknown

    ====================================================================================================
     TRANSIT SUPPLY CHAIN (Who provides to SB?)
    ====================================================================================================
    [*] Analyzing Upstream Supply Chain for 10 networks...
        - Analyzed connectivity for 10 networks.
    Rank | Upstream | Dependents | Global Status                  | Name
    ----------------------------------------------------------------------------------------------------
    #1   | AS139609 | 4          | PARTIAL (Mixed Feeds)          | Unknown
    #2   | AS45891  | 2          | VULNERABLE (No Coverage)       | Unknown
    #3   | AS4637   | 1          | CORE: PROTECTED                | Unknown
    #4   | AS17559  | 1          | PARTIAL (Mixed Feeds)          | Unknown
    #5   | AS135409 | 1          | PARTIAL (Mixed Feeds)          | Unknown
    #6   | AS7594   | 1          | PARTIAL (Mixed Feeds)          | Unknown
    #7   | AS132468 | 1          | STUB: VULNERABLE               | Unknown

    ====================================================================================================
     TOP VULNERABLE SB NETWORKS
    ====================================================================================================
    ASN      | Cone     | Feeds  | Name
    --------------------------------------------------------------------------------
    AS45891  | 2        | 1/1    | Unknown
    AS142279 | 0        | 1/1    | Unknown
    AS150349 | 0        | 1/1    | Unknown
    AS150403 | 0        | 1/1    | Unknown
    AS24013  | 0        | 10/16  | Unknown
    AS132468 | 0        | 1/1    | Unknown
    AS132462 | 0        | 1/1    | Unknown
    AS134525 | 0        | 1/1    | Unknown
