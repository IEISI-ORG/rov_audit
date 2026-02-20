    [*] Loading Global Audit for WS...

    ====================================================================================================
     NATIONAL ROUTING SECURITY: WS
    ====================================================================================================
    Total Networks:      6
    Total Cone Gravity:  1
    ------------------------------------------------------------
    SECURE NETWORKS:         2 (33.3%) -> Protects 100.0% of Traffic
    VULNERABLE NETWORKS:     1 (16.7%) -> Exposes  0.0% of Traffic

    ====================================================================================================
     THE WS CORE (Top 20 Networks)
    ====================================================================================================
    ASN      | Verdict                        | Cone     | APNIC% | Name
    ----------------------------------------------------------------------------------------------------
    AS17993  | SECURE (Active Local ROV)      | 1        | 100%   | Unknown
    AS150321 | STUB: SECURE (Full Coverage)   | 0        | -      | Unknown
    AS153053 | STUB: VULNERABLE               | 0        | -      | Unknown
    AS38800  | NOT ROUTED                     | 0        | 1%     | Unknown
    AS38227  | NOT ROUTED                     | 0        | -      | Unknown
    AS139679 | NOT ROUTED                     | 0        | -      | Unknown

    ====================================================================================================
     TRANSIT SUPPLY CHAIN (Who provides to WS?)
    ====================================================================================================
    [*] Analyzing Upstream Supply Chain for 6 networks...
        - Analyzed connectivity for 6 networks.
    Rank | Upstream | Dependents | Global Status                  | Name
    ----------------------------------------------------------------------------------------------------
    #1   | AS9241   | 1          | STUB: VULNERABLE               | Unknown
    #2   | AS4826   | 1          | SECURE (Full Coverage)         | Unknown
    #3   | AS6939   | 1          | CORE: PROTECTED                | Unknown
    #4   | AS174    | 1          | CORE: PROTECTED                | Unknown
    #5   | AS18400  | 1          | PARTIAL (Mixed Feeds)          | Unknown
    #6   | AS132528 | 1          | STUB: VULNERABLE               | Unknown
    #7   | AS38800  | 1          | NOT ROUTED                     | Unknown
    #8   | AS38227  | 1          | NOT ROUTED                     | Unknown

    ====================================================================================================
     TOP VULNERABLE WS NETWORKS
    ====================================================================================================
    ASN      | Cone     | Feeds  | Name
    --------------------------------------------------------------------------------
    AS153053 | 0        | 1/1    | Unknown
