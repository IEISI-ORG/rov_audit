    [*] Loading Global Audit for PF...

    ====================================================================================================
     NATIONAL ROUTING SECURITY: PF
    ====================================================================================================
    Total Networks:      4
    Total Cone Gravity:  2
    ------------------------------------------------------------
    SECURE NETWORKS:         0 ( 0.0%) -> Protects 0.0% of Traffic
    VULNERABLE NETWORKS:     3 (75.0%) -> Exposes  0.0% of Traffic

    ====================================================================================================
     THE PF CORE (Top 20 Networks)
    ====================================================================================================
    ASN      | Verdict                        | Cone     | APNIC% | Name
    ----------------------------------------------------------------------------------------------------
    AS55943  | PARTIAL (Mixed Feeds)          | 2        | 0%     | Unknown
    AS9471   | STUB: VULNERABLE               | 0        | 0%     | Unknown
    AS138179 | STUB: VULNERABLE               | 0        | 0%     | Unknown
    AS56017  | STUB: VULNERABLE               | 0        | 0%     | Unknown

    ====================================================================================================
     TRANSIT SUPPLY CHAIN (Who provides to PF?)
    ====================================================================================================
    [*] Analyzing Upstream Supply Chain for 4 networks...
        - Analyzed connectivity for 4 networks.
    Rank | Upstream | Dependents | Global Status                  | Name
    ----------------------------------------------------------------------------------------------------
    #1   | AS55943  | 3          | PARTIAL (Mixed Feeds)          | Unknown
    #2   | AS36149  | 2          | SECURE (Full Coverage)         | Unknown
    #3   | AS3257   | 1          | CORE: PROTECTED                | Unknown
    #4   | AS6939   | 1          | CORE: PROTECTED                | Unknown
    #5   | AS174    | 1          | CORE: PROTECTED                | Unknown

    ====================================================================================================
     TOP VULNERABLE PF NETWORKS
    ====================================================================================================
    ASN      | Cone     | Feeds  | Name
    --------------------------------------------------------------------------------
    AS9471   | 0        | 1/1    | Unknown
    AS138179 | 0        | 1/1    | Unknown
    AS56017  | 0        | 1/1    | Unknown
