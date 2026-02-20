    [*] Loading Global Audit for FJ...

    ====================================================================================================
     NATIONAL ROUTING SECURITY: FJ
    ====================================================================================================
    Total Networks:      13
    Total Cone Gravity:  11
    ------------------------------------------------------------
    SECURE NETWORKS:         4 (30.8%) -> Protects 18.2% of Traffic
    VULNERABLE NETWORKS:     7 (53.8%) -> Exposes  0.0% of Traffic

    ====================================================================================================
     THE FJ CORE (Top 20 Networks)
    ====================================================================================================
    ASN      | Verdict                        | Cone     | APNIC% | Name
    ----------------------------------------------------------------------------------------------------
    AS38442  | PARTIAL (Mixed Feeds)          | 7        | 0%     | Unknown
    AS45355  | SECURE (Full Coverage)         | 2        | 1%     | Unknown
    AS4638   | Unverified (Transit/Peer?)     | 2        | 87%    | Unknown
    AS141470 | STUB: VULNERABLE               | 0        | -      | Unknown
    AS142245 | STUB: SECURE (Full Coverage)   | 0        | -      | Unknown
    AS149429 | STUB: VULNERABLE               | 0        | -      | Unknown
    AS24390  | STUB: SECURE (Full Coverage)   | 0        | -      | Unknown
    AS9241   | STUB: VULNERABLE               | 0        | -      | Unknown
    AS132248 | STUB: VULNERABLE               | 0        | -      | Unknown
    AS137890 | STUB: VULNERABLE               | 0        | -      | Unknown
    AS136921 | STUB: SECURE (Full Coverage)   | 0        | -      | Unknown
    AS135647 | STUB: VULNERABLE               | 0        | -      | Unknown
    AS45349  | STUB: VULNERABLE               | 0        | -      | Unknown

    ====================================================================================================
     TRANSIT SUPPLY CHAIN (Who provides to FJ?)
    ====================================================================================================
    [*] Analyzing Upstream Supply Chain for 13 networks...
        - Analyzed connectivity for 12 networks.
    Rank | Upstream | Dependents | Global Status                  | Name
    ----------------------------------------------------------------------------------------------------
    #1   | AS174    | 3          | CORE: PROTECTED                | Unknown
    #2   | AS6939   | 3          | CORE: PROTECTED                | Unknown
    #3   | AS4637   | 3          | CORE: PROTECTED                | Unknown
    #4   | AS4638   | 3          | Unverified (Transit/Peer?)     | Unknown
    #5   | AS7474   | 2          | SECURE (Full Coverage)         | Unknown
    #6   | AS38442  | 2          | PARTIAL (Mixed Feeds)          | Unknown
    #7   | AS7575   | 2          | SECURE (Full Coverage)         | Unknown
    #8   | AS4648   | 2          | PARTIAL (Mixed Feeds)          | Unknown
    #9   | AS2914   | 1          | CORE: PROTECTED                | Unknown
    #10  | AS7473   | 1          | SECURE (Active Local ROV)      | Unknown
    #11  | AS132528 | 1          | STUB: VULNERABLE               | Unknown
    #12  | AS45349  | 1          | STUB: VULNERABLE               | Unknown
    #13  | AS45355  | 1          | SECURE (Full Coverage)         | Unknown

    ====================================================================================================
     TOP VULNERABLE FJ NETWORKS
    ====================================================================================================
    ASN      | Cone     | Feeds  | Name
    --------------------------------------------------------------------------------
    AS141470 | 0        | 1/1    | Unknown
    AS149429 | 0        | 1/1    | Unknown
    AS9241   | 0        | 1/3    | Unknown
    AS132248 | 0        | 1/1    | Unknown
    AS137890 | 0        | 1/1    | Unknown
    AS135647 | 0        | 1/1    | Unknown
    AS45349  | 0        | 3/7    | Unknown
