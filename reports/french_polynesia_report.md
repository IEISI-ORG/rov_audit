    [*] Loading Global Audit for PF...

    ====================================================================================================
     NATIONAL ROUTING SECURITY: PF
    ====================================================================================================
    Total Networks:      6
    Total Cone Gravity:  2
    ------------------------------------------------------------
    SECURE NETWORKS:         0 ( 0.0%) -> Protects 0.0% of Traffic
    VULNERABLE NETWORKS:     4 (66.7%) -> Exposes  0.0% of Traffic

    ====================================================================================================
     THE PF CORE (Top 20 Networks)
    ====================================================================================================
    ASN      | Verdict                        | Cone     | APNIC% | Name
    ----------------------------------------------------------------------------------------------------
    AS55943  | PARTIAL (Mixed Feeds)          | 2        | 0%     | ONATI
    AS138179 | STUB: VULNERABLE               | 0        | 0%     | PACIFIC MOBILE TELECOM
    AS139263 | STUB: VULNERABLE               | 0        | -      | Universite de la Polynesie Francaise
    AS9471   | STUB: VULNERABLE               | 0        | 0%     | ONATI
    AS56017  | STUB: VULNERABLE               | 0        | 3%     | VITI
    AS133896 | NOT ROUTED                     | 0        | -      | Tahiti Nui Telecom

    ====================================================================================================
     TRANSIT SUPPLY CHAIN (Who provides to PF?)
    ====================================================================================================
    [*] Analyzing Upstream Supply Chain for 6 networks...
        - Analyzed connectivity for 6 networks.
    Rank | Upstream | Dependents | Global Status                  | Name
    ----------------------------------------------------------------------------------------------------
    #1   | AS55943  | 3          | PARTIAL (Mixed Feeds)          | ONATI
    #2   | AS36149  | 2          | SECURE (Full Coverage)         | Hawaiian Telcom Services Company, Inc.
    #3   | AS3257   | 1          | CORE: PROTECTED                | GTT Communications Inc.
    #4   | AS6939   | 1          | CORE: PROTECTED                | Hurricane Electric LLC
    #5   | AS174    | 1          | CORE: PROTECTED                | Cogent Communications, LLC

    ====================================================================================================
     TOP VULNERABLE PF NETWORKS
    ====================================================================================================
    ASN      | Cone     | Feeds  | Name
    --------------------------------------------------------------------------------
    AS138179 | 0        | 1/1    | PACIFIC MOBILE TELECOM
    AS139263 | 0        | 1/1    | Universite de la Polynesie Francaise
    AS9471   | 0        | 1/1    | ONATI
    AS56017  | 0        | 1/1    | VITI
