    [*] Loading Global Audit for CK...

    ====================================================================================================
     NATIONAL ROUTING SECURITY: CK
    ====================================================================================================
    Total Networks:      2
    Total Cone Gravity:  0
    ------------------------------------------------------------
    SECURE NETWORKS:         0 ( 0.0%) -> Protects 0.0% of Traffic
    VULNERABLE NETWORKS:     2 (100.0%) -> Exposes  0.0% of Traffic

    ====================================================================================================
     THE CK CORE (Top 20 Networks)
    ====================================================================================================
    ASN      | Verdict                        | Cone     | APNIC% | Name
    ----------------------------------------------------------------------------------------------------
    AS152093 | STUB: VULNERABLE               | 0        | -      | VakaNet Limited
    AS10131  | STUB: VULNERABLE               | 0        | 0%     | Telecom Cook Islands

    ====================================================================================================
     TRANSIT SUPPLY CHAIN (Who provides to CK?)
    ====================================================================================================
    [*] Analyzing Upstream Supply Chain for 2 networks...
        - Analyzed connectivity for 2 networks.
    Rank | Upstream | Dependents | Global Status                  | Name
    ----------------------------------------------------------------------------------------------------
    #1   | AS9507   | 1          | PARTIAL (Mixed Feeds)          | NextHop Pty Ltd
    #2   | AS45177  | 1          | SECURE (Active Local ROV)      | Devoli
    #3   | AS12684  | 1          | PARTIAL (Mixed Feeds)          | SES ASTRA S.A.
    #4   | AS174    | 1          | CORE: PROTECTED                | Cogent Communications, LLC

    ====================================================================================================
     TOP VULNERABLE CK NETWORKS
    ====================================================================================================
    ASN      | Cone     | Feeds  | Name
    --------------------------------------------------------------------------------
    AS152093 | 0        | 2/3    | VakaNet Limited
    AS10131  | 0        | 3/6    | Telecom Cook Islands
