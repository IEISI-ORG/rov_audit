    [*] Loading Global Audit for FJ...

    ====================================================================================================
     NATIONAL ROUTING SECURITY: FJ
    ====================================================================================================
    Total Networks:      12
    Total Cone Gravity:  8
    ------------------------------------------------------------
    SECURE NETWORKS:         3 (25.0%) -> Protects 12.5% of Traffic
    VULNERABLE NETWORKS:     6 (50.0%) -> Exposes  0.0% of Traffic

    ====================================================================================================
     THE FJ CORE (Top 20 Networks)
    ====================================================================================================
    ASN      | Verdict                        | Cone     | APNIC% | Name
    ----------------------------------------------------------------------------------------------------
    AS38442  | PARTIAL (Mixed Feeds)          | 5        | 0%     | Vodafone Fiji Limited
    AS4638   | Unverified (Transit/Peer?)     | 2        | 88%    | Telecom Fiji Limited
    AS45355  | SECURE (Full Coverage)         | 1        | 0%     | Digicel Fiji Limited
    AS141470 | STUB: VULNERABLE               | 0        | -      | ITC Services
    AS137890 | STUB: VULNERABLE               | 0        | -      | Walesi Ltd
    AS136921 | STUB: SECURE (Full Coverage)   | 0        | -      | Fiji National University
    AS149429 | STUB: VULNERABLE               | 0        | -      | Reserve Bank of Fiji
    AS24390  | STUB: SECURE (Full Coverage)   | 0        | -      | The University of the South Pacific
    AS9241   | STUB: VULNERABLE               | 0        | -      | Fiji International Telecomunications Ltd
    AS135647 | NOT ROUTED (Registry)          | 0        | -      | Airports Fiji Limited
    AS132248 | STUB: VULNERABLE               | 0        | -      | Reserve Bank of Fiji
    AS45349  | STUB: VULNERABLE               | 0        | -      | Telecom Fiji Ltd

    ====================================================================================================
     TRANSIT SUPPLY CHAIN (Who provides to FJ?)
    ====================================================================================================
    [*] Analyzing Upstream Supply Chain for 12 networks...
        - Analyzed connectivity for 12 networks.
    Rank | Upstream | Dependents | Global Status                  | Name
    ----------------------------------------------------------------------------------------------------
    #1   | AS174    | 3          | CORE: PROTECTED                | Cogent Communications, LLC
    #2   | AS6939   | 3          | CORE: PROTECTED                | Hurricane Electric LLC
    #3   | AS4637   | 3          | CORE: PROTECTED                | Telstra Global
    #4   | AS4638   | 3          | Unverified (Transit/Peer?)     | Telecom Fiji Limited
    #5   | AS7474   | 2          | SECURE (Full Coverage)         | SingTel Optus Pty Ltd
    #6   | AS38442  | 2          | PARTIAL (Mixed Feeds)          | Vodafone Fiji Limited
    #7   | AS7575   | 2          | SECURE (Full Coverage)         | Australian Academic and Research Network
    #8   | AS4648   | 2          | PARTIAL (Mixed Feeds)          | Spark New Zealand
    #9   | AS2914   | 1          | CORE: PROTECTED                | NTT America, Inc.
    #10  | AS7473   | 1          | SECURE (Active Local ROV)      | Singapore Telecommunications Ltd
    #11  | AS45349  | 1          | STUB: VULNERABLE               | Telecom Fiji Ltd
    #12  | AS132528 | 1          | STUB: VULNERABLE               | DIGICEL (AUS) PTY LTD
    #13  | AS45355  | 1          | SECURE (Full Coverage)         | Digicel Fiji Limited

    ====================================================================================================
     TOP VULNERABLE FJ NETWORKS
    ====================================================================================================
    ASN      | Cone     | Feeds  | Name
    --------------------------------------------------------------------------------
    AS141470 | 0        | 1/1    | ITC Services
    AS137890 | 0        | 1/1    | Walesi Ltd
    AS149429 | 0        | 1/1    | Reserve Bank of Fiji
    AS9241   | 0        | 1/3    | Fiji International Telecomunications Ltd
    AS132248 | 0        | 1/1    | Reserve Bank of Fiji
    AS45349  | 0        | 3/7    | Telecom Fiji Ltd
