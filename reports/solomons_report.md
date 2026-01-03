    [*] Loading Global Audit for SB...

    ====================================================================================================
     NATIONAL ROUTING SECURITY: SB
    ====================================================================================================
    Total Networks:      11
    Total Cone Gravity:  5
    ------------------------------------------------------------
    SECURE NETWORKS:         0 ( 0.0%) -> Protects 0.0% of Traffic
    VULNERABLE NETWORKS:     8 (72.7%) -> Exposes  40.0% of Traffic

    ====================================================================================================
     THE SB CORE (Top 20 Networks)
    ====================================================================================================
    ASN      | Verdict                        | Cone     | APNIC% | Name
    ----------------------------------------------------------------------------------------------------
    AS139609 | PARTIAL (Mixed Feeds)          | 3        | -      | Solomon Islands Submarine Cable Company
    AS45891  | VULNERABLE (No Coverage)       | 2        | 1%     | Solomon Telekom Co Ltd
    AS139277 | NOT ROUTED                     | 0        | -      | Solomon Islands Government ICT Support D
    AS142279 | STUB: VULNERABLE               | 0        | -      | Solitech Ltd
    AS150403 | STUB: VULNERABLE               | 0        | -      | Solomon Islands National Provident Fund 
    AS150349 | STUB: VULNERABLE               | 0        | -      | Pacific Vaizeds Enterprise Ltd
    AS24013  | STUB: VULNERABLE               | 0        | -      | SB Professional Services
    AS134525 | STUB: VULNERABLE               | 0        | -      | Solomon Telekom Co Ltd
    AS132468 | STUB: VULNERABLE               | 0        | 0%     | SATSOL LIMITED
    AS132462 | STUB: VULNERABLE               | 0        | -      | Bemobile Solomon Islands Ltd
    AS132260 | NOT ROUTED                     | 0        | -      | SATSOL LIMITED

    ====================================================================================================
     TRANSIT SUPPLY CHAIN (Who provides to SB?)
    ====================================================================================================
    [*] Analyzing Upstream Supply Chain for 11 networks...
        - Analyzed connectivity for 11 networks.
    Rank | Upstream | Dependents | Global Status                  | Name
    ----------------------------------------------------------------------------------------------------
    #1   | AS139609 | 4          | PARTIAL (Mixed Feeds)          | Solomon Islands Submarine Cable Company
    #2   | AS45891  | 2          | VULNERABLE (No Coverage)       | Solomon Telekom Co Ltd
    #3   | AS4637   | 1          | CORE: PROTECTED                | Telstra Global
    #4   | AS17559  | 1          | PARTIAL (Mixed Feeds)          | Spectrums Core Network
    #5   | AS135409 | 1          | PARTIAL (Mixed Feeds)          | Kacific Broadband Satellites Pte Ltd
    #6   | AS132468 | 1          | STUB: VULNERABLE               | SATSOL LIMITED
    #7   | AS7594   | 1          | PARTIAL (Mixed Feeds)          | On Q

    ====================================================================================================
     TOP VULNERABLE SB NETWORKS
    ====================================================================================================
    ASN      | Cone     | Feeds  | Name
    --------------------------------------------------------------------------------
    AS45891  | 2        | 1/1    | Solomon Telekom Co Ltd
    AS142279 | 0        | 1/1    | Solitech Ltd
    AS150403 | 0        | 1/1    | Solomon Islands National Provident Fund Board
    AS150349 | 0        | 1/1    | Pacific Vaizeds Enterprise Ltd
    AS24013  | 0        | 11/17  | SB Professional Services
    AS134525 | 0        | 1/1    | Solomon Telekom Co Ltd
    AS132468 | 0        | 1/1    | SATSOL LIMITED
    AS132462 | 0        | 1/1    | Bemobile Solomon Islands Ltd
