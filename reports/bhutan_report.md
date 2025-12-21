    [*] Loading Global Audit for BT...

    ====================================================================================================
     NATIONAL ROUTING SECURITY: BT
    ====================================================================================================
    Total Networks:      24
    Total Cone Gravity:  10
    ------------------------------------------------------------
    SECURE NETWORKS:         2 ( 8.3%) -> Protects 0.0% of Traffic
    VULNERABLE NETWORKS:    18 (75.0%) -> Exposes  0.0% of Traffic

    ====================================================================================================
     THE BT CORE (Top 20 Networks)
    ====================================================================================================
    ASN      | Verdict                        | Cone     | APNIC% | Name
    ----------------------------------------------------------------------------------------------------
    AS17660  | PARTIAL (Mixed Feeds)          | 9        | 0%     | DrukNet ISP
    AS18024  | Unverified (Transit/Peer?)     | 1        | 0%     | Bhutan Telecom Ltd
    AS7615   | STUB: VULNERABLE               | 0        | -      | Bhutan Internet Exchange
    AS18025  | STUB: VULNERABLE               | 0        | -      | Bhutan Telecom Ltd
    AS23955  | STUB: VULNERABLE               | 0        | 75%    | Tashi InfoComm Limited
    AS38004  | STUB: SECURE (Active ROV)      | 0        | 100%   | FastLink Wireless ISP, DrukCom Pvt. Ente
    AS132232 | STUB: VULNERABLE               | 0        | -      | Data Centre Services
    AS132894 | STUB: VULNERABLE               | 0        | 0%     | Sigma Internet Service
    AS134715 | STUB: VULNERABLE               | 0        | 0%     | Government Technology Agency
    AS135147 | STUB: VULNERABLE               | 0        | -      | T Bank Limited
    AS135666 | STUB: VULNERABLE               | 0        | -      | Government Data Center (DITT/MoIC)
    AS136039 | STUB: VULNERABLE               | 0        | 1%     | NANO, Bhutan
    AS137412 | STUB: SECURE (Active ROV)      | 0        | 99%    | Tashicell Domestic AS Thimphu Bhutan
    AS137925 | NOT ROUTED (Registry)          | 0        | -      | GIC-Bhutan Reinsurance Co. Ltd.
    AS137994 | NOT ROUTED (Registry)          | 0        | -      | Bhutan National Bank limited
    AS138529 | STUB: VULNERABLE               | 0        | 0%     | DATANET WIFI
    AS138558 | STUB: VULNERABLE               | 0        | 0%     | Gelephu Digital Network
    AS140695 | STUB: VULNERABLE               | 0        | -      | Bank of Bhutan Limited
    AS141680 | STUB: VULNERABLE               | 0        | 0%     | SuperNet Infocomm
    AS151498 | STUB: VULNERABLE               | 0        | -      | Bhutan Power Corporation Ltd

    ====================================================================================================
     TRANSIT SUPPLY CHAIN (Who provides to BT?)
    ====================================================================================================
    [*] Analyzing Upstream Supply Chain for 24 networks...
        - Analyzed connectivity for 24 networks.
    Rank | Upstream | Dependents | Global Status                  | Name
    ----------------------------------------------------------------------------------------------------
    #1   | AS38740  | 15         | PARTIAL (Mixed Feeds)          | Tashi InfoComm Limited
    #2   | AS17660  | 10         | PARTIAL (Mixed Feeds)          | DrukNet ISP
    #3   | AS18024  | 6          | Unverified (Transit/Peer?)     | Bhutan Telecom Ltd
    #4   | AS6453   | 2          | CORE: PROTECTED                | TATA Communications (America) Inc
    #5   | AS136039 | 2          | STUB: VULNERABLE               | NANO, Bhutan
    #6   | AS2914   | 1          | CORE: PROTECTED                | NTT America, Inc.
    #7   | AS9498   | 1          | SECURE (Full Coverage)         | Bharti Airtel Ltd.

    ====================================================================================================
     TOP VULNERABLE BT NETWORKS
    ====================================================================================================
    ASN      | Cone     | Feeds  | Name
    --------------------------------------------------------------------------------
    AS7615   | 0        | 1/1    | Bhutan Internet Exchange
    AS18025  | 0        | 1/1    | Bhutan Telecom Ltd
    AS23955  | 0        | 1/1    | Tashi InfoComm Limited
    AS132232 | 0        | 2/2    | Data Centre Services
    AS132894 | 0        | 1/1    | Sigma Internet Service
    AS134715 | 0        | 2/2    | Government Technology Agency
    AS135147 | 0        | 1/1    | T Bank Limited
    AS135666 | 0        | 2/2    | Government Data Center (DITT/MoIC)
    AS136039 | 0        | 1/2    | NANO, Bhutan
    AS138529 | 0        | 2/2    | DATANET WIFI
    AS138558 | 0        | 2/2    | Gelephu Digital Network
    AS140695 | 0        | 1/1    | Bank of Bhutan Limited
    AS141680 | 0        | 1/1    | SuperNet Infocomm
    AS151498 | 0        | 1/1    | Bhutan Power Corporation Ltd
    AS151955 | 0        | 1/1    | DRUK PNB BANK LIMITED
