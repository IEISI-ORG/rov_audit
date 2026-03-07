    [*] Loading Global Audit for CN...

    ====================================================================================================
     NATIONAL ROUTING SECURITY: CN
    ====================================================================================================
    Total Networks:      3,026
    Total Cone Gravity:  5,790
    ------------------------------------------------------------
    SECURE NETWORKS:        77 ( 2.5%) -> Protects 12.6% of Traffic
    VULNERABLE NETWORKS:  1594 (52.7%) -> Exposes  15.2% of Traffic

    ====================================================================================================
     THE CN CORE (Top 20 Networks)
    ====================================================================================================
    ASN      | Verdict                        | Cone     | APNIC% | Name
    ----------------------------------------------------------------------------------------------------
    AS38255  | Unverified (Transit/Peer?)     | 4183     | -      | China Education and Research Network (CE
    AS4134   | CORE: UNPROTECTED              | 387      | 0%     | China Telecom Backbone
    AS24429  | PARTIAL (Mixed Feeds)          | 197      | -      | Alibaba Cloud
    AS4837   | CORE: UNPROTECTED              | 111      | 0%     | China Unicom Backbone
    AS139317 | SECURE (Full Coverage)         | 71       | -      | Ningbo Dahuamao Information Technology C
    AS4808   | Unverified (Transit/Peer?)     | 70       | 0%     | China Unicom Beijing Province Network
    AS4847   | Unverified (Transit/Peer?)     | 69       | 0%     | China Telecom Beijing Province Network
    AS9808   | CORE: UNPROTECTED              | 69       | 0%     | China Mobile Backbone
    AS56048  | Unverified (Transit/Peer?)     | 49       | 0%     | China Mobile Group Beijing Company
    AS4809   | CORE: PROTECTED                | 47       | 0%     | China Telecom Next Generation Carrier Ne
    AS4812   | VULNERABLE (No Coverage)       | 44       | 0%     | China Telecom Shanghai Province Network
    AS38272  | VULNERABLE (No Coverage)       | 40       | -      | China Education and Research Network (CE
    AS9425   | VULNERABLE (No Coverage)       | 40       | -      | Future Internet Technology Infrastructur
    AS17621  | Unverified (Transit/Peer?)     | 32       | 0%     | China Unicom Shanghai network
    AS24400  | Unverified (Transit/Peer?)     | 31       | 0%     | Shanghai Mobile Communications Co.,Ltd.
    AS146788 | VULNERABLE (No Coverage)       | 30       | -      | China Broadcasting Network Co., Ltd
    AS213605 | SECURE (Active Local ROV)      | 27       | -      | Liu HaoRan
    AS4538   | PARTIAL (Mixed Feeds)          | 26       | 0%     | China Education and Research Network Cen
    AS56040  | Unverified (Transit/Peer?)     | 19       | 0%     | China Mobile Group GuangDong Company
    AS140083 | VULNERABLE (No Coverage)       | 17       | -      | China Telecom Anhui Province Mobile Data

    ====================================================================================================
     TRANSIT SUPPLY CHAIN (Who provides to CN?)
    ====================================================================================================
    [*] Analyzing Upstream Supply Chain for 3026 networks...
        - Analyzed connectivity for 3020 networks.
    Rank | Upstream | Dependents | Global Status                  | Name
    ----------------------------------------------------------------------------------------------------
    #1   | AS38255  | 626        | Unverified (Transit/Peer?)     | China Education and Research Network (CE
    #2   | AS4134   | 142        | CORE: UNPROTECTED              | China Telecom Backbone
    #3   | AS20473  | 93         | SECURE (Full Coverage)         | The Constant Company, LLC
    #4   | AS139317 | 69         | SECURE (Full Coverage)         | Ningbo Dahuamao Information Technology C
    #5   | AS4847   | 65         | Unverified (Transit/Peer?)     | China Telecom Beijing Province Network
    #6   | AS4808   | 62         | Unverified (Transit/Peer?)     | China Unicom Beijing Province Network
    #7   | AS4837   | 55         | CORE: UNPROTECTED              | China Unicom Backbone
    #8   | AS38272  | 40         | VULNERABLE (No Coverage)       | China Education and Research Network (CE
    #9   | AS9425   | 40         | VULNERABLE (No Coverage)       | Future Internet Technology Infrastructur
    #10  | AS9808   | 36         | CORE: UNPROTECTED              | China Mobile Backbone
    #11  | AS4812   | 35         | VULNERABLE (No Coverage)       | China Telecom Shanghai Province Network
    #12  | AS53667  | 34         | SECURE (Full Coverage)         | FranTech Solutions
    #13  | AS6939   | 33         | CORE: PROTECTED                | Hurricane Electric LLC
    #14  | AS56048  | 33         | Unverified (Transit/Peer?)     | China Mobile Group Beijing Company
    #15  | AS44324  | 32         | SECURE (Active Local ROV)      | MoeDove LLC
    #16  | AS17621  | 29         | Unverified (Transit/Peer?)     | China Unicom Shanghai network
    #17  | AS34927  | 27         | SECURE (Full Coverage)         | iFog GmbH
    #18  | AS24400  | 24         | Unverified (Transit/Peer?)     | Shanghai Mobile Communications Co.,Ltd.
    #19  | AS7720   | 22         | SECURE (Full Coverage)         | Skywolf Technology LLC
    #20  | AS4809   | 21         | CORE: PROTECTED                | China Telecom Next Generation Carrier Ne

    ====================================================================================================
     TOP VULNERABLE CN NETWORKS
    ====================================================================================================
    ASN      | Cone     | Feeds  | Name
    --------------------------------------------------------------------------------
    AS4134   | 387      | 0/0    | China Telecom Backbone
    AS4837   | 111      | 0/0    | China Unicom Backbone
    AS9808   | 69       | 0/0    | China Mobile Backbone
    AS4812   | 44       | 1/1    | China Telecom Shanghai Province Network
    AS9425   | 40       | 1/1    | Future Internet Technology Infrastructure (FITI)
    AS38272  | 40       | 1/1    | China Education and Research Network (CERNET)
    AS146788 | 30       | 1/1    | China Broadcasting Network Co., Ltd
    AS140083 | 17       | 1/1    | China Telecom Anhui Province Mobile Data Network
    AS23650  | 17       | 1/1    | China Telecom Jiangsu Province IDC Network
    AS140345 | 16       | 1/1    | CHINATELECOM Yunnan province Shengji 5G network
    AS138169 | 15       | 1/1    | China Telecom Guangxi Province Mobile Data Network
    AS131285 | 14       | 1/1    | CHINATELECOM Hubei province Shengji 5G network
    AS9929   | 13       | 0/0    | CHINA UNICOM Industrial Internet Backbone
    AS134238 | 12       | 1/1    | CHINANET Jiangx province IDC network
    AS134768 | 10       | 1/1    | CHINANET SHAANXI province Cloud Base network
