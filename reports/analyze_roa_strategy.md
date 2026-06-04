    [*] Loading Data for ROA Strategy Report...
        - Loading Cones from final_as_rank.csv... OK (86582 ASNs)
        - Loading Graph from data/downstream_graph.json... OK
        - Loading ASN data from packed file... OK (122,782 records)

    ===============================================================================================
    1. THE GLASS HOUSES (Secure Providers, Unsigned Routes)
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Signed%  | Name
    -----------------------------------------------------------------------------------------------
    AS3216   | RU | 29953    |   1.3%  | Vimpelcom PJSC
    AS48185  | BE | 22960    |   0.0%  | team.blue NV
    AS16735  | BR | 2323     |   0.0%  | Algar Telecom
    AS14840  | BR | 1638     |   0.0%  | BR.DIGITAL 
    AS46887  | US | 1379     |   0.3%  | Crown Castle Fiber LLC
    AS1031   | US | 941      |   0.0%  | PEER 1031 LLC
    AS201054 | PL | 857      |   0.0%  | Stowarzyszenie e-Poludnie
    AS209    | US | 608      |   1.3%  | Lumen (ex. Qwest)
    AS61568  | BR | 551      |   0.0%  | ALOO TELECOM - FSF TECNOLOGIA SA
    AS3549   | US | 475      |   1.2%  | Lumen (fka. Global Crossing)
    AS3786   | KR | 460      |   0.2%  | LG DACOM Corporation
    AS10429  | BR | 434      |   0.0%  | Vivo (TELEFÔNICA BRASIL)
    AS2764   | AU | 411      |   0.7%  | AAPT Limited
    AS28368  | BR | 311      |   0.0%  | Wirelink (Sobralnet)
    AS62081  | PL | 283      |   0.0%  | Stowarzyszenie e-Poludnie

    ===============================================================================================
    2. SCREAMING INTO THE VOID (Fully Signed, Vulnerable Upstreams)
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Signed%  | Name
    -----------------------------------------------------------------------------------------------
    AS37721  | BF | 58375    | 100.0%  | Virtual Technologies & Solutions
    AS17639  | PH | 40992    |  97.9%  | Converge ICT Solutions Inc.
    AS9304   | HK | 8894     | 100.0%  | HGC Global Communications Limited
    AS38001  | SG | 7866     | 100.0%  | NewMedia Express Pte. Ltd.
    AS52468  | PA | 5113     | 100.0%  | UFINET PANAMA S.A.
    AS12741  | PL | 796      |  98.9%  | Netia SA
    AS3223   | GB | 792      | 100.0%  | Voxility LLP
    AS14789  | US | 726      | 100.0%  | Cloudflare, Inc.
    AS18229  | IN | 445      | 100.0%  | CtrlS
    AS45820  | IN | 330      |  98.4%  | Tata Teleservices ISP
    AS53356  | CA | 270      | 100.0%  | Free Range Cloud Hosting Inc.
    AS42337  | IR | 230      | 100.0%  | Respina Networks & Beyond PJSC
    AS131111 | ID | 223      | 100.0%  | PT Mora Telematika Indonesia Tbk
    AS12302  | RO | 218      |  99.6%  | Vodafone Romania S.A.
    AS135607 | PH | 194      | 100.0%  | Infinivan Incorporated

    ===============================================================================================
    3. WEIGHTED EVANGELISM TARGETS
       Metric = (Provider Cone Size) * (Count of Unsigned Customers)
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Unsigned | Impact Score   | Name
    -----------------------------------------------------------------------------------------------
    AS3356   | US | 73670    | 29909    | 2,203,396,030  | Lumen (Level 3)
    AS6939   | US | 75321    | 28516    | 2,147,853,636  | Hurricane Electric LLC
    AS174    | US | 73113    | 26798    | 1,959,282,174  | Cogent Communications, LLC
    AS1299   | SE | 70501    | 27016    | 1,904,655,016  | Arelion (fka. Telia Carrier)
    AS3257   | US | 69044    | 25448    | 1,757,031,712  | GTT Communications Inc.
    AS6461   | US | 70976    | 23809    | 1,689,867,584  | Zayo Bandwidth
    AS2914   | US | 68200    | 23602    | 1,609,656,400  | NTT America, Inc.
    AS4637   | HK | 64963    | 23669    | 1,537,609,247  | Telstra International Limited
    AS6762   | IT | 65675    | 23326    | 1,531,935,050  | Telecom Italia Sparkle (Seabone)
    AS6453   | US | 65360    | 23152    | 1,513,214,720  | TATA Communications (America) Inc
    AS3491   | HK | 66369    | 21423    | 1,421,823,087  | PCCW Global (HK) Ltd.
    AS5511   | FR | 60990    | 22358    | 1,363,614,420  | Orange S.A.
    AS3320   | DE | 66103    | 19681    | 1,300,973,143  | Deutsche Telekom AG
    AS12956  | ES | 61606    | 21047    | 1,296,621,482  | Telxius (Telefonica Global)
    AS4134   | CN | 64918    | 19616    | 1,273,431,488  | China Telecom Backbone
    AS1273   | EU | 62094    | 20304    | 1,260,756,576  | Vodafone Group PLC
    AS6830   | NL | 61419    | 20290    | 1,246,191,510  | Liberty Global Europe Holding B.V.
    AS701    | US | 68382    | 15078    | 1,031,063,796  | Verizon Business
    AS9002   | GB | 46963    | 18659    | 876,282,617    | RETN Limited
    AS4809   | CN | 64341    | 7660     | 492,852,060    | China Telecom Next Generation Carri
    AS4837   | CN | 43958    | 11165    | 490,791,070    | China Unicom Backbone
    AS7922   | US | 61322    | 7174     | 439,924,028    | Comcast Cable Communications, LLC
    AS7018   | US | 68964    | 4319     | 297,855,516    | AT&T Enterprises, LLC
    AS33891  | DE | 33358    | 6191     | 206,519,378    | Core-Backbone GmbH
    AS34927  | CH | 32325    | 6179     | 199,736,175    | iFog GmbH

    [+] Saved strategy to roa_strategy_weighted_v2.csv
