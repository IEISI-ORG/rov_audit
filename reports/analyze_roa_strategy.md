    [*] Loading V19 Data Sets...
        - Scanning JSON cache for ROA stats... OK (120980 records)
        - Loading Topology... OK

    ===============================================================================================
    1. THE GLASS HOUSES (Secure Providers, Unsigned Routes)
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Signed%  | Name
    -----------------------------------------------------------------------------------------------
    AS3356   | US | 65326    |   5.0%  | Lumen (Level 3)
    AS174    | US | 64687    |   9.6%  | Cogent Communications, LLC
    AS3216   | RU | 38066    |   0.2%  | Vimpelcom PJSC
    AS33891  | DE | 33466    |   0.0%  | Core-Backbone GmbH
    AS29632  | DE | 22831    |   0.0%  | Netassist International EOOD
    AS48185  | BE | 21187    |   0.0%  | team.blue NV
    AS56662  | PL | 12088    |   0.0%  | Marcin Gondek
    AS16735  | BR | 2459     |   0.0%  | Algar Telecom
    AS1764   | AT | 1677     |   5.7%  | Next Layer Telecommunications
    AS14840  | BR | 1554     |   0.0%  | BR.DIGITAL 
    AS46887  | US | 1359     |   0.4%  | Crown Castle Fiber LLC
    AS53062  | BR | 1195     |   4.1%  | ALT | GRUPO BRASIL TECPAR
    AS4766   | KR | 1045     |   3.6%  | Korea Telecom
    AS201054 | PL | 906      |   0.0%  | Stowarzyszenie e-Poludnie
    AS3549   | US | 546      |   0.4%  | Lumen (fka. Global Crossing)

    ===============================================================================================
    2. SCREAMING INTO THE VOID (Fully Signed, Vulnerable Upstreams)
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Signed%  | Name
    -----------------------------------------------------------------------------------------------
    AS45820  | IN | 319      |  98.7%  | Tata Teleservices ISP
    AS17762  | IN | 129      |  99.4%  | Tata Teleservices Maharashtra Ltd
    AS45117  | IN | 112      | 100.0%  | Ishan Netsol Pvt Ltd
    AS135718 | IN | 44       | 100.0%  | DISHAWAVES INFONET PVT. LTD
    AS23688  | BD | 44       |  99.6%  | Link3 Technologies Ltd.
    AS141731 | BD | 41       | 100.0%  | Max Hub Limited
    AS212330 | IQ | 40       | 100.0%  | Civilisation Information Technology, communic
    AS149765 | BD | 35       | 100.0%  | Coronet Corporation Limited
    AS15836  | MD | 34       | 100.0%  | Arax-Impex s.r.l.
    AS24323  | BD | 34       |  99.0%  | aamra networks limited
    AS4007   | NP | 32       | 100.0%  | Subisu Cablenet (Pvt) Ltd, Baluwatar, Kathman
    AS38203  | BD | 30       | 100.0%  | ADN Telecom Ltd.
    AS25184  | IR | 29       | 100.0%  | Afranet
    AS9230   | BD | 27       | 100.0%  | Bangladesh Online Ltd.
    AS24631  | IR | 26       | 100.0%  | Tose'h Fanavari Ertebabat Pasargad Arian Co. 

    ===============================================================================================
    3. WEIGHTED EVANGELISM TARGETS
       Metric = (Provider Cone Size) * (Count of Unsigned Customers)
       Highlighting massive providers with dirty customer bases.
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Unsigned | Impact Score   | Name
    -----------------------------------------------------------------------------------------------
        (Calculating weighted metrics for 636 providers...)
    AS6939   | US | 67899    | 32543    | 2,209,637,157  | Hurricane Electric LLC
    AS3356   | US | 65326    | 32630    | 2,131,587,380  | Lumen (Level 3)
    AS174    | US | 64687    | 30441    | 1,969,136,967  | Cogent Communications, LLC
    AS1299   | SE | 47517    | 30578    | 1,452,974,826  | Arelion (fka. Telia Carrier)
    AS24482  | SG | 65177    | 18500    | 1,205,774,500  | SG.GS
    AS6461   | US | 41149    | 25251    | 1,039,053,399  | Zayo Bandwidth
    AS9002   | GB | 45924    | 22312    | 1,024,656,288  | RETN Limited
    AS3257   | US | 29302    | 27222    | 797,659,044    | GTT Communications Inc.
    AS2914   | US | 28358    | 25992    | 737,081,136    | NTT America, Inc.
    AS3216   | RU | 38066    | 17492    | 665,850,472    | Vimpelcom PJSC
    AS33891  | DE | 33466    | 18400    | 615,774,400    | Core-Backbone GmbH
    AS20485  | RU | 27399    | 17493    | 479,290,707    | TransTeleCom JSC
    AS4826   | AU | 12231    | 21674    | 265,094,694    | Vocus Connect International Backbon
    AS6762   | IT | 10217    | 23560    | 240,712,520    | Telecom Italia Sparkle (Seabone)
    AS6453   | US | 8495     | 25337    | 215,237,815    | TATA Communications (America) Inc
    AS12389  | RU | 11307    | 17493    | 197,793,351    | Rostelecom PJSC
    AS35280  | FR | 52107    | 3695     | 192,535,365    | F5 Networks SARL
    AS3491   | US | 8359     | 22559    | 188,570,681    | PCCW Global, Inc.
    AS9498   | IN | 7394     | 19698    | 145,647,012    | Bharti Airtel Ltd.
    AS13335  | US | 16400    | 7621     | 124,984,400    | Cloudflare, Inc.
    AS7713   | ID | 6913     | 17493    | 120,929,109    | PT Telkom Indonesia Tbk
    AS8966   | AE | 6501     | 17493    | 113,721,993    | Etisalat (ETC)
    AS4637   | HK | 4781     | 22200    | 106,138,200    | Telstra International Limited
    AS7018   | US | 5219     | 19636    | 102,480,284    | AT&T Enterprises, LLC
    AS701    | US | 4230     | 24226    | 102,475,980    | Verizon Business

    [+] Saved strategy to roa_strategy_weighted.csv
