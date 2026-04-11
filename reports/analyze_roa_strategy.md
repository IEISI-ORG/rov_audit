    [*] Loading V19 Data Sets...
        - Scanning JSON cache for ROA stats... OK (121350 records)
        - Loading Topology... OK

    ===============================================================================================
    1. THE GLASS HOUSES (Secure Providers, Unsigned Routes)
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Signed%  | Name
    -----------------------------------------------------------------------------------------------
    AS3356   | US | 64668    |   5.0%  | Lumen (Level 3)
    AS174    | US | 64504    |   9.6%  | Cogent Communications, LLC
    AS3216   | RU | 35508    |   0.3%  | Vimpelcom PJSC
    AS33891  | DE | 33865    |   0.0%  | Core-Backbone GmbH
    AS29632  | DE | 21725    |   0.0%  | Netassist International EOOD
    AS56662  | PL | 12408    |   0.0%  | Marcin Gondek
    AS16735  | BR | 2836     |   0.0%  | Algar Telecom
    AS1764   | AT | 1927     |   5.8%  | Next Layer Telecommunications
    AS14840  | BR | 1653     |   0.0%  | BR.DIGITAL 
    AS46887  | US | 1370     |   0.4%  | Crown Castle Fiber LLC
    AS4766   | KR | 1022     |   4.0%  | Korea Telecom
    AS201054 | PL | 792      |   0.0%  | Stowarzyszenie e-Poludnie
    AS9318   | KR | 543      |   8.9%  | SK Broadband Co Ltd
    AS3549   | US | 536      |   0.6%  | Lumen (fka. Global Crossing)
    AS10429  | BR | 515      |   0.0%  | Vivo (TELEFÔNICA BRASIL)

    ===============================================================================================
    2. SCREAMING INTO THE VOID (Fully Signed, Vulnerable Upstreams)
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Signed%  | Name
    -----------------------------------------------------------------------------------------------
    AS45820  | IN | 347      |  98.8%  | Tata Teleservices ISP
    AS17762  | IN | 127      |  99.4%  | Tata Teleservices Maharashtra Ltd
    AS45117  | IN | 118      | 100.0%  | Ishan Netsol Pvt Ltd
    AS29465  | NG | 69       |  98.4%  | MTN NIGERIA Communication limited
    AS23688  | BD | 46       |  99.6%  | Link3 Technologies Ltd.
    AS135718 | IN | 44       | 100.0%  | DISHAWAVES INFONET PVT. LTD
    AS141731 | BD | 42       | 100.0%  | Max Hub Limited
    AS151690 | IN | 37       | 100.0%  | FAB FIVE NETWORK PRIVATE LIMITED
    AS24323  | BD | 34       |  99.0%  | aamra networks limited
    AS149765 | BD | 34       | 100.0%  | Coronet Corporation Limited
    AS15836  | MD | 33       | 100.0%  | Arax-Impex s.r.l.
    AS25019  | SA | 32       |  97.8%  | Saudi Telecom Company JSC
    AS16010  | GE | 31       | 100.0%  | Magticom Ltd.
    AS4007   | NP | 31       | 100.0%  | Subisu Cablenet (Pvt) Ltd, Baluwatar, Kathman
    AS25184  | IR | 26       | 100.0%  | Afranet

    ===============================================================================================
    3. WEIGHTED EVANGELISM TARGETS
       Metric = (Provider Cone Size) * (Count of Unsigned Customers)
       Highlighting massive providers with dirty customer bases.
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Unsigned | Impact Score   | Name
    -----------------------------------------------------------------------------------------------
        (Calculating weighted metrics for 638 providers...)
    AS6939   | US | 68256    | 32224    | 2,199,481,344  | Hurricane Electric LLC
    AS3356   | US | 64668    | 32281    | 2,087,547,708  | Lumen (Level 3)
    AS174    | US | 64504    | 30073    | 1,939,828,792  | Cogent Communications, LLC
    AS1299   | SE | 48082    | 30224    | 1,453,230,368  | Arelion (fka. Telia Carrier)
    AS24482  | SG | 65410    | 18343    | 1,199,815,630  | SG.GS
    AS9002   | GB | 46955    | 22073    | 1,036,437,715  | RETN Limited
    AS6461   | US | 40790    | 24973    | 1,018,648,670  | Zayo Bandwidth
    AS3257   | US | 30274    | 26916    | 814,854,984    | GTT Communications Inc.
    AS2914   | US | 28854    | 25706    | 741,720,924    | NTT America, Inc.
    AS33891  | DE | 33865    | 18211    | 616,715,515    | Core-Backbone GmbH
    AS3216   | RU | 35508    | 17343    | 615,815,244    | Vimpelcom PJSC
    AS20485  | RU | 30619    | 17344    | 531,055,936    | TransTeleCom JSC
    AS6762   | IT | 10469    | 23303    | 243,959,107    | Telecom Italia Sparkle (Seabone)
    AS6453   | US | 8822     | 25078    | 221,238,116    | TATA Communications (America) Inc
    AS31500  | AG | 12515    | 17354    | 217,185,310    | Global Network Management Inc
    AS3491   | HK | 8891     | 22321    | 198,456,011    | PCCW Global (HK) Ltd.
    AS35280  | FR | 50969    | 3686     | 187,871,734    | F5 Networks SARL
    AS12389  | RU | 10447    | 17344    | 181,192,768    | Rostelecom PJSC
    AS31133  | RU | 10436    | 17344    | 181,001,984    | MegaFon PJSC
    AS9498   | IN | 7821     | 19486    | 152,400,006    | Bharti Airtel Ltd.
    AS13335  | US | 16573    | 7566     | 125,391,318    | Cloudflare, Inc.
    AS7713   | ID | 6908     | 17344    | 119,812,352    | PT Telkom Indonesia Tbk
    AS8966   | AE | 6759     | 17344    | 117,228,096    | Etisalat (ETC)
    AS4637   | HK | 4944     | 21968    | 108,609,792    | Telstra International Limited
    AS7018   | US | 5316     | 19474    | 103,523,784    | AT&T Enterprises, LLC

    [+] Saved strategy to roa_strategy_weighted.csv
