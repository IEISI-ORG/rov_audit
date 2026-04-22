    [*] Loading Data for ROA Strategy Report...
        - Loading Cones from final_as_rank.csv... OK (86333 ASNs)
        - Loading Graph from data/downstream_graph.json... OK
    [4] Loading ROA Stats from data/parsed... OK (122180 records)

    ===============================================================================================
    1. THE GLASS HOUSES (Secure Providers, Unsigned Routes)
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Signed%  | Name
    -----------------------------------------------------------------------------------------------
    AS46887  | US | 1375     |   0.3%  | Crown Castle Fiber LLC
    AS4766   | KR | 1242     |   0.1%  | Korea Telecom
    AS50263  | UA | 625      |   0.0%  | A-Systems Sp. z o.o.
    AS3549   | US | 524      |   1.2%  | Lumen (fka. Global Crossing)
    AS209    | US | 504      |   1.3%  | Lumen (ex. Qwest)
    AS3786   | KR | 458      |   0.2%  | LG DACOM Corporation
    AS4134   | CN | 419      |   2.4%  | China Telecom Backbone
    AS10429  | BR | 406      |   0.0%  | Vivo (TELEFÔNICA BRASIL)
    AS28368  | BR | 332      |   0.0%  | Wirelink (Sobralnet)
    AS7738   | BR | 188      |   0.0%  | V.tal
    AS1031   | US | 178      |   0.0%  | PEER 1031 LLC
    AS3269   | IT | 173      |   0.1%  | TIM S.p.A. (fka. Telecom Italia S.p.A.)
    AS13649  | US | 172      |   1.7%  | Flexential Colorado Corp.
    AS23005  | US | 140      |   0.1%  | SWITCH, LTD
    AS4837   | CN | 116      |   1.2%  | China Unicom Backbone

    ===============================================================================================
    2. SCREAMING INTO THE VOID (Fully Signed, Vulnerable Upstreams)
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Signed%  | Name
    -----------------------------------------------------------------------------------------------
    AS37721  | BF | 60817    | 100.0%  | Virtual Technologies & Solutions
    AS35280  | FR | 53251    | 100.0%  | F5 Networks SARL
    AS17639  | PH | 43164    |  97.8%  | Converge ICT Solutions Inc.
    AS34927  | CH | 34524    | 100.0%  | iFog GmbH
    AS48362  | AT | 33110    | 100.0%  | Stadtwerke Feldkirch
    AS213241 | BE | 25054    | 100.0%  | TECHIT.BE SRL
    AS3214   | DE | 21983    | 100.0%  | xTom GmbH
    AS56655  | NO | 14403    | 100.0%  | Gigahost AS
    AS212024 | FR | 14225    | 100.0%  | Marc Schmitt
    AS25091  | CH | 13758    | 100.0%  | IP-Max SA
    AS1836   | CH | 13396    |  99.9%  | green.ch AG
    AS31133  | RU | 11436    |  99.8%  | MegaFon PJSC
    AS12389  | RU | 11001    |  99.3%  | Rostelecom PJSC
    AS49673  | RU | 8979     | 100.0%  | Truenetwork LLC
    AS208972 | TR | 8197     | 100.0%  | GIBIRNet Iletisim

    ===============================================================================================
    3. WEIGHTED EVANGELISM TARGETS
       Metric = (Provider Cone Size) * (Count of Unsigned Customers)
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Unsigned | Impact Score   | Name
    -----------------------------------------------------------------------------------------------
    AS6939   | US | 73872    | 32248    | 2,382,224,256  | Hurricane Electric LLC
    AS3356   | US | 67438    | 32309    | 2,178,854,342  | Lumen (Level 3)
    AS174    | US | 68044    | 30106    | 2,048,532,664  | Cogent Communications, LLC
    AS1299   | SE | 50745    | 30248    | 1,534,934,760  | Arelion (fka. Telia Carrier)
    AS24482  | SG | 67784    | 18331    | 1,242,548,504  | SG.GS
    AS6461   | US | 47351    | 24969    | 1,182,307,119  | Zayo Bandwidth
    AS9002   | GB | 48418    | 22062    | 1,068,197,916  | RETN Limited
    AS3257   | US | 32706    | 26928    | 880,707,168    | GTT Communications Inc.
    AS2914   | US | 31341    | 25707    | 805,683,087    | NTT America, Inc.
    AS3216   | RU | 35392    | 17324    | 613,131,008    | Vimpelcom PJSC
    AS33891  | DE | 33704    | 18191    | 613,109,464    | Core-Backbone GmbH
    AS20485  | RU | 28956    | 17325    | 501,662,700    | TransTeleCom JSC
    AS6762   | IT | 10841    | 23289    | 252,476,049    | Telecom Italia Sparkle (Seabone)
    AS31500  | AG | 13373    | 17335    | 231,820,955    | Global Network Management Inc
    AS6453   | US | 8959     | 25087    | 224,754,433    | TATA Communications (America) Inc
    AS3491   | HK | 9349     | 22300    | 208,482,700    | PCCW Global (HK) Ltd.
    AS31133  | RU | 11436    | 17325    | 198,128,700    | MegaFon PJSC
    AS35280  | FR | 53251    | 3679     | 195,910,429    | F5 Networks SARL
    AS12389  | RU | 11001    | 17325    | 190,592,325    | Rostelecom PJSC
    AS7018   | US | 9438     | 19466    | 183,720,108    | AT&T Enterprises, LLC
    AS701    | US | 6880     | 23976    | 164,954,880    | Verizon Business
    AS9498   | IN | 8034     | 19460    | 156,341,640    | Bharti Airtel Ltd.
    AS13335  | US | 18764    | 7537     | 141,424,268    | Cloudflare, Inc.
    AS7713   | ID | 6914     | 17325    | 119,785,050    | PT Telkom Indonesia Tbk
    AS8966   | AE | 6882     | 17325    | 119,230,650    | Etisalat (E&)

    [+] Saved strategy to roa_strategy_weighted_v2.csv
