    [*] Loading Data for ROA Strategy Report...
        - Loading Cones from final_as_rank.csv... OK (86317 ASNs)
        - Loading Graph from data/downstream_graph.json... OK
    [4] Loading ROA Stats from data/parsed... OK (122193 records)

    ===============================================================================================
    1. THE GLASS HOUSES (Secure Providers, Unsigned Routes)
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Signed%  | Name
    -----------------------------------------------------------------------------------------------
    AS46887  | US | 1379     |   0.3%  | Crown Castle Fiber LLC
    AS4766   | KR | 1261     |   0.1%  | Korea Telecom
    AS50263  | UA | 592      |   0.0%  | A-Systems Sp. z o.o.
    AS3549   | US | 525      |   1.2%  | Lumen (fka. Global Crossing)
    AS209    | US | 505      |   1.3%  | Lumen (ex. Qwest)
    AS3786   | KR | 458      |   0.2%  | LG DACOM Corporation
    AS10429  | BR | 425      |   0.0%  | Vivo (TELEFÔNICA BRASIL)
    AS28368  | BR | 329      |   0.0%  | Wirelink (Sobralnet)
    AS7738   | BR | 185      |   0.0%  | V.tal
    AS1031   | US | 177      |   0.0%  | PEER 1031 LLC
    AS3269   | IT | 174      |   0.1%  | TIM S.p.A. (fka. Telecom Italia S.p.A.)
    AS13649  | US | 171      |   1.7%  | Flexential Colorado Corp.
    AS23005  | US | 140      |   0.1%  | SWITCH, LTD
    AS8167   | BR | 115      |   0.0%  | V.tal
    AS2907   | JP | 114      |   7.0%  | Science Information Network

    ===============================================================================================
    2. SCREAMING INTO THE VOID (Fully Signed, Vulnerable Upstreams)
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Signed%  | Name
    -----------------------------------------------------------------------------------------------
    AS37721  | BF | 60716    | 100.0%  | Virtual Technologies & Solutions
    AS35280  | FR | 52753    | 100.0%  | F5 Networks SARL
    AS17639  | PH | 43128    |  97.8%  | Converge ICT Solutions Inc.
    AS34927  | CH | 34451    | 100.0%  | iFog GmbH
    AS48362  | AT | 32931    | 100.0%  | Stadtwerke Feldkirch
    AS213241 | BE | 25036    | 100.0%  | TECHIT.BE SRL
    AS3214   | DE | 22045    | 100.0%  | xTom GmbH
    AS56655  | NO | 14487    | 100.0%  | Gigahost AS
    AS212024 | FR | 14156    | 100.0%  | Marc Schmitt
    AS25091  | CH | 13742    | 100.0%  | IP-Max SA
    AS1836   | CH | 13649    |  99.9%  | green.ch AG
    AS31133  | RU | 11110    |  99.8%  | MegaFon PJSC
    AS12389  | RU | 11019    |  99.3%  | Rostelecom PJSC
    AS49673  | RU | 9069     | 100.0%  | Truenetwork LLC
    AS208972 | TR | 8200     | 100.0%  | GIBIRNet Iletisim

    ===============================================================================================
    3. WEIGHTED EVANGELISM TARGETS
       Metric = (Provider Cone Size) * (Count of Unsigned Customers)
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Unsigned | Impact Score   | Name
    -----------------------------------------------------------------------------------------------
    AS6939   | US | 72881    | 32248    | 2,350,266,488  | Hurricane Electric LLC
    AS3356   | US | 67370    | 32309    | 2,176,657,330  | Lumen (Level 3)
    AS174    | US | 68015    | 30106    | 2,047,659,590  | Cogent Communications, LLC
    AS1299   | SE | 50748    | 30248    | 1,535,025,504  | Arelion (fka. Telia Carrier)
    AS24482  | SG | 67857    | 18331    | 1,243,886,667  | SG.GS
    AS6461   | US | 47263    | 24969    | 1,180,109,847  | Zayo Bandwidth
    AS9002   | GB | 48665    | 22062    | 1,073,647,230  | RETN Limited
    AS3257   | US | 32631    | 26928    | 878,687,568    | GTT Communications Inc.
    AS2914   | US | 31360    | 25707    | 806,171,520    | NTT America, Inc.
    AS33891  | DE | 33935    | 18191    | 617,311,585    | Core-Backbone GmbH
    AS3216   | RU | 35341    | 17324    | 612,247,484    | Vimpelcom PJSC
    AS20485  | RU | 28807    | 17325    | 499,081,275    | TransTeleCom JSC
    AS6762   | IT | 11053    | 23289    | 257,413,317    | Telecom Italia Sparkle (Seabone)
    AS31500  | AG | 13306    | 17335    | 230,659,510    | Global Network Management Inc
    AS6453   | US | 8861     | 25087    | 222,295,907    | TATA Communications (America) Inc
    AS3491   | HK | 9309     | 22300    | 207,590,700    | PCCW Global (HK) Ltd.
    AS35280  | FR | 52753    | 3679     | 194,078,287    | F5 Networks SARL
    AS31133  | RU | 11110    | 17325    | 192,480,750    | MegaFon PJSC
    AS12389  | RU | 11019    | 17325    | 190,904,175    | Rostelecom PJSC
    AS7018   | US | 9477     | 19466    | 184,479,282    | AT&T Enterprises, LLC
    AS9498   | IN | 8814     | 19460    | 171,520,440    | Bharti Airtel Ltd.
    AS701    | US | 6995     | 23976    | 167,712,120    | Verizon Business
    AS13335  | US | 18875    | 7537     | 142,260,875    | Cloudflare, Inc.
    AS8966   | AE | 7066     | 17325    | 122,418,450    | Etisalat (E&)
    AS7713   | ID | 6670     | 17325    | 115,557,750    | PT Telkom Indonesia Tbk

    [+] Saved strategy to roa_strategy_weighted_v2.csv
