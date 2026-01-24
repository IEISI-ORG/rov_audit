    [*] Loading V19 Data Sets...
        - Scanning JSON cache for ROA stats... OK (120467 records)
        - Loading Topology... OK

    ===============================================================================================
    1. THE GLASS HOUSES (Secure Providers, Unsigned Routes)
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Signed%  | Name
    -----------------------------------------------------------------------------------------------
    AS3356   | US | 66883    |   5.1%  | Lumen (Level 3)
    AS3216   | RU | 38493    |   0.2%  | Vimpelcom PJSC
    AS33891  | DE | 33875    |   0.0%  | Core-Backbone GmbH
    AS29632  | DE | 22718    |   0.0%  | Netassist International EOOD
    AS48185  | BE | 21978    |   0.0%  | team.blue NV
    AS56662  | PL | 18167    |   0.0%  | Marcin Gondek
    AS48858  | RU | 10534    |   0.0%  | JSC "ER-Telecom Holding"
    AS7575   | AU | 7710     |   4.6%  | Australian Academic and Research Network (AAR
    AS16735  | BR | 2681     |   0.0%  | Algar Telecom
    AS1764   | AT | 1707     |   5.8%  | Next Layer Telecommunications
    AS46887  | US | 1353     |   0.4%  | Crown Castle Fiber LLC
    AS53062  | BR | 1349     |   3.1%  | ALT | GRUPO BRASIL TECPAR
    AS201054 | PL | 985      |   0.0%  | Stowarzyszenie e-Poludnie
    AS4766   | KR | 983      |   3.5%  | Korea Telecom
    AS3549   | US | 709      |   0.4%  | Lumen (fka. Global Crossing)

    ===============================================================================================
    2. SCREAMING INTO THE VOID (Fully Signed, Vulnerable Upstreams)
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Signed%  | Name
    -----------------------------------------------------------------------------------------------
    AS45820  | IN | 306      |  98.7%  | Tata Teleservices ISP
    AS45117  | IN | 111      | 100.0%  | Ishan's Network
    AS17762  | IN | 100      |  99.6%  | Tata Teleservices Maharashtra Ltd
    AS135718 | IN | 44       | 100.0%  | DISHAWAVES INFONET PVT. LTD
    AS141731 | BD | 43       | 100.0%  | Max Hub Limited
    AS212330 | IQ | 42       | 100.0%  | Civilisation Information Technology, communic
    AS23688  | BD | 42       |  99.6%  | Link3 Technologies Ltd.
    AS24323  | BD | 35       |  98.0%  | aamra networks limited
    AS63969  | BD | 30       | 100.0%  | Race Online Limited
    AS4007   | NP | 30       | 100.0%  | Subisu Cablenet (Pvt) Ltd, Baluwatar, Kathman
    AS25184  | IR | 28       | 100.0%  | Afranet
    AS9230   | BD | 25       | 100.0%  | Bangladesh Online Ltd.
    AS38203  | BD | 24       | 100.0%  | ADN Telecom Ltd.
    AS11556  | PA | 24       | 100.0%  | Cable & Wireless Panama
    AS27717  | VE | 22       | 100.0%  | Corporacion Digitel C.A.

    ===============================================================================================
    3. WEIGHTED EVANGELISM TARGETS
       Metric = (Provider Cone Size) * (Count of Unsigned Customers)
       Highlighting massive providers with dirty customer bases.
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Unsigned | Impact Score   | Name
    -----------------------------------------------------------------------------------------------
        (Calculating weighted metrics for 632 providers...)
    AS6939   | US | 67716    | 32737    | 2,216,818,692  | Hurricane Electric LLC
    AS3356   | US | 66883    | 32854    | 2,197,374,082  | Lumen (Level 3)
    AS174    | US | 64425    | 30675    | 1,976,236,875  | Cogent Communications, LLC
    AS1299   | SE | 47707    | 30803    | 1,469,518,721  | Arelion (fka. Telia Carrier)
    AS24482  | SG | 65008    | 18604    | 1,209,408,832  | SG.GS
    AS6461   | US | 43299    | 25422    | 1,100,747,178  | Zayo Bandwidth
    AS9002   | GB | 44712    | 22442    | 1,003,426,704  | RETN Limited
    AS3257   | US | 32027    | 27417    | 878,084,259    | GTT Communications Inc.
    AS2914   | US | 29142    | 26166    | 762,529,572    | NTT America, Inc.
    AS3216   | RU | 38493    | 17586    | 676,937,898    | Vimpelcom PJSC
    AS33891  | DE | 33875    | 18503    | 626,789,125    | Core-Backbone GmbH
    AS20485  | RU | 27887    | 17587    | 490,448,669    | TransTeleCom JSC
    AS4826   | AU | 11802    | 21804    | 257,330,808    | Vocus Connect International Backbon
    AS6762   | IT | 10728    | 23720    | 254,468,160    | Telecom Italia Sparkle (Seabone)
    AS12389  | RU | 13218    | 17587    | 232,464,966    | Rostelecom PJSC
    AS6453   | US | 8549     | 25495    | 217,956,755    | TATA Communications (America) Inc
    AS3491   | US | 8457     | 22700    | 191,973,900    | PCCW Global, Inc.
    AS35280  | FR | 50699    | 3716     | 188,397,484    | F5 Networks SARL
    AS9498   | IN | 7660     | 19817    | 151,798,220    | Bharti Airtel Ltd.
    AS13335  | US | 18869    | 7700     | 145,291,300    | Cloudflare, Inc.
    AS8966   | AE | 6022     | 17587    | 105,908,914    | Etisalat (ETC)
    AS4637   | HK | 4655     | 22332    | 103,955,460    | Telstra International Limited
    AS7018   | US | 5242     | 19739    | 103,471,838    | AT&T Enterprises, LLC
    AS701    | US | 4131     | 24362    | 100,639,422    | Verizon Business
    AS7713   | ID | 5628     | 17587    | 98,979,636     | PT Telkom Indonesia Tbk

    [+] Saved strategy to roa_strategy_weighted.csv
