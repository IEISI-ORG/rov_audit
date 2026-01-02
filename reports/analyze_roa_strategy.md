    [*] Loading V19 Data Sets...
        - Scanning JSON cache for ROA stats... OK (120071 records)
        - Loading Topology... OK

    ===============================================================================================
    1. THE GLASS HOUSES (Secure Providers, Unsigned Routes)
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Signed%  | Name
    -----------------------------------------------------------------------------------------------
    AS3356   | US | 66657    |   5.1%  | Lumen (Level 3)
    AS3216   | RU | 38672    |   0.2%  | Vimpelcom PJSC
    AS33891  | XX | 33269    |   0.0%  | Core-Backbone GmbH
    AS29632  | XX | 23823    |   0.0%  | Netassist International EOOD
    AS48185  | BE | 22501    |   0.0%  | team.blue NV
    AS56662  | PL | 18451    |   0.0%  | Marcin Gondek
    AS48858  | RU | 11013    |   0.0%  | JSC "ER-Telecom Holding"
    AS7575   | AU | 7671     |   4.6%  | Australian Academic and Research Network (AAR
    AS16735  | BR | 2660     |   0.0%  | Algar Telecom
    AS46887  | US | 1400     |   0.4%  | Crown Castle Fiber LLC
    AS53062  | BR | 1382     |   3.1%  | ALT | GRUPO BRASIL TECPAR
    AS4766   | KR | 1122     |   3.5%  | Korea Telecom
    AS201054 | PL | 953      |   0.0%  | Stowarzyszenie e-Poludnie
    AS209    | US | 698      |   1.4%  | Lumen (ex. Qwest)
    AS3549   | US | 688      |   0.4%  | Lumen (fka. Global Crossing)

    ===============================================================================================
    2. SCREAMING INTO THE VOID (Fully Signed, Vulnerable Upstreams)
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Signed%  | Name
    -----------------------------------------------------------------------------------------------
    AS45820  | IN | 306      |  98.7%  | Tata Teleservices ISP
    AS17762  | IN | 116      |  99.6%  | Tata Teleservices Maharashtra Ltd
    AS45117  | IN | 115      | 100.0%  | Ishan's Network
    AS135718 | IN | 44       | 100.0%  | DISHAWAVES INFONET PVT. LTD
    AS141731 | BD | 43       | 100.0%  | Max Hub Limited
    AS23688  | BD | 42       |  99.6%  | Link3 Technologies Ltd.
    AS212330 | IQ | 40       | 100.0%  | Civilisation Information Technology, communic
    AS24323  | BD | 36       |  98.0%  | aamra networks limited
    AS25184  | IR | 30       | 100.0%  | Afranet
    AS4007   | NP | 28       | 100.0%  | Subisu Cablenet (Pvt) Ltd, Baluwatar, Kathman
    AS9230   | BD | 26       | 100.0%  | Bangladesh Online Ltd.
    AS23956  | BD | 26       |  99.5%  | AmberIT Limited
    AS11556  | PA | 24       | 100.0%  | Cable & Wireless Panama
    AS141898 | ID | 23       | 100.0%  | PT Milenial Inti Telekomunikasi
    AS9129   | ZA | 23       | 100.0%  | MTN Business Kenya

    ===============================================================================================
    3. WEIGHTED EVANGELISM TARGETS
       Metric = (Provider Cone Size) * (Count of Unsigned Customers)
       Highlighting massive providers with dirty customer bases.
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Unsigned | Impact Score   | Name
    -----------------------------------------------------------------------------------------------
        (Calculating weighted metrics for 631 providers...)
    AS6939   | US | 67546    | 32737    | 2,211,253,402  | Hurricane Electric LLC
    AS3356   | US | 66657    | 32854    | 2,189,949,078  | Lumen (Level 3)
    AS174    | US | 64451    | 30675    | 1,977,034,425  | Cogent Communications, LLC
    AS1299   | SE | 46526    | 30803    | 1,433,140,378  | Arelion (fka. Telia Carrier)
    AS24482  | SG | 64798    | 18604    | 1,205,501,992  | SG.GS
    AS6461   | US | 41855    | 25422    | 1,064,037,810  | Zayo Bandwidth
    AS9002   | GB | 44765    | 22442    | 1,004,616,130  | RETN Limited
    AS3257   | US | 29228    | 27417    | 801,344,076    | GTT Communications Inc.
    AS2914   | US | 29625    | 26166    | 775,167,750    | NTT America, Inc.
    AS3216   | RU | 38672    | 17586    | 680,085,792    | Vimpelcom PJSC
    AS33891  | XX | 33269    | 18503    | 615,576,307    | Core-Backbone GmbH
    AS20485  | RU | 28045    | 17587    | 493,227,415    | TransTeleCom JSC
    AS6762   | IT | 10898    | 23720    | 258,500,560    | Telecom Italia Sparkle (Seabone)
    AS4826   | AU | 11634    | 21804    | 253,667,736    | Vocus Connect International Backbon
    AS12389  | RU | 13915    | 17587    | 244,723,105    | Rostelecom PJSC
    AS6453   | US | 8724     | 25495    | 222,418,380    | TATA Communications (America) Inc
    AS3491   | US | 8563     | 22700    | 194,380,100    | PCCW Global, Inc.
    AS35280  | FR | 50591    | 3716     | 187,996,156    | F5 Networks SARL
    AS9498   | IN | 7841     | 19817    | 155,385,097    | Bharti Airtel Ltd.
    AS13335  | US | 19220    | 7700     | 147,994,000    | Cloudflare, Inc.
    AS4637   | HK | 4882     | 22332    | 109,024,824    | Telstra Global
    AS7713   | ID | 6161     | 17587    | 108,353,507    | PT Telkom Indonesia Tbk
    AS7018   | US | 5286     | 19739    | 104,340,354    | AT&T Enterprises, LLC
    AS8966   | AE | 5811     | 17587    | 102,198,057    | Etisalat (ETC)
    AS701    | US | 4039     | 24362    | 98,398,118     | Verizon Business

    [+] Saved strategy to roa_strategy_weighted.csv
