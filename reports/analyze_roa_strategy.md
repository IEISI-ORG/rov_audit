    [*] Loading V19 Data Sets...
        - Scanning JSON cache for ROA stats... OK (120195 records)
        - Loading Topology... OK

    ===============================================================================================
    1. THE GLASS HOUSES (Secure Providers, Unsigned Routes)
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Signed%  | Name
    -----------------------------------------------------------------------------------------------
    AS3356   | US | 66688    |   5.1%  | Lumen (Level 3)
    AS3216   | RU | 37970    |   0.2%  | Vimpelcom PJSC
    AS33891  | DE | 33373    |   0.0%  | Core-Backbone GmbH
    AS29632  | DE | 23796    |   0.0%  | Netassist International EOOD
    AS48185  | BE | 22499    |   0.0%  | team.blue NV
    AS56662  | PL | 19141    |   0.0%  | Marcin Gondek
    AS48858  | RU | 11016    |   0.0%  | JSC "ER-Telecom Holding"
    AS7575   | AU | 7645     |   4.6%  | Australian Academic and Research Network (AAR
    AS16735  | BR | 2655     |   0.0%  | Algar Telecom
    AS46887  | US | 1401     |   0.4%  | Crown Castle Fiber LLC
    AS53062  | BR | 1383     |   3.1%  | ALT | GRUPO BRASIL TECPAR
    AS4766   | KR | 1116     |   3.5%  | Korea Telecom
    AS201054 | PL | 951      |   0.0%  | Stowarzyszenie e-Poludnie
    AS209    | US | 698      |   1.4%  | Lumen (ex. Qwest)
    AS3549   | US | 691      |   0.4%  | Lumen (fka. Global Crossing)

    ===============================================================================================
    2. SCREAMING INTO THE VOID (Fully Signed, Vulnerable Upstreams)
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Signed%  | Name
    -----------------------------------------------------------------------------------------------
    AS45820  | IN | 306      |  98.7%  | Tata Teleservices ISP
    AS17762  | IN | 116      |  99.6%  | Tata Teleservices Maharashtra Ltd
    AS45117  | IN | 115      | 100.0%  | Ishan's Network
    AS141731 | BD | 44       | 100.0%  | Max Hub Limited
    AS135718 | IN | 44       | 100.0%  | DISHAWAVES INFONET PVT. LTD
    AS23688  | BD | 42       |  99.6%  | Link3 Technologies Ltd.
    AS212330 | IQ | 40       | 100.0%  | Civilisation Information Technology, communic
    AS24323  | BD | 36       |  98.0%  | aamra networks limited
    AS25184  | IR | 30       | 100.0%  | Afranet
    AS4007   | NP | 28       | 100.0%  | Subisu Cablenet (Pvt) Ltd, Baluwatar, Kathman
    AS23956  | BD | 26       |  99.5%  | AmberIT Limited
    AS9230   | BD | 26       | 100.0%  | Bangladesh Online Ltd.
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
        (Calculating weighted metrics for 629 providers...)
    AS6939   | US | 67596    | 32737    | 2,212,890,252  | Hurricane Electric LLC
    AS3356   | US | 66688    | 32854    | 2,190,967,552  | Lumen (Level 3)
    AS174    | US | 64462    | 30675    | 1,977,371,850  | Cogent Communications, LLC
    AS1299   | SE | 46648    | 30803    | 1,436,898,344  | Arelion (fka. Telia Carrier)
    AS24482  | SG | 64806    | 18604    | 1,205,650,824  | SG.GS
    AS6461   | US | 41650    | 25422    | 1,058,826,300  | Zayo Bandwidth
    AS9002   | GB | 44394    | 22442    | 996,290,148    | RETN Limited
    AS3257   | US | 29265    | 27417    | 802,358,505    | GTT Communications Inc.
    AS2914   | US | 29632    | 26166    | 775,350,912    | NTT America, Inc.
    AS3216   | RU | 37970    | 17586    | 667,740,420    | Vimpelcom PJSC
    AS33891  | DE | 33373    | 18503    | 617,500,619    | Core-Backbone GmbH
    AS20485  | RU | 28132    | 17587    | 494,757,484    | TransTeleCom JSC
    AS6762   | IT | 10904    | 23720    | 258,642,880    | Telecom Italia Sparkle (Seabone)
    AS4826   | AU | 11401    | 21804    | 248,587,404    | Vocus Connect International Backbon
    AS12389  | RU | 14014    | 17587    | 246,464,218    | Rostelecom PJSC
    AS6453   | US | 8721     | 25495    | 222,341,895    | TATA Communications (America) Inc
    AS3491   | US | 8741     | 22700    | 198,420,700    | PCCW Global, Inc.
    AS35280  | FR | 50697    | 3716     | 188,390,052    | F5 Networks SARL
    AS9498   | IN | 7921     | 19817    | 156,970,457    | Bharti Airtel Ltd.
    AS13335  | US | 19261    | 7700     | 148,309,700    | Cloudflare, Inc.
    AS4637   | HK | 4880     | 22332    | 108,980,160    | Telstra Global
    AS7713   | ID | 5957     | 17587    | 104,765,759    | PT Telkom Indonesia Tbk
    AS7018   | US | 5291     | 19739    | 104,439,049    | AT&T Enterprises, LLC
    AS8966   | AE | 5932     | 17587    | 104,326,084    | Etisalat (ETC)
    AS701    | US | 4042     | 24362    | 98,471,204     | Verizon Business

    [+] Saved strategy to roa_strategy_weighted.csv
