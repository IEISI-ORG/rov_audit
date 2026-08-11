    [*] Loading Data for ROA Strategy Report...
        - Loading Cones from final_as_rank.csv... OK (87018 ASNs)
        - Loading Graph from data/downstream_graph.json... OK
        - Loading ASN data from packed file... OK (123,966 records)

    ===============================================================================================
    1. THE GLASS HOUSES (Secure Providers, Unsigned Routes)
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Signed%  | Name
    -----------------------------------------------------------------------------------------------
    AS48185  | BE | 21961    |   0.0%  | team.blue NV
    AS16735  | BR | 2020     |   0.0%  | Algar Telecom
    AS46887  | US | 1379     |   0.3%  | Zayo Bandwidth
    AS1031   | US | 1286     |   0.0%  | PEER 1031 LLC
    AS201054 | PL | 1109     |   0.0%  | Stowarzyszenie e-Poludnie
    AS61832  | BR | 685      |   0.0%  | Giga+ Empresas
    AS61568  | BR | 530      |   0.0%  | ALOO TELECOM - FSF TECNOLOGIA SA
    AS209    | US | 523      |   1.3%  | Lumen (ex. Qwest)
    AS10429  | BR | 518      |   0.0%  | Vivo (Telefônica Brasil)
    AS3786   | KR | 468      |   0.2%  | LG DACOM Corporation
    AS3549   | US | 432      |   0.9%  | Lumen (fka. Global Crossing)
    AS2764   | AU | 415      |   0.8%  | AAPT Limited
    AS62081  | PL | 281      |   0.0%  | Stowarzyszenie e-Poludnie
    AS28368  | BR | 278      |   0.0%  | Wirelink (Sobralnet)
    AS22381  | BR | 256      |   0.0%  | SAMM (Megatelecom)

    ===============================================================================================
    2. SCREAMING INTO THE VOID (Fully Signed, Vulnerable Upstreams)
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Signed%  | Name
    -----------------------------------------------------------------------------------------------
    AS4134   | CN | 65119    | 100.0%  | China Telecom Backbone
    AS37721  | BF | 57997    | 100.0%  | Virtual Technologies & Solutions
    AS4837   | CN | 47113    |  99.4%  | China Unicom Backbone
    AS38001  | SG | 7804     | 100.0%  | NewMedia Express Pte. Ltd.
    AS52468  | PA | 5670     | 100.0%  | UFINET PANAMA S.A.
    AS14789  | US | 1252     | 100.0%  | Cloudflare, Inc.
    AS12741  | PL | 784      |  98.9%  | Netia SA
    AS23947  | ID | 469      | 100.0%  | PT Mora Telematika Indonesia Tbk
    AS18229  | IN | 448      | 100.0%  | CtrlS
    AS45820  | IN | 336      |  98.2%  | Tata Teleservices ISP
    AS42337  | IR | 278      |  97.7%  | Respina Networks & Beyond PJSC
    AS131111 | ID | 222      |  99.8%  | PT Mora Telematika Indonesia Tbk
    AS20115  | US | 222      |  98.3%  | Charter Communications LLC
    AS971    | US | 211      | 100.0%  | PureVoltage Hosting Inc.
    AS401753 | VG | 204      | 100.0%  | BIXCE Inc

    ===============================================================================================
    3. WEIGHTED EVANGELISM TARGETS
       Metric = (Provider Cone Size) * (Count of Unsigned Customers)
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Unsigned | Impact Score   | Name
    -----------------------------------------------------------------------------------------------
    AS6939   | US | 79854    | 31932    | 2,549,897,928  | Hurricane Electric LLC
    AS3356   | US | 74023    | 28886    | 2,138,228,378  | Lumen (Level 3)
    AS174    | US | 73342    | 25149    | 1,844,477,958  | Cogent Communications, LLC
    AS1299   | SE | 70874    | 25861    | 1,832,872,514  | Arelion (fka. Telia Carrier)
    AS3257   | US | 69204    | 24411    | 1,689,338,844  | GTT Communications Inc.
    AS6461   | US | 71737    | 23544    | 1,688,975,928  | Zayo Bandwidth
    AS2914   | US | 68256    | 22436    | 1,531,391,616  | NTT America, Inc.
    AS4637   | HK | 66534    | 22436    | 1,492,756,824  | Telstra International Limited
    AS6762   | IT | 65544    | 22678    | 1,486,406,832  | Telecom Italia Sparkle (Seabone)
    AS6453   | US | 67132    | 21996    | 1,476,635,472  | TATA Communications (America) Inc
    AS3491   | HK | 66592    | 21074    | 1,403,359,808  | PCCW Global (HK) Ltd.
    AS5511   | FR | 61062    | 21284    | 1,299,643,608  | Orange S.A.
    AS3320   | DE | 66584    | 19072    | 1,269,890,048  | Deutsche Telekom AG
    AS1273   | EU | 62062    | 20051    | 1,244,405,162  | Vodafone Group PLC
    AS12956  | ES | 61269    | 20091    | 1,230,955,479  | Telxius (Telefonica Global)
    AS4134   | CN | 65119    | 18761    | 1,221,697,559  | China Telecom Backbone
    AS6830   | NL | 61620    | 19674    | 1,212,311,880  | Liberty Global Europe Holding B.V.
    AS701    | US | 68366    | 13320    | 910,635,120    | Verizon Business
    AS9002   | GB | 46051    | 17498    | 805,800,398    | RETN Limited
    AS4837   | CN | 47113    | 11992    | 564,979,096    | China Unicom Backbone
    AS4809   | CN | 64834    | 8085     | 524,182,890    | China Telecom Next Generation Carri
    AS7018   | US | 69063    | 4251     | 293,586,813    | AT&T Enterprises, LLC
    AS34927  | CH | 34152    | 6439     | 219,904,728    | iFog GmbH
    AS20485  | RU | 32970    | 6633     | 218,690,010    | TransTeleCom JSC
    AS33891  | DE | 34392    | 5812     | 199,886,304    | Core-Backbone GmbH

    [+] Saved strategy to roa_strategy_weighted_v2.csv
