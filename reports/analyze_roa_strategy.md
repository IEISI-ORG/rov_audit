    [*] Loading Data for ROA Strategy Report...
        - Loading Cones from final_as_rank.csv... OK (86353 ASNs)
        - Loading Graph from data/downstream_graph.json... OK
        - Loading ASN data from packed file... OK (122,260 records)

    ===============================================================================================
    1. THE GLASS HOUSES (Secure Providers, Unsigned Routes)
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Signed%  | Name
    -----------------------------------------------------------------------------------------------
    AS33891  | DE | 34369    |   0.0%  | Core-Backbone GmbH
    AS48185  | BE | 21512    |   0.0%  | team.blue NV
    AS201054 | PL | 865      |   0.0%  | Stowarzyszenie e-Poludnie
    AS209    | US | 622      |   1.3%  | Lumen (ex. Qwest)
    AS61568  | BR | 571      |   0.0%  | ALOO TELECOM - FSF TECNOLOGIA SA
    AS3549   | US | 517      |   1.2%  | Lumen (fka. Global Crossing)
    AS28368  | BR | 351      |   0.0%  | Wirelink (Sobralnet)
    AS23106  | BR | 264      |   0.0%  | American Tower Brasil
    AS263009 | BR | 251      |   0.0%  | FORTE TELECOM LTDA.
    AS28598  | BR | 188      |   0.0%  | MOB
    AS265269 | BR | 187      |   0.0%  | MEGA TELE INFORMATICA
    AS3269   | IT | 174      |   0.1%  | TIM S.p.A. (fka. Telecom Italia S.p.A.)
    AS13649  | US | 171      |   1.7%  | Flexential Colorado Corp.
    AS7738   | BR | 166      |   0.0%  | V.tal
    AS21574  | BR | 149      |   0.0%  | Century Telecom Ltda

    ===============================================================================================
    2. SCREAMING INTO THE VOID (Fully Signed, Vulnerable Upstreams)
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Signed%  | Name
    -----------------------------------------------------------------------------------------------
    AS6461   | US | 70612    | 100.0%  | Zayo Bandwidth
    AS6762   | IT | 65564    | 100.0%  | Telecom Italia Sparkle (Seabone)
    AS37721  | BF | 58127    | 100.0%  | Virtual Technologies & Solutions
    AS17639  | PH | 42313    |  97.8%  | Converge ICT Solutions Inc.
    AS34927  | CH | 31562    | 100.0%  | iFog GmbH
    AS31133  | RU | 10063    |  99.8%  | MegaFon PJSC
    AS38001  | SG | 7890     | 100.0%  | NewMedia Express Pte. Ltd.
    AS56655  | NO | 6834     | 100.0%  | Gigahost AS
    AS9304   | HK | 5231     |  97.7%  | HGC Global Communications Limited
    AS52468  | PA | 5015     | 100.0%  | UFINET PANAMA S.A.
    AS32787  | US | 3081     | 100.0%  | Akamai (Prolexic)
    AS4755   | IN | 2497     |  96.6%  | TATA Communications (formerly VSNL)
    AS53062  | BR | 1474     |  99.1%  | ALT | GRUPO BRASIL TECPAR
    AS20764  | RU | 1143     | 100.0%  | CJSC RASCOM
    AS202365 | TR | 1078     | 100.0%  | Chronos

    ===============================================================================================
    3. WEIGHTED EVANGELISM TARGETS
       Metric = (Provider Cone Size) * (Count of Unsigned Customers)
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Unsigned | Impact Score   | Name
    -----------------------------------------------------------------------------------------------
    AS3356   | US | 73001    | 30721    | 2,242,663,721  | Lumen (Level 3)
    AS6939   | US | 74912    | 29210    | 2,188,179,520  | Hurricane Electric LLC
    AS174    | US | 72425    | 27891    | 2,020,005,675  | Cogent Communications, LLC
    AS1299   | SE | 69799    | 28526    | 1,991,086,274  | Arelion (fka. Telia Carrier)
    AS6461   | US | 70612    | 27815    | 1,964,072,780  | Zayo Bandwidth
    AS3257   | US | 68229    | 25388    | 1,732,197,852  | GTT Communications Inc.
    AS2914   | US | 67256    | 25468    | 1,712,875,808  | NTT America, Inc.
    AS4637   | HK | 63842    | 25800    | 1,647,123,600  | Telstra International Limited
    AS6453   | US | 63584    | 25611    | 1,628,449,824  | TATA Communications (America) Inc
    AS3320   | DE | 64811    | 24235    | 1,570,694,585  | Deutsche Telekom AG
    AS6762   | IT | 65564    | 23730    | 1,555,833,720  | Telecom Italia Sparkle (Seabone)
    AS1273   | EU | 62000    | 25060    | 1,553,720,000  | Vodafone Group PLC
    AS12956  | ES | 61462    | 23976    | 1,473,612,912  | Telxius (Telefonica Global)
    AS4134   | CN | 60707    | 24075    | 1,461,521,025  | China Telecom Backbone
    AS3491   | HK | 64995    | 21935    | 1,425,665,325  | PCCW Global (HK) Ltd.
    AS5511   | FR | 61042    | 22593    | 1,379,121,906  | Orange S.A.
    AS6830   | NL | 61310    | 20187    | 1,237,664,970  | Liberty Global Europe Holding B.V.
    AS35280  | FR | 50483    | 21191    | 1,069,785,253  | F5 Networks SARL
    AS701    | US | 67302    | 15726    | 1,058,391,252  | Verizon Business
    AS4809   | CN | 45934    | 22094    | 1,014,865,796  | China Telecom Next Generation Carri
    AS9002   | GB | 46341    | 18191    | 842,989,131    | RETN Limited
    AS4837   | CN | 44096    | 11712    | 516,452,352    | China Unicom Backbone
    AS7018   | US | 67800    | 4130     | 280,014,000    | AT&T Enterprises, LLC
    AS3216   | RU | 34513    | 6825     | 235,551,225    | Vimpelcom PJSC
    AS33891  | DE | 34369    | 6574     | 225,941,806    | Core-Backbone GmbH

    [+] Saved strategy to roa_strategy_weighted_v2.csv
