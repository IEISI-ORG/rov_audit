    [*] Loading Data for ROA Strategy Report...
        - Loading Cones from final_as_rank.csv... OK (86453 ASNs)
        - Loading Graph from data/downstream_graph.json... OK
        - Loading ASN data from packed file... OK (122,550 records)

    ===============================================================================================
    1. THE GLASS HOUSES (Secure Providers, Unsigned Routes)
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Signed%  | Name
    -----------------------------------------------------------------------------------------------
    AS3216   | RU | 34717    |   1.3%  | Vimpelcom PJSC
    AS48185  | BE | 22344    |   0.0%  | team.blue NV
    AS16735  | BR | 2619     |   0.0%  | Algar Telecom
    AS14840  | BR | 1457     |   0.0%  | BR.DIGITAL 
    AS46887  | US | 1372     |   0.3%  | Crown Castle Fiber LLC
    AS201054 | PL | 1350     |   0.0%  | Stowarzyszenie e-Poludnie
    AS209    | US | 610      |   1.3%  | Lumen (ex. Qwest)
    AS61568  | BR | 533      |   0.0%  | ALOO TELECOM - FSF TECNOLOGIA SA
    AS3549   | US | 478      |   1.2%  | Lumen (fka. Global Crossing)
    AS10429  | BR | 473      |   0.0%  | Vivo (TELEFÔNICA BRASIL)
    AS3786   | KR | 459      |   0.2%  | LG DACOM Corporation
    AS2764   | AU | 424      |   0.6%  | AAPT Limited
    AS24115  | SG | 296      |   0.0%  | Equinix IX
    AS62081  | PL | 286      |   0.0%  | Stowarzyszenie e-Poludnie
    AS61973  | CZ | 269      |   0.0%  | Netassist International s.r.o.

    ===============================================================================================
    2. SCREAMING INTO THE VOID (Fully Signed, Vulnerable Upstreams)
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Signed%  | Name
    -----------------------------------------------------------------------------------------------
    AS37721  | BF | 58192    | 100.0%  | Virtual Technologies & Solutions
    AS17639  | PH | 42698    |  97.9%  | Converge ICT Solutions Inc.
    AS38001  | SG | 7938     | 100.0%  | NewMedia Express Pte. Ltd.
    AS9304   | HK | 5182     | 100.0%  | HGC Global Communications Limited
    AS52468  | PA | 4857     | 100.0%  | UFINET PANAMA S.A.
    AS8220   | GB | 4784     | 100.0%  | COLT
    AS12741  | PL | 793      |  98.9%  | Netia SA
    AS14789  | US | 674      | 100.0%  | Cloudflare, Inc.
    AS18229  | IN | 458      |  96.2%  | CtrlS
    AS45820  | IN | 343      |  98.7%  | Tata Teleservices ISP
    AS12302  | RO | 215      |  99.6%  | Vodafone Romania S.A.
    AS131111 | ID | 210      | 100.0%  | PT Mora Telematika Indonesia Tbk
    AS42337  | IR | 206      | 100.0%  | Respina Networks & Beyond PJSC
    AS1680   | IL | 158      |  99.7%  | Cellcom Fixed Line Communication L.P
    AS4761   | ID | 158      | 100.0%  | PT Indosat Tbk

    ===============================================================================================
    3. WEIGHTED EVANGELISM TARGETS
       Metric = (Provider Cone Size) * (Count of Unsigned Customers)
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Unsigned | Impact Score   | Name
    -----------------------------------------------------------------------------------------------
    AS3356   | US | 73602    | 30138    | 2,218,217,076  | Lumen (Level 3)
    AS6939   | US | 74338    | 28694    | 2,133,054,572  | Hurricane Electric LLC
    AS174    | US | 73036    | 27410    | 2,001,916,760  | Cogent Communications, LLC
    AS1299   | SE | 70453    | 27353    | 1,927,100,909  | Arelion (fka. Telia Carrier)
    AS3257   | US | 68971    | 25702    | 1,772,692,642  | GTT Communications Inc.
    AS6461   | US | 71349    | 24616    | 1,756,326,984  | Zayo Bandwidth
    AS2914   | US | 68085    | 23936    | 1,629,682,560  | NTT America, Inc.
    AS6453   | US | 66767    | 23400    | 1,562,347,800  | TATA Communications (America) Inc
    AS4637   | HK | 64917    | 24059    | 1,561,838,103  | Telstra International Limited
    AS6762   | IT | 65480    | 23554    | 1,542,315,920  | Telecom Italia Sparkle (Seabone)
    AS3491   | HK | 66397    | 21825    | 1,449,114,525  | PCCW Global (HK) Ltd.
    AS5511   | FR | 61017    | 22541    | 1,375,384,197  | Orange S.A.
    AS3320   | DE | 65999    | 20089    | 1,325,853,911  | Deutsche Telekom AG
    AS12956  | ES | 61443    | 21153    | 1,299,703,779  | Telxius (Telefonica Global)
    AS4134   | CN | 64579    | 20073    | 1,296,294,267  | China Telecom Backbone
    AS1273   | EU | 61836    | 20746    | 1,282,849,656  | Vodafone Group PLC
    AS6830   | NL | 61359    | 20641    | 1,266,511,119  | Liberty Global Europe Holding B.V.
    AS701    | US | 68286    | 15449    | 1,054,950,414  | Verizon Business
    AS9002   | GB | 46818    | 18942    | 886,826,556    | RETN Limited
    AS4837   | CN | 47004    | 11557    | 543,225,228    | China Unicom Backbone
    AS4809   | CN | 63887    | 7652     | 488,863,324    | China Telecom Next Generation Carri
    AS7922   | US | 61061    | 7169     | 437,746,309    | Comcast Cable Communications, LLC
    AS7018   | US | 68858    | 4398     | 302,837,484    | AT&T Enterprises, LLC
    AS3216   | RU | 34717    | 6991     | 242,706,547    | Vimpelcom PJSC
    AS33891  | DE | 33883    | 6279     | 212,751,357    | Core-Backbone GmbH

    [+] Saved strategy to roa_strategy_weighted_v2.csv
