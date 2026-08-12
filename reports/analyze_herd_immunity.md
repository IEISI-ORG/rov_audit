    [*] Loading rov_audit_v22_final.csv...
        - Loading Cones from final_as_rank.csv... OK (87018 ASNs)
        - Loading Graph from data/downstream_graph.json... OK
    [!] 88 IXP phantom networks excluded (< 5% captive customers). Re-run build_topology for full fix.

    ================================================================================
     HERD IMMUNITY STATUS
    ================================================================================

    [GLOBAL CORE] (The 100 largest legitimate transit networks)
      Networks Secure:      63 / 100  (63.0%)
      Traffic Protected:   81.8% (by Cone Weight)
      Progress: |████████████████████████████████████████░░░░░░░░░░|

    [TRANSIT LAYER] (The 1000 largest legitimate transit networks)
      Networks Secure:     313 / 1000  (31.3%)
      Traffic Protected:   79.8% (by Cone Weight)
      Progress: |███████████████████████████████████████░░░░░░░░░░░|

    ================================================================================
     THE HOLDOUTS (Top Vulnerable Transit Nets)
    ================================================================================
    ------------------------------------------------------------------------------------
    Rank  | ASN      | CC |       Cone |  Excl% | Name
    ------------------------------------------------------------------------------------
    #15   | AS4134   | CN |     65,119 |    80% | China Telecom Backbone
    #21   | AS4837   | CN |     47,113 |    62% | China Unicom Backbone
    #26   | AS3216   | RU |     25,976 |    32% | Vimpelcom PJSC
    #37   | AS52468  | PA |      5,670 |    50% | UFINET PANAMA S.A.
    #50   | AS9808   | CN |      2,366 |    73% | China Mobile Backbone
    #57   | AS9929   | CN |      1,748 |    67% | China Unicom Industrial Internet Backbon
    #66   | AS14789  | US |      1,252 |    22% | Cloudflare, Inc.
    #78   | AS12741  | PL |        784 |    71% | Netia SA
    #109  | AS18229  | IN |        448 |    81% | CtrlS
    #130  | AS45820  | IN |        336 |    68% | Tata Teleservices ISP
    #151  | AS42337  | IR |        278 |    91% | Respina Networks & Beyond PJSC
    #174  | AS9730   | IN |        230 |    74% | Bharti Telesonic Ltd
    #175  | AS13536  | US |        230 |    76% | FirstLight Networks, LLC
    #182  | AS20115  | US |        222 |    71% | Charter Communications LLC
    #183  | AS131111 | ID |        222 |    34% | PT Mora Telematika Indonesia Tbk
    #194  | AS7717   | ID |        208 |    30% | OpenIXP Route Servers
    #195  | AS263903 | BR |        204 |    62% | INFORBARRA TELECOM
    #225  | AS52925  | BR |        173 |    32% | Ascenty Data Centers e Telecomunicações 
    #240  | AS1680   | IL |        165 |    69% | Cellcom Fixed Line Communication L.P
    #264  | AS4761   | ID |        145 |    54% | PT Indosat Tbk
    #278  | AS17665  | IN |        134 |    84% | ONEOTT INTERTAINMENT LIMITED
    #284  | AS42020  | LB |        132 |    99% | OGERO
    #290  | AS17995  | ID |        129 |    68% | PT iForte Global Internet
    #304  | AS17762  | IN |        121 |    63% | Tata Teleservices Maharashtra Ltd
    #320  | AS8434   | SE |        111 |    66% | Telenor Sverige AB
    ------------------------------------------------------------------------------------

    CONCLUSION:
    CLOSE TO IMMUNITY. The Core is mostly safe, but key giants remain.
