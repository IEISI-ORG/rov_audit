    [*] Loading rov_audit_v22_final.csv...
        - Loading Cones from final_as_rank.csv... OK (86582 ASNs)
        - Loading Graph from data/downstream_graph.json... OK
    [!] 90 IXP phantom networks excluded (< 5% captive customers). Re-run build_topology for full fix.

    ================================================================================
     HERD IMMUNITY STATUS
    ================================================================================

    [GLOBAL CORE] (The 100 largest legitimate transit networks)
      Networks Secure:      57 / 100  (57.0%)
      Traffic Protected:   82.8% (by Cone Weight)
      Progress: |█████████████████████████████████████████░░░░░░░░░|

    [TRANSIT LAYER] (The 1000 largest legitimate transit networks)
      Networks Secure:     267 / 1000  (26.7%)
      Traffic Protected:   80.6% (by Cone Weight)
      Progress: |████████████████████████████████████████░░░░░░░░░░|

    ================================================================================
     THE HOLDOUTS (Top Vulnerable Transit Nets)
    ================================================================================
    ------------------------------------------------------------------------------------
    Rank  | ASN      | CC |       Cone |  Excl% | Name
    ------------------------------------------------------------------------------------
    #15   | AS4134   | CN |     64,918 |    74% | China Telecom Backbone
    #23   | AS4837   | CN |     43,958 |    66% | China Unicom Backbone
    #27   | AS20485  | RU |     28,709 |    21% | TransTeleCom JSC
    #31   | AS9304   | HK |      8,894 |    18% | HGC Global Communications Limited
    #41   | AS52468  | PA |      5,113 |    51% | UFINET PANAMA S.A.
    #50   | AS9808   | CN |      2,563 |    75% | China Mobile Backbone
    #75   | AS12741  | PL |        796 |    71% | Netia SA
    #76   | AS3223   | GB |        792 |    23% | Voxility LLP
    #78   | AS14789  | US |        726 |    28% | Cloudflare, Inc.
    #81   | AS9583   | IN |        665 |    57% | Sify Limited
    #90   | AS9929   | CN |        545 |    75% | China Unicom Industrial Internet Backbon
    #103  | AS18229  | IN |        445 |    77% | CtrlS
    #130  | AS45820  | IN |        330 |    69% | Tata Teleservices ISP
    #152  | AS53356  | CA |        270 |    28% | Free Range Cloud Hosting Inc.
    #174  | AS20115  | US |        232 |    73% | Charter Communications LLC
    #177  | AS9730   | IN |        231 |    74% | Bharti Telesonic Ltd
    #179  | AS42337  | IR |        230 |    90% | Respina Networks & Beyond PJSC
    #185  | AS131111 | ID |        223 |    28% | PT Mora Telematika Indonesia Tbk
    #186  | AS262663 | BR |        221 |    34% | METROFLEX TELECOMUNICACOES LTDA
    #187  | AS12302  | RO |        218 |    72% | Vodafone Romania S.A.
    #193  | AS13536  | US |        208 |    76% | FirstLight Networks, LLC
    #196  | AS263903 | BR |        202 |    60% | INFORBARRA TELECOM
    #203  | AS135607 | PH |        194 |    70% | Infinivan Incorporated
    #208  | AS20205  | US |        185 |     6% | Amplex Electric, Inc.
    #217  | AS7717   | ID |        178 |    30% | OpenIXP Route Servers
    ------------------------------------------------------------------------------------

    CONCLUSION:
    CLOSE TO IMMUNITY. The Core is mostly safe, but key giants remain.
