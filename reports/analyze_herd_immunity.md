    [*] Loading rov_audit_v22_final.csv...
        - Loading Cones from final_as_rank.csv... OK (86453 ASNs)
        - Loading Graph from data/downstream_graph.json... OK
    [!] 83 IXP phantom networks excluded (< 5% captive customers). Re-run build_topology for full fix.

    ================================================================================
     HERD IMMUNITY STATUS
    ================================================================================

    [GLOBAL CORE] (The 100 largest legitimate transit networks)
      Networks Secure:      58 / 100  (58.0%)
      Traffic Protected:   82.8% (by Cone Weight)
      Progress: |█████████████████████████████████████████░░░░░░░░░|

    [TRANSIT LAYER] (The 1000 largest legitimate transit networks)
      Networks Secure:     272 / 1000  (27.2%)
      Traffic Protected:   80.5% (by Cone Weight)
      Progress: |████████████████████████████████████████░░░░░░░░░░|

    ================================================================================
     THE HOLDOUTS (Top Vulnerable Transit Nets)
    ================================================================================
    ------------------------------------------------------------------------------------
    Rank  | ASN      | CC |       Cone |  Excl% | Name
    ------------------------------------------------------------------------------------
    #15   | AS4134   | CN |     64,579 |    81% | China Telecom Backbone
    #22   | AS4837   | CN |     47,004 |    67% | China Unicom Backbone
    #27   | AS20485  | RU |     28,703 |    22% | TransTeleCom JSC
    #41   | AS9304   | HK |      5,182 |    22% | HGC Global Communications Limited
    #42   | AS52468  | PA |      4,857 |    50% | UFINET PANAMA S.A.
    #43   | AS8220   | GB |      4,784 |    55% | COLT
    #51   | AS9808   | CN |      2,629 |    76% | China Mobile Backbone
    #76   | AS12741  | PL |        793 |    70% | Netia SA
    #80   | AS14789  | US |        674 |    29% | Cloudflare, Inc.
    #89   | AS9929   | CN |        543 |    69% | China Unicom Industrial Internet Backbon
    #104  | AS18229  | IN |        458 |    78% | CtrlS
    #130  | AS45820  | IN |        343 |    69% | Tata Teleservices ISP
    #175  | AS20115  | US |        232 |    73% | Charter Communications LLC
    #180  | AS9730   | IN |        229 |    73% | Bharti Telesonic Ltd
    #185  | AS12302  | RO |        215 |    72% | Vodafone Romania S.A.
    #186  | AS971    | US |        215 |    11% | PureVoltage Hosting Inc.
    #193  | AS131111 | ID |        210 |    29% | PT Mora Telematika Indonesia Tbk
    #196  | AS42337  | IR |        206 |    90% | Respina Networks & Beyond PJSC
    #200  | AS263903 | BR |        201 |    57% | INFORBARRA TELECOM
    #211  | AS20205  | US |        187 |     6% | Amplex Electric, Inc.
    #219  | AS262663 | BR |        182 |    27% | METROFLEX TELECOMUNICACOES LTDA
    #230  | AS7717   | ID |        174 |    32% | OpenIXP Route Servers
    #249  | AS52925  | BR |        161 |    30% | Ascenty Data Centers e Telecomunicações 
    #258  | AS4761   | ID |        158 |    52% | PT Indosat Tbk
    #260  | AS1680   | IL |        158 |    69% | Cellcom Fixed Line Communication L.P
    ------------------------------------------------------------------------------------

    CONCLUSION:
    CLOSE TO IMMUNITY. The Core is mostly safe, but key giants remain.
