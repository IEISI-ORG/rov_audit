    [*] Loading rov_audit_v22_final.csv...
        - Loading Cones from final_as_rank.csv... OK (86353 ASNs)
        - Loading Graph from data/downstream_graph.json... OK
    [!] 77 IXP phantom networks excluded (< 5% captive customers). Re-run build_topology for full fix.

    ================================================================================
     HERD IMMUNITY STATUS
    ================================================================================

    [GLOBAL CORE] (The 100 largest legitimate transit networks)
      Networks Secure:      33 / 100  (33.0%)
      Traffic Protected:   68.6% (by Cone Weight)
      Progress: |██████████████████████████████████░░░░░░░░░░░░░░░░|

    [TRANSIT LAYER] (The 1000 largest legitimate transit networks)
      Networks Secure:     262 / 1000  (26.2%)
      Traffic Protected:   66.6% (by Cone Weight)
      Progress: |█████████████████████████████████░░░░░░░░░░░░░░░░░|

    ================================================================================
     THE HOLDOUTS (Top Vulnerable Transit Nets)
    ================================================================================
    ------------------------------------------------------------------------------------
    Rank  | ASN      | CC |       Cone |  Excl% | Name
    ------------------------------------------------------------------------------------
    #4    | AS6461   | US |     70,612 |    39% | Zayo Bandwidth
    #10   | AS6762   | IT |     65,564 |    10% | Telecom Italia Sparkle (Seabone)
    #19   | AS4134   | CN |     60,707 |    81% | China Telecom Backbone
    #23   | AS4837   | CN |     44,096 |    65% | China Unicom Backbone
    #24   | AS3216   | RU |     34,513 |    28% | Vimpelcom PJSC
    #26   | AS34927  | CH |     31,562 |    10% | iFog GmbH
    #27   | AS20485  | RU |     29,164 |    21% | TransTeleCom JSC
    #32   | AS31133  | RU |     10,063 |    34% | MegaFon PJSC
    #34   | AS9498   | IN |      8,526 |    53% | Bharti Airtel Ltd.
    #37   | AS7713   | ID |      6,842 |    13% | PT Telkom Indonesia Tbk
    #38   | AS56655  | NO |      6,834 |     5% | Gigahost AS
    #41   | AS9304   | HK |      5,231 |    22% | HGC Global Communications Limited
    #42   | AS52468  | PA |      5,015 |    46% | UFINET PANAMA S.A.
    #50   | AS32787  | US |      3,081 |    52% | Akamai (Prolexic)
    #52   | AS9808   | CN |      2,537 |    77% | China Mobile Backbone
    #53   | AS4755   | IN |      2,497 |    54% | TATA Communications (formerly VSNL)
    #59   | AS8359   | RU |      2,053 |    60% | MTS PJSC
    #65   | AS53062  | BR |      1,474 |    60% | ALT | GRUPO BRASIL TECPAR
    #67   | AS46887  | US |      1,375 |    67% | Crown Castle Fiber LLC
    #69   | AS20764  | RU |      1,143 |    16% | CJSC RASCOM
    #70   | AS4230   | BR |      1,125 |    50% | Claro (Embratel)
    #73   | AS4766   | KR |      1,035 |    78% | Korea Telecom
    #77   | AS35598  | RU |        845 |    17% | INETCOM CARRIER LLC
    #79   | AS9049   | RU |        813 |    58% | JSC "ER-Telecom Holding"
    #80   | AS12741  | PL |        802 |    70% | Netia SA
    ------------------------------------------------------------------------------------

    CONCLUSION:
    NO IMMUNITY. Major transit providers are still leaking routes.
