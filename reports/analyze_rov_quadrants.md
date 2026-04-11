    [*] Loading Data...
        - Scanning JSON cache for ROA stats... OK (121350 records)
    [*] Classifying Quadrants (this takes a moment)...
        - Processing 200/1191...    - Processing 400/1191...    - Processing 600/1191...    - Processing 800/1191...    - Processing 1000/1191...
    ==============================================================================================================
    ROV STRATEGIC QUADRANT REPORT
    ==============================================================================================================

    === Q1: GOLD STANDARD ===
       IDEAL STATE: Secure Provider + Responsible Customers.
       The system is working as intended.
    --------------------------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | % Sign | Name
    --------------------------------------------------------------------------------------------------------------
    AS6939   | US | 68256    |  61.1% | Hurricane Electric LLC
    AS1299   | SE | 48082    |  66.4% | Arelion (fka. Telia Carrier)
    AS9002   | GB | 46955    |  67.8% | RETN Limited
    AS17639  | PH | 42567    |  85.7% | Converge ICT Solutions Inc.
    AS34549  | DE | 34154    |  67.2% | meerfarbig GmbH & Co. KG

    === Q2: THE VICTIMS ===
       SCREAMING INTO THE VOID: Customers have signed ROAs (>60%), but Provider is LEAKING.
       These providers are negating their customers' hard work.
    --------------------------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | % Sign | Name
    --------------------------------------------------------------------------------------------------------------
    AS24482  | SG | 65410    |  73.6% | SG.GS
    AS37721  | BF | 58181    |  66.8% | Virtual Technologies & Solutions
    AS35280  | FR | 50969    |  66.2% | F5 Networks SARL
    AS50300  | GB | 22908    |  85.3% | CustodianDC Limited
    AS48185  | BE | 21510    |  68.6% | team.blue NV

    === Q3: WASTED TECH ===
       GLASS HOUSES: Provider filters invalids, but Customers (<60%) haven't signed ROAs.
       The provider's security hardware is idle because customers are lazy.
    --------------------------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | % Sign | Name
    --------------------------------------------------------------------------------------------------------------
    AS3356   | US | 64668    |  34.1% | Lumen (Level 3)
    AS174    | US | 64504    |  44.7% | Cogent Communications, LLC
    AS6461   | US | 40790    |  33.4% | Zayo Bandwidth
    AS3216   | RU | 35508    |  32.1% | Vimpelcom PJSC
    AS34927  | CH | 32720    |  35.2% | iFog GmbH

    === Q4: THE SWAMP ===
       TOTAL FAILURE: Vulnerable Provider + Unsigned Customers.
       The 'Wild West' of the internet.
    --------------------------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | % Sign | Name
    --------------------------------------------------------------------------------------------------------------
    AS213241 | BE | 24556    |   0.0% | TECHIT.BE SRL
    AS212024 | FR | 13883    |   0.0% | Marc Schmitt
    AS31500  | AG | 12515    |  59.1% | Global Network Management Inc
    AS9498   | IN | 7821     |  57.7% | Bharti Airtel Ltd.
    AS58057  | CH | 6662     |  43.6% | Securebit AG

    [+] Full quadrant data saved to rov_quadrant_top5_v3.csv
