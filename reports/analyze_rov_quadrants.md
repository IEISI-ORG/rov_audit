    [*] Loading Data...
        - Scanning JSON cache for ROA stats... OK (120196 records)
    [*] Classifying Quadrants (this takes a moment)...
        - Processing 200/1165...    - Processing 400/1165...    - Processing 600/1165...    - Processing 800/1165...    - Processing 1000/1165...
    ==============================================================================================================
    ROV STRATEGIC QUADRANT REPORT
    ==============================================================================================================

    === Q1: GOLD STANDARD ===
       IDEAL STATE: Secure Provider + Responsible Customers.
       The system is working as intended.
    --------------------------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | % Sign | Name
    --------------------------------------------------------------------------------------------------------------
    AS1299   | SE | 46648    |  65.1% | Arelion (fka. Telia Carrier)
    AS9002   | GB | 44394    |  67.7% | RETN Limited
    AS17639  | PH | 41299    |  84.7% | Converge ICT Solutions Inc.
    AS41327  | IT | 36558    |  86.5% | Fiber Telecom S.p.A.
    AS34549  | DE | 34483    |  63.8% | meerfarbig GmbH & Co. KG

    === Q2: THE VICTIMS ===
       SCREAMING INTO THE VOID: Customers have signed ROAs (>60%), but Provider is LEAKING.
       These providers are negating their customers' hard work.
    --------------------------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | % Sign | Name
    --------------------------------------------------------------------------------------------------------------
    AS24482  | SG | 64806    |  73.6% | SG.GS
    AS37721  | BF | 57892    |  66.6% | Virtual Technologies & Solutions
    AS35280  | FR | 50697    |  66.2% | F5 Networks SARL
    AS8966   | AE | 5932     |  75.5% | Etisalat (ETC)
    AS57304  | RU | 3891     |  71.6% | RETN Russia

    === Q3: WASTED TECH ===
       GLASS HOUSES: Provider filters invalids, but Customers (<60%) haven't signed ROAs.
       The provider's security hardware is idle because customers are lazy.
    --------------------------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | % Sign | Name
    --------------------------------------------------------------------------------------------------------------
    AS6939   | US | 67596    |  59.7% | Hurricane Electric LLC
    AS3356   | US | 66688    |  33.1% | Lumen (Level 3)
    AS174    | US | 64462    |  43.1% | Cogent Communications, LLC
    AS6461   | US | 41650    |  31.9% | Zayo Bandwidth
    AS3216   | RU | 37970    |  31.4% | Vimpelcom PJSC

    === Q4: THE SWAMP ===
       TOTAL FAILURE: Vulnerable Provider + Unsigned Customers.
       The 'Wild West' of the internet.
    --------------------------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | % Sign | Name
    --------------------------------------------------------------------------------------------------------------
    AS38255  | CN | 4183     |   0.0% | China Education and Research Network (CERNET)
    AS9930   | MY | 2531     |  51.8% | TIME dotCom Bhd
    AS23764  | HK | 2319     |  58.5% | China Telecom Global
    AS52025  | GB | 2160     |  56.3% | ParadoxNetworks Limited
    AS202365 | TR | 1198     |  47.8% | Chronos

    [+] Full quadrant data saved to rov_quadrant_top5_v3.csv
