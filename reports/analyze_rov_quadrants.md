    [*] Loading Data...
        - Scanning JSON cache for ROA stats... OK (120467 records)
    [*] Classifying Quadrants (this takes a moment)...
        - Processing 200/1178...    - Processing 400/1178...    - Processing 600/1178...    - Processing 800/1178...    - Processing 1000/1178...
    ==============================================================================================================
    ROV STRATEGIC QUADRANT REPORT
    ==============================================================================================================

    === Q1: GOLD STANDARD ===
       IDEAL STATE: Secure Provider + Responsible Customers.
       The system is working as intended.
    --------------------------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | % Sign | Name
    --------------------------------------------------------------------------------------------------------------
    AS1299   | SE | 47707    |  65.1% | Arelion (fka. Telia Carrier)
    AS9002   | GB | 44712    |  67.7% | RETN Limited
    AS17639  | PH | 41976    |  84.7% | Converge ICT Solutions Inc.
    AS34549  | DE | 34174    |  63.8% | meerfarbig GmbH & Co. KG
    AS33891  | DE | 33875    |  68.1% | Core-Backbone GmbH

    === Q2: THE VICTIMS ===
       SCREAMING INTO THE VOID: Customers have signed ROAs (>60%), but Provider is LEAKING.
       These providers are negating their customers' hard work.
    --------------------------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | % Sign | Name
    --------------------------------------------------------------------------------------------------------------
    AS24482  | SG | 65008    |  73.6% | SG.GS
    AS37721  | BF | 58249    |  66.6% | Virtual Technologies & Solutions
    AS35280  | FR | 50699    |  66.2% | F5 Networks SARL
    AS8966   | AE | 6022     |  75.5% | Etisalat (ETC)
    AS57304  | RU | 4144     |  71.6% | RETN Russia

    === Q3: WASTED TECH ===
       GLASS HOUSES: Provider filters invalids, but Customers (<60%) haven't signed ROAs.
       The provider's security hardware is idle because customers are lazy.
    --------------------------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | % Sign | Name
    --------------------------------------------------------------------------------------------------------------
    AS6939   | US | 67716    |  59.7% | Hurricane Electric LLC
    AS3356   | US | 66883    |  33.1% | Lumen (Level 3)
    AS174    | US | 64425    |  43.1% | Cogent Communications, LLC
    AS6461   | US | 43299    |  31.9% | Zayo Bandwidth
    AS3216   | RU | 38493    |  31.4% | Vimpelcom PJSC

    === Q4: THE SWAMP ===
       TOTAL FAILURE: Vulnerable Provider + Unsigned Customers.
       The 'Wild West' of the internet.
    --------------------------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | % Sign | Name
    --------------------------------------------------------------------------------------------------------------
    AS38255  | CN | 4183     |   0.0% | China Education and Research Network (CERNET)
    AS9930   | MY | 2439     |  51.8% | TIME dotCom Bhd
    AS23764  | HK | 2197     |  58.5% | China Telecom Global
    AS9049   | RU | 1132     |  33.0% | JSC "ER-Telecom Holding"
    AS202365 | TR | 1108     |  47.8% | Chronos

    [+] Full quadrant data saved to rov_quadrant_top5_v3.csv
