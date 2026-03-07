    [*] Loading Data...
        - Scanning JSON cache for ROA stats... OK (120980 records)
    [*] Classifying Quadrants (this takes a moment)...
        - Processing 200/1199...    - Processing 400/1199...    - Processing 600/1199...    - Processing 800/1199...    - Processing 1000/1199...
    ==============================================================================================================
    ROV STRATEGIC QUADRANT REPORT
    ==============================================================================================================

    === Q1: GOLD STANDARD ===
       IDEAL STATE: Secure Provider + Responsible Customers.
       The system is working as intended.
    --------------------------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | % Sign | Name
    --------------------------------------------------------------------------------------------------------------
    AS6939   | US | 67899    |  60.1% | Hurricane Electric LLC
    AS1299   | SE | 47517    |  65.8% | Arelion (fka. Telia Carrier)
    AS9002   | GB | 45924    |  67.7% | RETN Limited
    AS17639  | PH | 41435    |  84.8% | Converge ICT Solutions Inc.
    AS34549  | DE | 34644    |  67.3% | meerfarbig GmbH & Co. KG

    === Q2: THE VICTIMS ===
       SCREAMING INTO THE VOID: Customers have signed ROAs (>60%), but Provider is LEAKING.
       These providers are negating their customers' hard work.
    --------------------------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | % Sign | Name
    --------------------------------------------------------------------------------------------------------------
    AS24482  | SG | 65177    |  74.0% | SG.GS
    AS37721  | BF | 58102    |  66.6% | Virtual Technologies & Solutions
    AS35280  | FR | 52107    |  66.2% | F5 Networks SARL
    AS8966   | AE | 6501     |  75.6% | Etisalat (ETC)
    AS24115  | SG | 3135     |  77.2% | Equinix IX

    === Q3: WASTED TECH ===
       GLASS HOUSES: Provider filters invalids, but Customers (<60%) haven't signed ROAs.
       The provider's security hardware is idle because customers are lazy.
    --------------------------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | % Sign | Name
    --------------------------------------------------------------------------------------------------------------
    AS3356   | US | 65326    |  33.5% | Lumen (Level 3)
    AS174    | US | 64687    |  43.8% | Cogent Communications, LLC
    AS6461   | US | 41149    |  32.7% | Zayo Bandwidth
    AS3216   | RU | 38066    |  31.9% | Vimpelcom PJSC
    AS34927  | CH | 32458    |  33.9% | iFog GmbH

    === Q4: THE SWAMP ===
       TOTAL FAILURE: Vulnerable Provider + Unsigned Customers.
       The 'Wild West' of the internet.
    --------------------------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | % Sign | Name
    --------------------------------------------------------------------------------------------------------------
    AS38255  | CN | 4183     |   0.0% | China Education and Research Network (CERNET)
    AS9930   | MY | 3049     |  52.8% | TIME dotCom Bhd
    AS23764  | HK | 2434     |  58.0% | China Telecom Global
    AS202365 | TR | 2178     |  48.5% | Chronos
    AS52025  | GB | 2066     |  56.4% | ParadoxNetworks Limited

    [+] Full quadrant data saved to rov_quadrant_top5_v3.csv
