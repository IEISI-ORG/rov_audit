    [*] Loading Data...
        - Loading Cones from final_as_rank.csv... OK (87018 ASNs)
        - Loading Graph from data/downstream_graph.json... OK
        - Loading ASN data from packed file... OK (123,966 records)
    [!] 70 IXP phantom networks excluded (< 5% captive customers).
    [*] Classifying Quadrants (this takes a moment)...
        - Processing 200/1140...    - Processing 400/1140...    - Processing 600/1140...    - Processing 800/1140...    - Processing 1000/1140...
    ==============================================================================================================
     ROV STRATEGIC QUADRANT REPORT
    ==============================================================================================================

    === Q1: GOLD STANDARD ===
       IDEAL STATE: Secure Provider + Responsible Customers.
       The system is working as intended.
    --------------------------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | % Sign | Name
    --------------------------------------------------------------------------------------------------------------
    AS4809   | CN | 64834    |  61.1% | China Telecom Next Generation Carrier Network
    AS34927  | CH | 34152    |  60.5% | iFog GmbH
    AS208972 | TR | 8127     |  66.1% | GIBIRNet Iletisim
    AS8218   | FR | 7426     |  69.5% | Zayo Europe
    AS9498   | IN | 7002     |  72.4% | Bharti Airtel Ltd.

    === Q2: THE VICTIMS ===
       SCREAMING INTO THE VOID: Customers have signed ROAs (>60%), but Provider is LEAKING.
       These providers are negating their customers' hard work.
    --------------------------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | % Sign | Name
    --------------------------------------------------------------------------------------------------------------
    AS33891  | DE | 34392    |  62.9% | Core-Backbone GmbH
    AS20485  | RU | 32970    |  62.8% | TransTeleCom JSC
    AS3303   | CH | 9224     |  62.3% | Swisscom (Schweiz) AG
    AS1103   | NL | 6177     |  67.3% | SURF B.V.
    AS13030  | CH | 5186     |  67.6% | Init7 (Switzerland) Ltd.

    === Q3: WASTED TECH ===
       GLASS HOUSES: Provider filters invalids, but Customers (<60%) haven't signed ROAs.
       The provider's security hardware is idle because customers are lazy.
    --------------------------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | % Sign | Name
    --------------------------------------------------------------------------------------------------------------
    AS6939   | US | 79854    |  52.7% | Hurricane Electric LLC
    AS3356   | US | 74023    |  54.3% | Lumen (Level 3)
    AS174    | US | 73342    |  55.9% | Cogent Communications, LLC
    AS6461   | US | 71737    |  56.5% | Zayo Bandwidth
    AS1299   | SE | 70874    |  56.3% | Arelion (fka. Telia Carrier)

    === Q4: THE SWAMP ===
       TOTAL FAILURE: Vulnerable Provider + Unsigned Customers.
       The 'Wild West' of the internet.
    --------------------------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | % Sign | Name
    --------------------------------------------------------------------------------------------------------------
    AS4134   | CN | 65119    |  58.8% | China Telecom Backbone
    AS4837   | CN | 47113    |  59.3% | China Unicom Backbone
    AS9002   | GB | 46051    |  59.4% | RETN Limited
    AS3216   | RU | 25976    |  57.4% | Vimpelcom PJSC
    AS12389  | RU | 11475    |  54.8% | Rostelecom PJSC

    [+] Full quadrant data saved to rov_quadrants_full.csv
