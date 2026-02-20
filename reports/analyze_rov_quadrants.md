    [*] Loading Data...
        - Scanning JSON cache for ROA stats... OK (120468 records)
    [*] Classifying Quadrants (this takes a moment)...
        - Processing 200/1181...    - Processing 400/1181...    - Processing 600/1181...    - Processing 800/1181...    - Processing 1000/1181...
    ==============================================================================================================
    ROV STRATEGIC QUADRANT REPORT
    ==============================================================================================================

    === Q1: GOLD STANDARD ===
       IDEAL STATE: Secure Provider + Responsible Customers.
       The system is working as intended.
    --------------------------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | % Sign | Name
    --------------------------------------------------------------------------------------------------------------
    AS6939   | US | 67852    |  60.1% | Unknown
    AS1299   | SE | 47379    |  65.8% | Unknown
    AS9002   | GB | 44443    |  67.7% | Unknown
    AS17639  | PH | 40743    |  84.8% | Unknown
    AS33891  | XX | 33990    |  68.2% | Unknown

    === Q2: THE VICTIMS ===
       SCREAMING INTO THE VOID: Customers have signed ROAs (>60%), but Provider is LEAKING.
       These providers are negating their customers' hard work.
    --------------------------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | % Sign | Name
    --------------------------------------------------------------------------------------------------------------
    AS24482  | SG | 65092    |  74.0% | Unknown
    AS37721  | BF | 57511    |  66.6% | Unknown
    AS35280  | FR | 51600    |  66.2% | Unknown
    AS8966   | AE | 4152     |  75.6% | Unknown
    AS24115  | XX | 2965     |  77.2% | Unknown

    === Q3: WASTED TECH ===
       GLASS HOUSES: Provider filters invalids, but Customers (<60%) haven't signed ROAs.
       The provider's security hardware is idle because customers are lazy.
    --------------------------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | % Sign | Name
    --------------------------------------------------------------------------------------------------------------
    AS3356   | US | 65297    |  33.5% | Unknown
    AS174    | US | 64638    |  43.8% | Unknown
    AS6461   | US | 42904    |  32.7% | Unknown
    AS3216   | RU | 36753    |  31.9% | Unknown
    AS3257   | US | 30050    |  50.0% | Unknown

    === Q4: THE SWAMP ===
       TOTAL FAILURE: Vulnerable Provider + Unsigned Customers.
       The 'Wild West' of the internet.
    --------------------------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | % Sign | Name
    --------------------------------------------------------------------------------------------------------------
    AS38255  | CN | 4183     |   0.0% | Unknown
    AS9930   | MY | 2727     |  52.8% | Unknown
    AS23764  | HK | 2500     |  58.0% | Unknown
    AS52025  | GB | 1929     |  56.4% | Unknown
    AS56662  | PL | 1890     |   0.0% | Unknown

    [+] Full quadrant data saved to rov_quadrant_top5_v3.csv
