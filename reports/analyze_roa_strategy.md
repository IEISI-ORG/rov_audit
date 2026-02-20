    [*] Loading V19 Data Sets...
        - Scanning JSON cache for ROA stats... OK (120468 records)
        - Loading Topology... OK

    ===============================================================================================
    1. THE GLASS HOUSES (Secure Providers, Unsigned Routes)
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Signed%  | Name
    -----------------------------------------------------------------------------------------------
    AS3356   | US | 65297    |   5.0%  | Unknown
    AS174    | US | 64638    |   9.6%  | Unknown
    AS3216   | RU | 36753    |   0.2%  | Unknown
    AS33891  | XX | 33990    |   0.0%  | Unknown
    AS29632  | XX | 23700    |   0.0%  | Unknown
    AS48185  | BE | 22590    |   0.0%  | Unknown
    AS16735  | BR | 2405     |   0.0%  | Unknown
    AS1764   | AT | 1814     |   5.7%  | Unknown
    AS14840  | BR | 1583     |   0.0%  | Unknown
    AS53062  | BR | 1537     |   4.1%  | Unknown
    AS46887  | US | 1358     |   0.4%  | Unknown
    AS4766   | KR | 1002     |   3.6%  | Unknown
    AS201054 | PL | 893      |   0.0%  | Unknown
    AS61832  | BR | 661      |   0.0%  | Unknown
    AS61568  | BR | 643      |   0.0%  | Unknown

    ===============================================================================================
    2. SCREAMING INTO THE VOID (Fully Signed, Vulnerable Upstreams)
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Signed%  | Name
    -----------------------------------------------------------------------------------------------
    AS45820  | IN | 315      |  98.7%  | Unknown
    AS17762  | IN | 123      |  99.4%  | Unknown
    AS45117  | IN | 113      | 100.0%  | Unknown
    AS135718 | IN | 44       | 100.0%  | Unknown
    AS141731 | BD | 42       | 100.0%  | Unknown
    AS212330 | IQ | 41       | 100.0%  | Unknown
    AS23688  | BD | 39       |  99.6%  | Unknown
    AS149765 | BD | 36       | 100.0%  | Unknown
    AS15836  | MD | 34       | 100.0%  | Unknown
    AS24323  | BD | 34       |  99.0%  | Unknown
    AS4007   | NP | 32       | 100.0%  | Unknown
    AS9230   | BD | 26       | 100.0%  | Unknown
    AS24631  | IR | 26       | 100.0%  | Unknown
    AS11556  | PA | 25       | 100.0%  | Unknown
    AS401753 | VG | 24       | 100.0%  | Unknown

    ===============================================================================================
    3. WEIGHTED EVANGELISM TARGETS
       Metric = (Provider Cone Size) * (Count of Unsigned Customers)
       Highlighting massive providers with dirty customer bases.
    -----------------------------------------------------------------------------------------------
    ASN      | CC | Cone     | Unsigned | Impact Score   | Name
    -----------------------------------------------------------------------------------------------
        (Calculating weighted metrics for 632 providers...)
    AS6939   | US | 67852    | 32543    | 2,208,107,636  | Unknown
    AS3356   | US | 65297    | 32630    | 2,130,641,110  | Unknown
    AS174    | US | 64638    | 30441    | 1,967,645,358  | Unknown
    AS1299   | SE | 47379    | 30578    | 1,448,755,062  | Unknown
    AS24482  | SG | 65092    | 18500    | 1,204,202,000  | Unknown
    AS6461   | US | 42904    | 25251    | 1,083,368,904  | Unknown
    AS9002   | GB | 44443    | 22312    | 991,612,216    | Unknown
    AS3257   | US | 30050    | 27222    | 818,021,100    | Unknown
    AS2914   | US | 28424    | 25992    | 738,796,608    | Unknown
    AS3216   | RU | 36753    | 17492    | 642,883,476    | Unknown
    AS33891  | XX | 33990    | 18400    | 625,416,000    | Unknown
    AS20485  | RU | 26480    | 17493    | 463,214,640    | Unknown
    AS4826   | AU | 11923    | 21674    | 258,419,102    | Unknown
    AS6762   | IT | 10733    | 23560    | 252,869,480    | Unknown
    AS6453   | US | 8342     | 25337    | 211,361,254    | Unknown
    AS12389  | RU | 11213    | 17493    | 196,149,009    | Unknown
    AS35280  | FR | 51600    | 3695     | 190,662,000    | Unknown
    AS3491   | US | 8358     | 22559    | 188,548,122    | Unknown
    AS9498   | IN | 7889     | 19698    | 155,397,522    | Unknown
    AS13335  | US | 18059    | 7621     | 137,627,639    | Unknown
    AS701    | US | 4205     | 24226    | 101,870,330    | Unknown
    AS4637   | HK | 4588     | 22200    | 101,853,600    | Unknown
    AS7018   | US | 5172     | 19636    | 101,557,392    | Unknown
    AS7713   | ID | 5632     | 17493    | 98,520,576     | Unknown
    AS3320   | DE | 4464     | 21151    | 94,418,064     | Unknown

    [+] Saved strategy to roa_strategy_weighted.csv
