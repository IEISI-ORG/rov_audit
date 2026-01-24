    [*] Loading Global Audit for PT...

    ====================================================================================================
     NATIONAL ROUTING SECURITY: PT
    ====================================================================================================
    Total Networks:      161
    Total Cone Gravity:  169
    ------------------------------------------------------------
    SECURE NETWORKS:        72 (44.7%) -> Protects 63.3% of Traffic
    VULNERABLE NETWORKS:    50 (31.1%) -> Exposes  1.8% of Traffic

    ====================================================================================================
     THE PT CORE (Top 20 Networks)
    ====================================================================================================
    ASN      | Verdict                        | Cone     | APNIC% | Name
    ----------------------------------------------------------------------------------------------------
    AS2860   | SECURE (Active Local ROV)      | 41       | 42%    | NOS COMUNICACOES, S.A.
    AS6424   | SECURE (Active Local ROV)      | 38       | 100%   | EDGOO NETWORKS
    AS15525  | Unverified (Transit/Peer?)     | 22       | 3%     | MEO - SERVICOS DE COMUNICACOES E MULTIME
    AS8657   | PARTIAL (Mixed Feeds)          | 20       | -      | MEO International Backbone
    AS9186   | PARTIAL (Mixed Feeds)          | 10       | 0%     | ONITELECOM - INFOCOMUNICACOES, S.A.
    AS12353  | SECURE (Full Coverage)         | 9        | 1%     | Vodafone Portugal - Communicacoes Pessoa
    AS3243   | SECURE (Active Local ROV)      | 6        | 0%     | MEO
    AS29003  | SECURE (Full Coverage)         | 5        | -      | IP TELECOM, SERVICOS DE TELECOMUNICACOES
    AS1930   | SECURE (Active Local ROV)      | 4        | 95%    | Fundacao para a Ciencia e a Tecnologia, 
    AS47787  | PARTIAL (Mixed Feeds)          | 4        | -      | EDGOO NETWORKS UNIPESSOAL LDA
    AS209874 | VULNERABLE (No Coverage)       | 3        | -      | Tech Tide Portugal Unipessoal LDA
    AS24768  | SECURE (Active Local ROV)      | 3        | -      | AlmourolTec, Lda
    AS50293  | PARTIAL (Mixed Feeds)          | 1        | -      | Interfiber Networks LDA
    AS201782 | SECURE (Full Coverage)         | 1        | -      | Make It Simple Consultoria Informatica L
    AS12926  | PARTIAL (Mixed Feeds)          | 1        | -      | AR TELECOM - Acessos e Redes de Telecomu
    AS200454 | PARTIAL (Mixed Feeds)          | 1        | -      | Tomas Oliveira Valente Leite de Castro
    AS199016 | STUB: VULNERABLE               | 0        | -      | VISUALFORMA TECNOLOGIAS DE INFORMACAO, S
    AS199155 | STUB: SECURE (Full Coverage)   | 0        | 99%    | Direcao Geral de Estatisticas da Educaca
    AS199130 | STUB: SECURE (Full Coverage)   | 0        | -      | 4Spiro - Sociedade de Consultoria, LDA
    AS197802 | STUB: VULNERABLE               | 0        | -      | Secretaria-Geral Ministerio da Administr

    ====================================================================================================
     TRANSIT SUPPLY CHAIN (Who provides to PT?)
    ====================================================================================================
    [*] Analyzing Upstream Supply Chain for 161 networks...
        - Analyzed connectivity for 161 networks.
    Rank | Upstream | Dependents | Global Status                  | Name
    ----------------------------------------------------------------------------------------------------
    #1   | AS2860   | 34         | SECURE (Active Local ROV)      | NOS COMUNICACOES, S.A.
    #2   | AS15525  | 20         | Unverified (Transit/Peer?)     | MEO - SERVICOS DE COMUNICACOES E MULTIME
    #3   | AS174    | 18         | CORE: PROTECTED                | Cogent Communications, LLC
    #4   | AS12353  | 11         | SECURE (Full Coverage)         | Vodafone Portugal - Communicacoes Pessoa
    #5   | AS6939   | 9          | CORE: PROTECTED                | Hurricane Electric LLC
    #6   | AS6424   | 9          | SECURE (Active Local ROV)      | EDGOO NETWORKS
    #7   | AS8220   | 9          | SECURE (Full Coverage)         | COLT
    #8   | AS1930   | 7          | SECURE (Active Local ROV)      | Fundacao para a Ciencia e a Tecnologia, 
    #9   | AS9186   | 7          | PARTIAL (Mixed Feeds)          | ONITELECOM - INFOCOMUNICACOES, S.A.
    #10  | AS3243   | 7          | SECURE (Active Local ROV)      | MEO
    #11  | AS29003  | 5          | SECURE (Full Coverage)         | IP TELECOM, SERVICOS DE TELECOMUNICACOES
    #12  | AS24768  | 4          | SECURE (Active Local ROV)      | AlmourolTec, Lda
    #13  | AS20473  | 4          | SECURE (Full Coverage)         | The Constant Company, LLC
    #14  | AS2914   | 3          | CORE: PROTECTED                | NTT America, Inc.
    #15  | AS6762   | 3          | CORE: PROTECTED                | Telecom Italia Sparkle (Seabone)
    #16  | AS1299   | 3          | CORE: PROTECTED                | Arelion (fka. Telia Carrier)
    #17  | AS8657   | 3          | PARTIAL (Mixed Feeds)          | MEO International Backbone
    #18  | AS8426   | 3          | SECURE (Active Local ROV)      | Claranet Limited
    #19  | AS6453   | 2          | CORE: PROTECTED                | TATA Communications (America) Inc
    #20  | AS3257   | 2          | CORE: PROTECTED                | GTT Communications Inc.

    ====================================================================================================
     TOP VULNERABLE PT NETWORKS
    ====================================================================================================
    ASN      | Cone     | Feeds  | Name
    --------------------------------------------------------------------------------
    AS209874 | 3        | 2/2    | Tech Tide Portugal Unipessoal LDA
    AS199016 | 0        | 2/2    | VISUALFORMA TECNOLOGIAS DE INFORMACAO, SA
    AS197802 | 0        | 1/1    | Secretaria-Geral Ministerio da Administracao Inter
    AS205378 | 0        | 2/3    | Yellow Dinosaur, Unip Lda
    AS205558 | 0        | 1/1    | Autoridade Nacional de Comunicacoes (Anacom)
    AS204094 | 0        | 2/5    | I4W - Web Solutions, Lda
    AS207118 | 0        | 1/1    | Diogo Castro
    AS200952 | 0        | 1/1    | Samuel Barata
    AS201170 | 0        | 1/2    | ANA - Aeroportos de Portugal, SA
    AS200706 | 0        | 1/3    | AXIANSEU - DIGITAL SOLUTIONS, S.A.
    AS201449 | 0        | 1/1    | Digital Absolut Business - Servidor, Virtualizacao
    AS199993 | 0        | 1/1    | Associacao DNS.PT
    AS202904 | 0        | 1/2    | Softman S.A.
    AS203529 | 0        | 1/1    | GETUPLINK - SYSTEM AND NETWORK SOLUTIONS, LDA
    AS203482 | 0        | 1/1    | Policia Judiciaria
