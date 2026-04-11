    [*] Loading Global Audit for PT...

    ====================================================================================================
     NATIONAL ROUTING SECURITY: PT
    ====================================================================================================
    Total Networks:      162
    Total Cone Gravity:  165
    ------------------------------------------------------------
    SECURE NETWORKS:        63 (38.9%) -> Protects 40.6% of Traffic
    VULNERABLE NETWORKS:    59 (36.4%) -> Exposes  1.2% of Traffic

    ====================================================================================================
     THE PT CORE (Top 20 Networks)
    ====================================================================================================
    ASN      | Verdict                        | Cone     | APNIC% | Name
    ----------------------------------------------------------------------------------------------------
    AS2860   | SECURE (Active Local ROV)      | 41       | 91%    | NOS COMUNICACOES, S.A.
    AS6424   | PARTIAL (Mixed Feeds)          | 36       | -      | EDGOO NETWORKS
    AS15525  | Unverified (Transit/Peer?)     | 22       | 2%     | MEO - SERVICOS DE COMUNICACOES E MULTIME
    AS8657   | PARTIAL (Mixed Feeds)          | 22       | -      | MEO International Backbone
    AS12353  | SECURE (Full Coverage)         | 11       | 98%    | Vodafone Portugal - Communicacoes Pessoa
    AS9186   | PARTIAL (Mixed Feeds)          | 11       | 1%     | ONITELECOM - INFOCOMUNICACOES, S.A.
    AS3243   | SECURE (Active Local ROV)      | 6        | 0%     | MEO
    AS1930   | SECURE (Active Local ROV)      | 4        | 98%    | Fundacao para a Ciencia e a Tecnologia, 
    AS24768  | SECURE (Active Local ROV)      | 3        | -      | AlmourolTec, Lda
    AS47787  | PARTIAL (Mixed Feeds)          | 2        | -      | EDGOO NETWORKS UNIPESSOAL LDA
    AS209874 | VULNERABLE (No Coverage)       | 2        | -      | Tech Tide Portugal Unipessoal LDA
    AS29003  | SECURE (Full Coverage)         | 2        | -      | IP TELECOM, SERVICOS DE TELECOMUNICACOES
    AS201782 | PARTIAL (Mixed Feeds)          | 1        | -      | Make It Simple Consultoria Informatica L
    AS12926  | PARTIAL (Mixed Feeds)          | 1        | 0%     | AR TELECOM - Acessos e Redes de Telecomu
    AS50293  | PARTIAL (Mixed Feeds)          | 1        | -      | Interfiber Networks LDA
    AS199016 | STUB: VULNERABLE               | 0        | -      | VISUALFORMA TECNOLOGIAS DE INFORMACAO, S
    AS199667 | NOT ROUTED                     | 0        | -      | 4Spiro - Sociedade de Consultoria, LDA
    AS199130 | STUB: SECURE (Full Coverage)   | 0        | -      | 4Spiro - Sociedade de Consultoria, LDA
    AS199155 | STUB: SECURE (Full Coverage)   | 0        | 100%   | Direcao Geral de Estatisticas da Educaca
    AS197802 | STUB: VULNERABLE               | 0        | -      | Secretaria-Geral Ministerio da Administr

    ====================================================================================================
     TRANSIT SUPPLY CHAIN (Who provides to PT?)
    ====================================================================================================
    [*] Analyzing Upstream Supply Chain for 162 networks...
        - Analyzed connectivity for 161 networks.
    Rank | Upstream | Dependents | Global Status                  | Name
    ----------------------------------------------------------------------------------------------------
    #1   | AS2860   | 34         | SECURE (Active Local ROV)      | NOS COMUNICACOES, S.A.
    #2   | AS15525  | 20         | Unverified (Transit/Peer?)     | MEO - SERVICOS DE COMUNICACOES E MULTIME
    #3   | AS174    | 18         | CORE: PROTECTED                | Cogent Communications, LLC
    #4   | AS12353  | 11         | SECURE (Full Coverage)         | Vodafone Portugal - Communicacoes Pessoa
    #5   | AS6939   | 9          | CORE: PROTECTED                | Hurricane Electric LLC
    #6   | AS6424   | 9          | PARTIAL (Mixed Feeds)          | EDGOO NETWORKS
    #7   | AS8220   | 9          | SECURE (Active Local ROV)      | COLT
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
    AS209874 | 2        | 3/3    | Tech Tide Portugal Unipessoal LDA
    AS199016 | 0        | 1/1    | VISUALFORMA TECNOLOGIAS DE INFORMACAO, SA
    AS197802 | 0        | 1/1    | Secretaria-Geral Ministerio da Administracao Inter
    AS205558 | 0        | 1/1    | Autoridade Nacional de Comunicacoes (Anacom)
    AS205378 | 0        | 2/2    | Yellow Dinosaur, Unip Lda
    AS204094 | 0        | 2/3    | I4W - Web Solutions, Lda
    AS207118 | 0        | 1/1    | Diogo Castro
    AS201170 | 0        | 1/2    | ANA - Aeroportos de Portugal, SA
    AS201449 | 0        | 1/1    | Digital Absolut Business - Servidor, Virtualizacao
    AS199993 | 0        | 1/1    | Associacao DNS.PT
    AS200706 | 0        | 1/3    | AXIANSEU - DIGITAL SOLUTIONS, S.A.
    AS200454 | 0        | 1/2    | Tomas Oliveira Valente Leite de Castro
    AS202904 | 0        | 1/2    | Softman S.A.
    AS203529 | 0        | 1/1    | GETUPLINK - SYSTEM AND NETWORK SOLUTIONS, LDA
    AS202170 | 0        | 1/2    | DSTELECOM, S.A.
