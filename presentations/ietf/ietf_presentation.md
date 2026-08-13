---
marp: true
theme: default
paginate: true
footer: tcs@ieisi.org | https://github.com/IEISI-ORG/rov_audit | WIP YMMV :)
header: '![IEISI logo](https://www.ieisi.org/images/apac_logo.png)'
backgroundColor: #F8F9FA
color: #333333
style: |
  @import url('https://fonts.googleapis.com/css2?family=Roboto+Flex:opsz,wdth,wght@25..151,100..1000&display=swap');
  header {
    position: absolute;
    top: 15px;
    right: 60px;
    padding: 0;
    height: 50px;
    display: flex;
    align-items: center;
  }
  header img {
    height: 45px;
    width: auto;
  }
  section {
    font-family: 'Roboto Flex', sans-serif;
    font-size: 18px;
    padding: 40px 60px;
    background-color: #F8F9FA;
    color: #333333;
  }
  h1 {
    color: #0F2C59;
    font-size: 2em;
    border-bottom: 2px solid #1A5B8F;
    padding-bottom: 10px;
  }
  h2 {
    color: #0F2C59;
    font-size: 1.4em;
  }
  h3 {
    color: #1A5B8F;
    font-size: 1.1em;
  }
  a { color: #1A5B8F; }
  code {
    background: #e2eaf3;
    color: #0F2C59;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 0.85em;
  }
  pre {
    background: #e2eaf3;
    border: 1px solid #1A5B8F;
    border-radius: 4px;
    padding: 16px;
    font-size: 0.75em;
    color: #333333;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85em;
  }
  th {
    background: #0F2C59;
    color: #ffffff;
    padding: 6px 12px;
    text-align: left;
  }
  td {
    padding: 5px 12px;
    border-bottom: 1px solid #1A5B8F;
  }
  .columns {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 30px;
  }
  .columns3 {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 20px;
  }
  .box {
    background: #ffffff;
    border-top: 4px solid #1A5B8F;
    border-radius: 4px;
    padding: 16px;
    margin: 8px 0;
    box-shadow: 0 4px 6px rgba(0,0,0,0.05);
  }
  .green { color: #1e6b2e; }
  .red { color: #D94838; }
  .yellow { color: #7a5200; }
  .blue { color: #1A5B8F; }
  .muted { color: #4a4a4a; font-size: 0.85em; }
  section.title {
    display: flex;
    flex-direction: column;
    justify-content: center;
    text-align: center;
    background: #0F2C59;
    color: #081832;
  }
  section.title h1 {
    font-size: 2.4em;
    border: none;
    margin-bottom: 10px;
    color: #081832;
  }
  section.title h2 {
    color: rgba(26,91,143,0.90);
    font-size: 1em;
    font-weight: normal;
  }
  section.section-break {
    display: flex;
    flex-direction: column;
    justify-content: center;
    text-align: center;
    background: #0F2C59;
    color: #081832;
  }
  section.section-break h1 {
    font-size: 2.6em;
    border: none;
    color: #081832;
  }
  section.section-break h2 {
    color: rgba(15,44,89,0.90);
    font-weight: normal;
  }
  blockquote {
    border-left: 4px solid #1A5B8F;
    padding-left: 20px;
    color: #4a4a4a;
    font-style: italic;
    margin: 16px 0;
  }
---

<!-- _class: title -->

# Global ROV Audit & Triangulation

## Measuring RPKI Route Origin Validation Adoption
## Through Dependency Graph Analysis

---

**IETF** · March 2026

<span class="muted">A framework to answer not just "Is ROV enabled?" but "Is this network *protected*?"</span>

---

# The Problem: BGP Is Still Mostly Trust-Based

The Border Gateway Protocol underpins all global routing. It was designed for **cooperation**, not adversarial environments.

<div class="columns">
<div>

### What can go wrong

- **Route Hijacking** — attacker announces your prefix, attracts your traffic
- **Route Leaks** — misconfiguration propagates invalid paths at global scale
- **Prefix Interception** — traffic silently redirected through a third country

</div>
<div>

### Real incidents

- **2010**: China Telecom hijacked 15% of global routes for 18 minutes
- **2018**: BGP leak redirected Google traffic through Nigeria, Russia, China
- **2022**: Cloudflare, Amazon, AT&T routes hijacked via RPKI-invalid prefix
- **2024**: Multiple large-scale leaks from South Asia transit networks

</div>
</div>

> BGP security is not an individual property. It is a **collective one**.

---

# RPKI: The Two-Part Solution

<div class="columns">
<div>

### ROA — Route Origin Authorization
*"I claim this prefix"*

- Published in a signed certificate
- Links an ASN to the prefix(es) it is authorized to originate
- Stored in RPKI repositories (RIRs)
- Passive: does nothing by itself

**Think of it as a signed deed of ownership**

</div>
<div>

### ROV — Route Origin Validation
*"I verify what I receive"*

- Routers check incoming BGP announcements against the RPKI
- If a route is **RPKI-Invalid** → drop it
- Must be configured and enforced at each AS
- Active: this is what actually stops attacks

**Think of it as checking that deed at the border**

</div>
</div>

<div class="box">

Both must exist for the system to work. **ROA without ROV** = a signed deed that nobody checks. **ROV without ROA** = a border inspector with no database to query.

</div>

---

# The Question Everyone Gets Wrong

<div class="columns">
<div>

### The naive question
> "Does AS12345 have ROV enabled?"

Simple binary. Most existing tools stop here.

**Problems:**
- Doesn't account for inheritance
- Ignores upstream topology
- Misses "clean pipe" protection
- Can't distinguish active vs passive protection

</div>
<div>

### The right question
> "Is AS12345 *protected* from invalid route propagation — and how?"

Requires dependency graph analysis.

**Protection sources:**
- **Active**: AS filters invalids itself
- **Passive**: upstream provider filters on its behalf
- **Partial**: some upstreams filter, some don't
- **None**: invalid routes flow freely

</div>
</div>

---
<!-- _class: section-break -->

# Philosophy
## Herd Immunity for the Internet

---

# Herd Immunity: The Core Concept

> Just as epidemic disease can be suppressed when enough individuals are immune, **BGP hijacks can be suppressed when enough transit networks enforce ROV**.

<div class="columns">
<div>

### How it applies to BGP

The internet has a power-law structure. A small number of **Tier 1 and large transit networks** carry a disproportionate share of global traffic.

If *those* networks enforce ROV, the invalid routes they drop **never reach the billions of end-users** downstream — regardless of those users' own AS configuration.

</div>
<div>

### The cone model

Every network has a **customer cone**: the set of all ASes reachable downstream through it.

```
Tier 1 (cone = 70,000)
  └─ Regional ISP (cone = 500)
       └─ Local ISP (cone = 20)
            └─ Enterprise (cone = 1)
```

ROV at the Tier 1 protects *everyone* in its cone — ~70,001 networks.

</div>
</div>

---

# What This Tool Measures

<div class="columns">
<div>

### Traditional approach
Check if a network has ROV enabled. List networks. Count them.

Result: "X% of networks have ROV."

**Misleading** — a small stub AS and a Tier 1 backbone count equally.

</div>
<div>

### Our approach
Weight by **customer cone size** (downstream reach). Trace the dependency graph for every network.

Result: "X% of global routable traffic flows through networks that will drop RPKI-invalid routes."

**Meaningful** — weighted by actual internet impact.

</div>
</div>

<div class="box">

We also identify:
- Networks that are protected **passively** (clean pipe) even without local ROV
- Networks that protect others but **don't protect themselves** (Glass Houses)
- Networks doing everything right but whose effort is **nullified by their upstream** (Screaming Into the Void)

</div>

---
<!-- _class: section-break -->

# Architecture
## How the Tool Works

---

# System Overview: Four Phases

```
┌─────────────────────────────────────────────────────────────────────┐
│  Phase 1                Phase 2               Phase 3         Phase 4│
│  BGP Topology  ──────►  Data Hydration  ───►  Audit   ──────► Reports│
│  (Go)                   (Python)               (Python)       (Python)│
└─────────────────────────────────────────────────────────────────────┘
        │                      │                    │               │
  400MB MRT dump         6 data sources       Verdict logic    30+ reports
  Valley-free logic      Zero-scrape arch     120k ASNs         Country deep dives
  Cone calculation       Per-AS JSON cache    Dependency walk   Herd immunity calc
```

**Data sources used:**

| Source | Data |
|--------|------|
| RIPE RIS (MRT dumps) | Raw BGP routing tables — provider/customer relationships |
| APNIC Labs | ROA signing percentage per ASN |
| BGP.Tools | ASN names, ROV status tags |
| Cloudflare IsBGPSafeYet | Known-secure operators |
| IPtoASN | Geolocation (country codes) |
| RIPE Atlas | Active forensic probe results |

---

# Phase 1: Building the Internet's Topology Map

<div class="columns">
<div>

### Input
RIPE RIS `latest-bview.gz` (~400MB)
MRT binary format BGP table dump

### Process (Go)
1. Parse all BGP AS-PATH sequences
2. De-prepend repeated ASNs
3. Classify each hop as provider→customer or peer→peer using **Valley-Free** (Gao-Rexford) logic
4. Build `relationships.csv`
5. Run transitive closure → **customer cone sizes**

</div>
<div>

### Valley-Free Routing Logic

```
RULE: A packet can travel UP to a provider,
      ACROSS to a peer, and DOWN to a customer.
      It cannot go UP again after going DOWN.

  Tier1 ──── Tier1          ← peering
    │
  Transit                   ← provider→customer
    │
  Regional                  ← provider→customer
    │
  Stub                      ← customer (leaf)
```

Any path violating this model indicates a route leak or misconfiguration.

</div>
</div>

<div class="muted">Output: final_as_rank.csv — 70,000+ ASNs ranked by customer cone size</div>

---

# Phase 2: Data Triangulation — Zero-Scrape Architecture

We hydrate the topology with security metadata from **six independent sources**.

<div class="columns">

<div>

### What we fetch

- **ASN Name** (BGP.Tools CSV bulk)
- **Country Code** (IPtoASN, triple-validated)
- **ROV Status** (BGP.Tools tags + Cloudflare)
- **ROA Signing %** (APNIC Labs JSON API)
- **Tier 1 classification** (curated list of 27 known backbone providers)
- **Upstream provider list** (from Phase 1 relationships)

</div>

<div>

### Per-ASN JSON cache

```json
{
  "asn": 10000,
  "name": "Example ISP",
  "is_tier1": false,
  "cone_size": 142,
  "upstreams": [3356, 1299, 6939],
  "cc": "US",
  "roa_signed_pct": 78.3,
  "roa_stats": {
    "valid": 47,
    "total": 60
  }
}
```

~120,000 files, one per ASN

</div>
</div>

<div class="muted">Design principle: no scraping, no web parsing — only bulk APIs, published datasets, and structured endpoints.</div>

---

# Phase 3: The Audit — Verdict Logic

Each network is classified by walking its **upstream dependency graph**.

```
for each AS in database:
    if is_tier1:
        verdict = CORE:PROTECTED or CORE:UNPROTECTED  (based on ROV status)
    else:
        secure_feeds = count(upstreams where verdict == PROTECTED)
        total_feeds  = count(upstreams)

        if secure_feeds == total_feeds:   → SECURE (Full Coverage)
        if secure_feeds == 0:             → VULNERABLE (No Coverage)
        if 0 < secure_feeds < total_feeds:→ PARTIAL (Mixed Feeds)

        if cone_size < threshold:
            prefix verdict with STUB:
```

<div class="columns">
<div>

### Key insight
Protection is **transitive**. A network is secure if *all* paths to the DFZ pass through an ROV-enforcing router — regardless of where in the path that enforcement happens.

</div>
<div>

### Key caveat
Partial is dangerous. A network with 3 upstream providers — 2 secure, 1 leaking — is effectively vulnerable, because attackers will always exploit the leaking path.

</div>
</div>

---

# The Verdict Taxonomy

| Verdict | Meaning | Count | Traffic Impact |
|---------|---------|-------|---------------|
| **CORE: PROTECTED** | Tier 1 with ROV enforced | 22 | **25.9%** |
| CORE: UNPROTECTED | Tier 1 without ROV | 5 | ~0% |
| **SECURE (Full Coverage)** | All upstreams are secure | 1,179 | **52.1%** |
| **SECURE (Active Local ROV)** | Filters invalids locally | 678 | **3.5%** |
| PARTIAL (Mixed Feeds) | Some upstreams vulnerable | 3,989 | 6.1% |
| VULNERABLE (No Coverage) | Upstream accepts invalids | 55,859 | 0.3% |
| NOT ROUTED | No prefixes announced | 36,986 | — |
| Unverified (Transit/Peer?) | Unknown — needs forensics | 187 | 12.1% |

<div class="box">

**Total networks in database: 120,444**
<span class="green">Fully Protected: 23,949 (19.9%)</span> · <span class="yellow">Partially Protected: 3,989 (3.3%)</span> · <span class="red">Vulnerable: 55,338 (45.9%)</span>

</div>

---

# Phase 4: Analysis Reports

From the master audit CSV, we generate targeted analytical reports:

<div class="columns3">

<div class="box">

**Herd Immunity**
What % of global traffic flows through ROV-enforcing networks?
Weighted by customer cone size.

</div>

<div class="box">

**ROV Quadrant Analysis**
2×2 matrix: who filters vs. who signs. Identifies system failures.

</div>

<div class="box">

**ROA Signing Hygiene**
Glass Houses: networks that filter others but don't sign their own routes.

</div>

<div class="box">

**Country Deep Dives**
Per-nation security posture, critical ISPs, and regional recommendations.
30+ countries covered.

</div>

<div class="box">

**ASPA Readiness**
Estimates transition cost and benefits of ASPA adoption across transit networks.

</div>

<div class="box">

**Forensic Verification**
RIPE Atlas active probes to confirm or deny ROV enforcement in "Unverified" large networks.

</div>

</div>

---
<!-- _class: section-break -->

# Findings
## What the Data Shows

---

# The Core: 27 Tier 1 Networks

These 27 networks are the backbone of the global internet. Their combined customer cones span virtually every routable AS on earth.

<div class="columns">
<div>

### Status as of March 2026

```
CORE: PROTECTED  (22 networks)
 ✓ AS6939   Hurricane Electric
 ✓ AS1299   Arelion (Telia Carrier)
 ✓ AS3356   Lumen (Level 3)
 ✓ AS174    Cogent Communications
 ✓ AS6461   Zayo Bandwidth
 ✓ AS9002   RETN Limited
 ...and 16 more

CORE: UNPROTECTED (5 networks)
 ✗ AS4134   China Telecom Backbone
 ✗ AS4837   China Unicom Backbone
 ✗ AS9808   China Mobile Backbone
 ✗ AS2828   Verizon Business
 ✗ AS9929   China Unicom Industrial
```

</div>
<div>

### Why this matters

The 5 unprotected Tier 1 networks collectively provide transit to hundreds of millions of end-users.

An invalid route announced against a network they transit will propagate globally — because there is no ROV enforcement at the last backstop.

**22/27 Tier 1s protected = 81% of the Core secured.**

The 5 holdouts represent disproportionate geopolitical risk — concentrated in China (4 networks) and US (Verizon Business).

</div>
</div>

---

# Herd Immunity: Current Status

<div class="columns">
<div>

### Top 100 largest networks

```
Networks with ROV: 86 / 100  (86.0%)
Traffic protected: 85.3%

████████████████████████████████████░░░░░░
```

### Top 1,000 transit networks

```
Networks with ROV: 489 / 1000  (48.9%)
Traffic protected: 82.5%

█████████████████████████████████████░░░░░
```

</div>
<div>

### Interpretation

**The herd immunity threshold is approximately 80% of traffic.**

We are at **82.5%** by transit weight. The core of the internet has, in practical terms, **achieved herd immunity** for well-originated routes.

However, this is not uniformly distributed:
- Strong in Europe, North America, Oceania
- Significant gaps in South/Southeast Asia
- Structural gaps in China (Tier 1 holdouts)

</div>
</div>

> CONCLUSION: The core is essentially safe. The tail risk is concentrated in specific geographic regions and specific large networks.

---

# The High-Impact Holdouts

If these networks enabled ROV, global protection would jump meaningfully.

| Rank | ASN | CC | Cone | Network |
|------|-----|----|------|---------|
| #154 | AS4134 | CN | 387 | China Telecom Backbone |
| #177 | AS45820 | IN | 319 | Tata Teleservices ISP |
| #217 | AS9730 | IN | 234 | Bharti Telesonic Ltd |
| #342 | AS17762 | IN | 129 | Tata Teleservices Maharashtra Ltd |
| #364 | AS4837 | CN | 111 | China Unicom Backbone |
| #377 | AS33132 | US | 104 | Crown Castle Fiber LLC |
| #414 | AS12357 | ES | 92 | Vodafone España S.A.U. |
| #507 | AS9808 | CN | 69 | China Mobile Backbone |
| #828 | AS5384 | AE | 33 | Emirates Telecommunications |

<div class="muted">

India (IN) also appears 4× in the top holdouts. South Asia is the primary geographic gap in global ROV adoption after China.

</div>

---

# The ROV Quadrant Analysis

A 2×2 matrix reveals four structural failure modes in the system:

<div class="columns">
<div>

### Q1: Gold Standard ✓
*Provider filters invalids AND customers sign ROAs*

```
AS6939  Hurricane Electric      60.1% signing
AS1299  Arelion (Telia)         65.8% signing
AS9002  RETN Limited            67.7% signing
```
System working as intended.

### Q3: Glass Houses ⚠
*Provider filters, but own routes unsigned*

```
AS3356  Lumen (Level 3)         5.0% signing
AS174   Cogent Communications   9.6% signing
AS3216  Vimpelcom               0.2% signing
```
They protect others. They are unprotected.

</div>
<div>

### Q2: Screaming Into the Void ⚠
*Customers signed ROAs, but provider leaks*

```
AS24482  SG.GS (Singapore)      74.0% signing
AS37721  VTS (Burkina Faso)     66.6% signing
```
Customers did their homework. Provider negated it.

### Q4: The Swamp ✗
*Vulnerable provider AND unsigned customers*

```
AS38255  CERNET (China)          0.0% signing
AS9930   TIME dotCom (Malaysia) 52.8% signing
```
Complete failure on both axes.

</div>
</div>

---

# Glass Houses: The Asymmetry Problem

<div class="columns">
<div>

**Networks filtering invalids but not signing their own routes:**

| ASN | Cone | ROA Signed |
|-----|------|-----------|
| AS3356 Lumen | 65,326 | 5.0% |
| AS174 Cogent | 64,687 | 9.6% |
| AS3216 Vimpelcom | 38,066 | 0.2% |
| AS33891 Core-Backbone | 33,466 | 0.0% |
| AS4766 Korea Telecom | 1,045 | 3.6% |

</div>
<div>

### Why this is a problem

If Lumen (AS3356) were hijacked, the attacker would propagate routes to **65,326 downstream networks**.

Lumen's own ROV filters would detect the hijack — but the hijack is *of Lumen's own routes*, so there is nothing to filter. The attack succeeds against the very network doing the filtering.

**ROV enforcer ≠ ROA signer. You need both.**

</div>
</div>

<div class="box">

**Global ROA signing status:**
<span class="green">Fully signed (>90%): 38,901 networks (32.3%)</span> · <span class="yellow">Partially signed: 7,810 (6.5%)</span> · <span class="red">Unsigned: 73,733 (61.2%)</span>

</div>

---

# Screaming Into the Void

<div class="columns">
<div>

Networks that have done everything right — 100% ROA signing — but whose upstream provider does not enforce ROV:

| ASN | CC | Cone | Provider feeds leaking |
|-----|----|----|----------------------|
| AS45820 Tata Teleservices | IN | 319 | 1/1 |
| AS17762 Tata Maharashtra | IN | 129 | 2/2 |
| AS23688 Link3 Technologies | BD | 44 | 1/1 |
| AS141731 Max Hub | BD | 41 | 3/3 |
| AS4007 Subisu Cablenet | NP | 32 | 1/1 |

</div>
<div>

### The ROA signing tragedy

These networks published signed ROA records. Their routes are verifiable. Their prefixes can be validated by any ROV-capable router.

But their upstream provider does not perform that validation. Any invalid announcement against them will be accepted and propagated upstream — the ROA signatures are ignored.

**ROA without upstream ROV is security theater.**

The problem is not with these networks. It is with their transit providers.

</div>
</div>

---

# Country-Level Analysis: South Asia Focus

The most significant regional gap. India and Bangladesh dominate the holdout list.

<div class="columns">
<div>

### India
- Largest holdouts: Tata Teleservices, Bharti Telesonic
- Major transit networks without ROV serve ~500+ downstream ASNs
- Economic consolidation means a small number of large ISPs control most routes
- **Policy lever**: TRAI could mandate ROV for licensed telecom operators

### Bangladesh
- 4 networks appear in "Screaming Into the Void" list
- Link3 Technologies (AS23688, cone 44) is fully signed but upstream leaks
- Rapid growth of ISP sector without routing security requirements

</div>
<div>

### Nepal
- Subisu Cablenet (AS4007) — fully signed, upstream leaks
- Nepal Telecom (Tier 2) is partially signed
- Small market; depends almost entirely on Indian transit — inherits India's gaps

### China (structural)
- 4 of 5 unprotected Tier 1 networks are Chinese operators
- Unique position: state-controlled networks
- Resolution likely requires regulatory/government-level engagement, not technical persuasion

</div>
</div>

---

# Active Forensics: RIPE Atlas Verification

Some large networks appear as "Unverified" — they have ROV tags in BGP.Tools but no confirmed data.

<div class="columns">
<div>

### The method

1. Identify target ASN with "Unverified" status
2. Find a RIPE Atlas probe inside that AS
3. Announce a **crafted RPKI-Invalid test prefix**
4. Run traceroutes from that probe to a controlled endpoint
5. Compare path for **Valid** vs **Invalid** prefix

If the Invalid trace drops at the network boundary → **ROV confirmed**.
If both traces reach the same endpoint → **leaking confirmed**.

</div>
<div>

### What this produces

```python
# verify_forensic_path_v2.py output:
Target ASN: AS12345
Probe: #987654 (inside AS12345)

Valid prefix trace:
  1. 10.x.x.x  (internal)
  2. 203.x.x.x (upstream)
  3. DESTINATION REACHED ✓

Invalid prefix trace:
  1. 10.x.x.x  (internal)
  2. REQUEST TIMED OUT
  ← route dropped at AS12345 border

VERDICT: ROV CONFIRMED. Reclassifying as SECURE.
```

</div>
</div>

<div class="muted">Results are fed back into the main audit, improving classification accuracy for large "Unverified" networks (combined cone ~12% of global traffic).</div>

---
<!-- _class: section-break -->

# The Stack
## Technical Implementation

---

# Technology Choices

<div class="columns">
<div>

### Go — BGP Processing

The raw MRT dump is 400MB of binary data. Processing it in Python would take 20+ minutes.

Go processes it in **under 60 seconds** using concurrent goroutines for path parsing and valley-free classification.

```go
// Concurrent MRT processing
func processPaths(paths []BGPPath) {
    sem := make(chan struct{}, workers)
    for _, path := range paths {
        sem <- struct{}{}
        go func(p BGPPath) {
            defer func() { <-sem }()
            classifyRelationships(p)
        }(path)
    }
}
```

</div>
<div>

### Python — Analysis & Reporting

All analysis, data triangulation, and report generation is in Python.

- `pandas` for CSV manipulation across 120k rows
- `asyncio` + `aiohttp` for parallel ROA stat fetching
- `ripe.atlas.cousteau` for forensic probe coordination

### Zero-Scrape Architecture

No HTML parsing. No browser automation. Every data source used is:
- A bulk-downloadable CSV or compressed TSV
- A documented JSON API
- A structured public dataset

This makes the tool **reproducible and respectful** of data providers.

</div>
</div>

---

# Data Pipeline: End to End

```
RIPE RIS                BGP.Tools             APNIC Labs
latest-bview.gz         rov.csv               rpki-history/
(400MB MRT)             (ASN names/tags)      (ROA signing %)
     │                       │                      │
     ▼                       │                      │
bgp-extractor (Go)           │                      │
  - Parse AS-PATHs           │                      │
  - Valley-free classify     │                      │
  - Output relationships.csv │                      │
     │                       │                      │
     ▼                       ▼                      ▼
cone-calculator (Go)    rov_no_scrape_v20.py (Python)
  - Transitive closure       - Fetch all metadata
  - Customer cone sizes      - Build data/parsed/as_*.json
  - final_as_rank.csv        - 120,000 per-ASN JSON files
          │                       │
          └───────────────────────┘
                          │
                          ▼
               rov_global_audit_v20.py
                  - Walk dependency graph
                  - Assign verdicts
                  - rov_audit_v20_final.csv
                          │
              ┌───────────┼──────────────┐
              ▼           ▼              ▼
      herd_immunity   quadrant_v3   country_deep_dive
      .py             .py           .py [CC]
```

---
<!-- _class: section-break -->

# What This Means
## Implications & Next Steps

---

# Summary: The State of Internet Routing Security

<div class="columns">
<div>

### The good news

- **86% of the top 100 networks** have ROV enabled
- **82.5% of transit-weighted traffic** passes through ROV-enforcing nodes
- Herd immunity threshold (~80%) has been **crossed** for well-originated routes
- ROA signing growing: 32% of networks now >90% signed

</div>
<div>

### The remaining problems

1. **5 Tier 1 networks** still do not enforce ROV — 4 are Chinese state carriers
2. **South Asia** (India, Bangladesh) has the largest holdout clusters
3. **Glass Houses** — large networks protect others but don't sign their own routes
4. **Partial protection** (3,989 networks) is nearly as bad as no protection for attackers who can exploit leaking upstreams
5. **187 large networks** remain forensically unverified (~12% of traffic impact)

</div>
</div>

---

# Recommendations

<div class="columns">
<div>

### For network operators

1. **Enable ROV** — use RIPE's RPKI Validator or RIPEstat to check your status
2. **Sign your own routes with ROA** — even if you already filter invalids
3. **Require ROV from customers** — make it a peering/transit requirement
4. **Check your upstreams** — if they leak, your ROA signing is wasted

### For IXPs and transit providers

- Make ROV a **peering policy requirement**
- Publish your ROV status in PeeringDB
- Prefer customers/peers with ROA signing

</div>
<div>

### For regulators and policy makers

- **South Asia**: TRAI (India), BTRC (Bangladesh) should consider ROV mandates for licensed telecom operators
- **China**: Engagement with MIIT on Tier 1 ROV adoption is the highest-leverage intervention globally
- **RIPE NCC**: Consider making ROA signing a requirement for IP space allocation renewal

### For the IETF community

- Continued work on **ASPA** (AS Provider Authorization) to extend protection from origin to path
- Better tooling for **partial protection analysis** — the binary "secure/vulnerable" framing is insufficient

</div>
</div>

---

# ASPA: The Next Layer

Current RPKI/ROV protects against **origin hijacks** only.

**ASPA (AS Provider Authorization)** extends this to **path hijacks** — route leaks where the origin is legitimate but the path is not.

<div class="columns">
<div>

### What ASPA adds

Each AS publishes a signed record of its legitimate upstream providers.

```
AS12345 authorizes providers:
  - AS3356 (Lumen)
  - AS1299 (Arelion)
```

Routers can then validate that the full AS-PATH in a BGP announcement is consistent with published provider relationships — not just the origin.

</div>
<div>

### ASPA readiness (from our analysis)

The valley-free relationship data we already collect is **exactly the data ASPA would use**.

Our `relationships.csv` and cone calculations are structurally compatible with ASPA's provider authorization model.

Estimated transition coverage if top 1,000 transit networks adopted ASPA: **~71% of global transit** would have path-level validation.

</div>
</div>

<div class="muted">Full analysis: reports/analyze_aspa_realistic.md</div>

---

# Data Availability & Reproducibility

<div class="columns">
<div>

### Open source

- Full codebase on GitHub: `IEISI-ORG/rov_audit`
- Licensed under **CC BY-NC 4.0**
- Free to use for research, education, and non-commercial analysis
- Pull requests welcome

### Reproducibility

The entire pipeline runs on public data. No proprietary sources, no scraping, no API keys required for the core audit.

```bash
# Full pipeline, one command:
make all

# Or step by step:
make topology
make metadata
make audit
make reports
```

</div>
<div>

### Cite as

> **"Global ROV Audit & Triangulation Tool"**
> *A framework for measuring Internet Routing Security via Dependency Analysis.*
> IEISI-ORG, 2026.
> `github.com/IEISI-ORG/rov_audit`

### Data freshness

- BGP table: updated daily (RIPE RIS publishes every 8 hours)
- APNIC ROA stats: updated weekly
- Full audit run: ~2 hours on commodity hardware

Reports in this presentation reflect data from **March 2026**.

</div>
</div>

---
<!-- _class: title -->

# Thank You

## Global ROV Audit & Triangulation Tool

---

**Questions welcome.**

<div class="columns">

<div>

### Key numbers to remember

- **120,444** networks audited
- **82.5%** of transit-weighted traffic protected
- **86/100** top networks have ROV
- **5** Tier 1 networks still holdouts
- **3 of them** are Chinese state carriers

</div>

<div>

### Resources

- Code + data: `github.com/IEISI-ORG/rov_audit`
- License: CC BY-NC 4.0
- Reports: 30+ country deep-dives, all public

---

*"The internet's security is a collective property. No network is an island."*

</div>
</div>
