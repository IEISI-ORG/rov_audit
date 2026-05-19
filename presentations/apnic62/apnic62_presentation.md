---
marp: true
theme: apnic62
paginate: true
footer: APNIC-62 · Mumbai, India · September 2026 · Terry Sweetser · IEISI
backgroundColor: "#ffffff"
color: "#1a1a2e"
---

<!-- _class: title-slide -->

# Global ROV Audit & Triangulation
### Measuring Internet Routing Security and "Herd Immunity"

**Presenter:** Terry Sweetser
**Organization:** IEISI
**Conference:** APNIC-62 · Mumbai, India · September 2026

---

# Agenda

1. **Why Measurement Matters** — BGP security is not binary
2. **Methodology** — Zero-scrape triangulation at scale
3. **Global Results** — 121,363 ASNs audited
4. **Herd Immunity** — Where does protection actually come from?
5. **ROA Signing** — Glass Houses and wasted infrastructure
6. **APNIC Region Deep-Dive** — AU, NZ, JP, IN, ID, CN
7. **ASPA Readiness** — The next layer and the Reality Gap
8. **Recommendations** — Concrete actions by audience

---

<!-- _class: section-divider -->

# Part I: The Problem

Why "Is BGP secure?" is the wrong question

---

# The Measurement Problem

BGP security deployment has **three distinct layers** — each independently measurable, each independently breakable.

| Layer | Question | Standard |
|---|---|---|
| **ROA** | Have you *claimed* your prefixes? | RPKI ROA signing |
| **ROV** | Are you *filtering* invalid routes? | BGP origin validation |
| **ASPA** | Are you *validating* the path? | AS_PATH verification |

> **A network that enforces ROV but has not signed its own ROAs is a Glass House** — filtering for others while its own prefixes remain unprotected.
> A network that signs ROAs but skips ROV claims security it cannot deliver.

The real question: **"What percentage of global traffic is actually protected right now, and by whom?"**

---

# The Three Failure Modes

We observe three structural pathologies in the current internet:

**🏚 Glass Houses** — "I filter, but I haven't signed"
Providers enforce ROV, but their own prefixes are *NotFound* to ROV — unsigned, unprotected. ROV drops *Invalid* routes (mismatched ROA); it passes *NotFound* routes silently. A hijacker targeting unsigned space gets a free pass at every ROV enforcer.

**📢 Screaming Into The Void** — "I signed, but my provider leaks"
Networks with exemplary ROA hygiene (>97% signed) whose upstreams are confirmed non-ROV. Their diligence is negated at the transit layer.

**🌵 Wild West / SITV (Screaming Into The Void)** — "Neither signed, nor filtering"
The majority position: no ROA, no ROV. These networks are both vulnerable and a source of routing pollution for their peers.

---

<!-- _class: section-divider -->

# Part II: Methodology

Zero-scrape triangulation at scale

---

# Zero-Scrape Architecture

**No web scraping. Only structured API data and BGP table dumps.**

```
RIPE RIS MRT Dumps (5 global collectors)
    ↓ Go MRT Parser (bgp-extractor)
    ↓ Valley-Free Topology Builder
    ↓ Customer Cone Calculator (cone-calculator.go)
                    ↓
         ┌──────────┴──────────┐
  APNIC RPKI API          bgp.tools API
  (242 countries)         (1,282 ROV tags)
  APNIC Timeseries        Cloudflare Safe List
  (9,907 ASNs)            (464 ASNs)
         └──────────┬──────────┘
                    ↓
         RIPE Atlas Forensic Engine
         (7-verdict path taxonomy)
                    ↓
         121,363 ASNs audited
```

All data with 7-day TTL — stale results are discarded, not stacked.

---

# Topology: Valley-Free BGP

**Gao-Rexford Valley-Free constraint** governs all legitimate BGP paths:

```
(customer→provider)* → (peer↔peer)? → (provider→customer)*
```

Once a path descends to a customer, it cannot go back up to a provider.
This means **Tier-1s appear at the peak** — any ASN that appears universally at the center of all paths is definitionally a Tier-1.

### Topology Inference Rules (priority order):
1. Non-transit ASNs (RIRs, IXP route servers) → skip
2. Tier-1 ↔ non-Tier-1 → Tier-1 is *always* the provider
3. Tier-1 ↔ Tier-1 → peering link (no cone relationship)
4. `degree(A) > 4 × degree(B)` → A is provider of B
5. `degree(B) > 4 × degree(A)` → B is provider of A
6. Otherwise → peering link

Confirmed transit links require observation from **≥2 geographically distinct** RIPE RIS collectors (AMS, Palo Alto, Johannesburg, Singapore, Montevideo).

---

# Multi-Collector IXP Phantom Mitigation

**The IXP Phantom Problem:**
Route servers at IXPs (e.g. AMS-IX) strip their own ASN from AS-paths per RFC 7947. A network peering with 500 ASNs at AMS-IX looks like a transit provider with 500 customers — the 4× degree ratio fires, and a phantom cone of 50,000+ appears.

**The Fix — consensus across regions:**

| Link seen in | Ratio threshold | Interpretation |
|---|---|---|
| ≥2 distinct regions | 4× (standard) | Confirmed transit relationship |
| 1 region only | 8× (strict) | Likely IXP peering artefact |

**Result:** 83 IXP phantom networks excluded from herd immunity calculations (e.g. AS7717 OpenIXP Route Servers, ID — cone 174, excl% 32%).

A backstop `cone_quality()` check also filters any non-Tier-1 with <5% captive customers.

---

# RIPE Atlas Forensic Verification

For large transit ASNs, APNIC telemetry is insufficient — it measures *user-visible filtering*, not *local ROV policy*.

**7-probe-level verdicts from dual traceroute to RPKI-valid/invalid beacons:**

| Verdict | Meaning |
|---|---|
| `SECURE (Target Filtered)` | Target is the drop boundary — **confirmed ROV** |
| `SECURE (Upstream Filtered)` | Target forwarded invalid; upstream caught it — **NOT doing ROV** |
| `SECURE (Pre-Target Filtered)` | Filtered before target — inconclusive |
| `VULNERABLE` | Target in path_i AND invalid reachable — **confirmed non-ROV** |
| `VULNERABLE (Bypass Route)` | Invalid reachable, path avoided target — network leaks |
| `INCONCLUSIVE (Off-Path)` | Probe routed around target — probe discarded |
| `INCONCLUSIVE (Probe Down)` | Valid unreachable — probe discarded |

> **Key insight:** `SECURE (Upstream Filtered)` counts as **non-ROV** for the target — the target forwarded the invalid prefix. The upstream saved it, but the target is not filtering.

---

# APNIC Data Quality: Adaptive Window Selection

APNIC's ROV measurement API returns rolling windows: 7, 14, 28, 112 days.

**The 7-day problem:** A sparse network (e.g. Telstra International AS4637) may have `seen=2, filtered=4` in the 7-day window → 6 total samples → a 33% "rate" that is pure noise.

**Our fix — adaptive window selection:**
- Pick the shortest window where `seen + filtered ≥ 30`
- Fall back 7→14→28→112 days
- If no window meets threshold → store as `[None, 0]`, exclude from all statistics
- Regression detection uses `n ≥ 100` samples (stricter) to avoid noise triggering REGRESSED status

**Regression lookback = 1 year**, not all-time. Early 2019–2020 APNIC measurement spikes would falsely flag stable networks (AT&T's stable 55–58% had an all-time spike to 100% from measurement noise).

---

<!-- _class: section-divider -->

# Part III: Global Results

121,363 ASNs · May 2026

---

# Global Verdict Breakdown

**121,363 ASNs audited across 242 countries.**

| Verdict | ASNs | % | Avg Cone | Traffic Impact |
|---|---|---|---|---|
| **CORE: ACTIVE PROTECTOR** | 21 | 0.02% | 63,702 | **52.7%** |
| ACTIVE LOCAL ROV | 170 | 0.14% | 844 | 5.7% |
| PASSIVE (Clean Pipe) | 912 | 0.75% | 298 | 10.7% |
| STUB: PASSIVE | 18,392 | 15.2% | 0 | 0.0% |
| PARTIAL: VULNERABLE | 3,760 | 3.1% | 124 | 18.3% |
| REGRESSED | 940 | 0.8% | 136 | 5.0% |
| STUB: VULNERABLE | 56,786 | 46.8% | 0 | 0.0% |
| CORE: UNPROTECTED | 4 | <0.01% | 28,689 | **4.5%** |

**Overall:** SECURE 20,462 (16.9%) · PARTIAL 3,760 (3.1%) · VULNERABLE 58,961 (48.6%)

> 21 networks protect 52.7% of global traffic. 4 networks expose 4.5%.

---

# The Herd Immunity Scoreboard

```
[GLOBAL CORE] Top 100 legitimate transit networks

  Networks Secure:      58 / 100  (58.0%)
  Traffic Protected:   82.8%  (by Cone Weight)

  ████████████████████████████████████████░░░░░░░░░

[TRANSIT LAYER] Top 1,000 legitimate transit networks

  Networks Secure:     272 / 1,000  (27.2%)
  Traffic Protected:   80.5%  (by Cone Weight)

  ████████████████████████████████████████░░░░░░░░░░
```

**Interpretation:** We are asymptotically close to herd immunity at the traffic level — but not at the network count level. The long tail of vulnerable small transit ASNs represent real exposure for their direct customers.

---

# The Holdouts: Top Vulnerable Transit Networks

*Networks whose ROV deployment would have the highest impact:*

| Rank | ASN | CC | Cone | Excl% | Name |
|---|---|---|---|---|---|
| #15 | AS4134 | CN | 64,579 | 81% | China Telecom Backbone |
| #22 | AS4837 | CN | 47,004 | 67% | China Unicom Backbone |
| #27 | AS20485 | RU | 28,703 | 22% | TransTeleCom JSC |
| #41 | AS9304 | HK | 5,182 | 22% | HGC Global Communications |
| #42 | AS52468 | PA | 4,857 | 50% | UFINET PANAMA |
| #43 | AS8220 | GB | 4,784 | 55% | COLT |
| #51 | AS9808 | CN | 2,629 | 76% | China Mobile Backbone |
| #104 | AS18229 | IN | 458 | 78% | CtrlS |
| #130 | AS45820 | IN | 343 | 69% | Tata Teleservices ISP |

**`Excl%`** = percentage of direct customers with ≤2 total providers — a measure of captive dependence. High excl% means customers *cannot* route around this provider.

---

# The ROV Quadrant Map

| | **Provider: SECURE** | **Provider: VULNERABLE** |
|---|---|---|
| **Customers: Signed (>60%)** | ✅ **Q1: Gold Standard** | 📢 **Q2: Screaming Into The Void** |
| **Customers: Unsigned (<60%)** | 🏚 **Q3: Glass Houses** | 🌵 **Q4: The Swamp** |

**Q1 Gold Standard examples:** Hurricane Electric (cone 68,256), SG.GS (65,410), Arelion (48,082)

**Q2 Screaming Into The Void:** Virtual Technologies & Solutions / BF (cone 58,181, 66.8% signed), F5 Networks SARL / FR (50,969, 66.2% signed)

**Q3 Glass Houses:** Lumen/Level 3 (cone 64,668, only 34.1% signed), Cogent (64,504, 44.7%), Zayo (40,790, 33.4%)

**Q4 The Swamp:** TECHIT.BE SRL (cone 24,556, 0% signed), Rostelecom (10,447, 37.3%)

---

<!-- _class: section-divider -->

# Part IV: ROA Signing

Where is the inventory, and who is wasting it?

---

# Global ROA Signing Status

**Of 121,363 ASNs with active routing:**

```
  Fully Signed (>90%):    43,150   (35.6%)  ██████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
  Partially Signed:        5,900   ( 4.9%)  ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
  Totally Unsigned:       72,313   (59.6%)  ████████████████████████████████░░░░░░░░░░░░░░░░░░
```

**More than half of all routed networks have zero ROA coverage.**

This means ROV-enforcing providers — even those doing everything right — are regularly seeing legitimate-but-unsigned routes from their customers. Enforcing strict invalid-drop is operationally difficult when 60% of customer prefixes are unprotected by a ROA.

ROA signing is the **foundation** of the entire RPKI ecosystem. Without it, ROV is filtering noise; with it, ROV becomes a precision instrument.

---

# Glass Houses: Secure Providers, Unsigned Routes

*These networks filter RPKI invalids for their customers, but expose their own prefixes:*

| ASN | CC | Cone | Signed% | Name |
|---|---|---|---|---|
| AS3216 | RU | 34,717 | 1.3% | Vimpelcom PJSC |
| AS48185 | BE | 22,344 | 0.0% | team.blue NV |
| AS16735 | BR | 2,619 | 0.0% | Algar Telecom |
| AS14840 | BR | 1,457 | 0.0% | BR.DIGITAL |
| AS46887 | US | 1,372 | 0.3% | Crown Castle Fiber LLC |
| AS2764 | AU | 424 | 0.6% | AAPT Limited |

> **The irony:** Vimpelcom (34,717-network cone) actively drops invalid routes for its 34,717 downstream customers, but 98.7% of its own prefixes are unsigned — meaning any attacker announcing a more-specific prefix wins by longest-match, and because Vimpelcom has no ROA, ROV-enforcing networks have no basis to reject the attacker's announcement as Invalid — it is simply *NotFound*.

---

# Screaming Into The Void

*Networks with excellent ROA hygiene whose upstream transit negates the protection:*

| ASN | CC | Cone | Signed% | Secure Feeds | Name |
|---|---|---|---|---|---|
| AS37721 | BF | 58,192 | 100% | 1/17 | Virtual Technologies & Solutions |
| AS17639 | PH | 42,698 | 97.9% | 0/10 | Converge ICT Solutions |
| AS38001 | SG | 7,938 | 100% | 0/8 | NewMedia Express |
| AS9304 | HK | 5,182 | 100% | 2/15 | HGC Global Communications |
| AS52468 | PA | 4,857 | 100% | 0/7 | UFINET PANAMA |
| AS8220 | GB | 4,784 | 100% | 0/12 | COLT |
| AS18229 | IN | 458 | 96.2% | 1/1 | CtrlS (India) |
| AS131111 | ID | 210 | 100% | 1/1 | PT Mora Telematika Indonesia |
| AS4761 | ID | 158 | 100% | 3/10 | PT Indosat Tbk |

> **SITV is concentrated in the APNIC region.** 4 of 9 top-listed SITV networks are in APAC. The diligence of regional operators is being negated by global holdouts at the transit layer.

---

# Weighted ROA Evangelism: Where to Focus

*Impact = (Provider Cone) × (Count of Unsigned Customers)*

| ASN | Cone | Unsigned Customers | Impact Score | Name |
|---|---|---|---|---|
| AS3356 | 73,602 | 30,138 | **2.22 Billion** | Lumen (Level 3) |
| AS6939 | 74,338 | 28,694 | **2.13 Billion** | Hurricane Electric |
| AS174 | 73,036 | 27,410 | **2.00 Billion** | Cogent |
| AS1299 | 70,453 | 27,353 | **1.93 Billion** | Arelion |
| AS4637 | 64,917 | 24,059 | **1.56 Billion** | Telstra International |
| AS4134 | 64,579 | 20,073 | **1.30 Billion** | China Telecom Backbone |
| AS4809 | 63,887 | 7,652 | **489 Million** | China Telecom Next-Gen |

**Recommendation:** RIR outreach campaigns should target customers of the top 25 providers by Impact Score. These networks will generate the highest ROA density per outreach effort.

---

<!-- _class: section-divider -->

# Part V: APNIC Region Deep-Dive

AU · NZ · JP · IN · ID · CN

---

# Australia — Strong Foundation, Fragmented Middle

**2,976 networks · Cone gravity 16,836**

| Metric | Value |
|---|---|
| SECURE (Active/Passive) | 784 (26.3%) → protects **93.8%** of traffic |
| VULNERABLE | 760 (25.5%) → exposes only 0.6% of traffic |

**The AU core is largely secure:** AARNet (AS7575), Vocus (AS4826), Telstra (AS1221), Aussie Broadband (AS4764) are all ACTIVE LOCAL ROV.

**Key concern:** TPG Telecom (AS7545) — the #2 transit provider with 259 dependent customers — is `PARTIAL: VULNERABLE (Mixed)`. SingTel Optus (AS7474) with 139 dependents is similarly mixed.

**Glass House alert:** AAPT Limited (AS2764) — cone 424, only 0.6% of prefixes signed. Actively filtering but completely unsigned.

> AU sits well above global average but the partial-VULNERABLE providers in the transit supply chain represent real risk for the ~2,200 networks that don't route directly through AARNet or Telstra.

---

# New Zealand — Good Traffic Coverage, Mixed Middle Tier

**718 networks · Cone gravity 2,445**

| Metric | Value |
|---|---|
| SECURE (Active/Passive) | 68 (9.5%) → protects **82.2%** of traffic |
| VULNERABLE | 312 (43.5%) → exposes only 0.7% of traffic |

**Vetta Group** (AS64073, cone 1,902) is the dominant transit entity and `PASSIVE (Clean Pipe)` — protected via upstream ROV, not doing its own filtering.

**Two Degrees** (AS9790) is `ACTIVE LOCAL ROV` — the clearest direct-filtering operator in the NZ market.

**Almost the entire middle tier** — Spark, Devoli, Feenix, Mercury, REANNZ — is `PARTIAL: VULNERABLE (Mixed)`. NZ traffic protection comes primarily from Cogent and Hurricane Electric at the Tier-1 layer, not from domestic filtering.

**Action:** NZ ISPs need to progress from PASSIVE to ACTIVE. The upstream protection is real but not resilient — any upstream policy change loses the benefit immediately.

---

# Japan — High APNIC Scores, Low Structural Security

**973 networks · Cone gravity 1,806**

| Metric | Value |
|---|---|
| SECURE (Active/Passive) | 231 (23.7%) → protects only **39.5%** of traffic |
| VULNERABLE | 443 (45.5%) → exposes 1.1% of traffic |

> **The paradox:** IIJ (AS2497) has 99% APNIC score but is `PARTIAL: VULNERABLE (Mixed)`. KDDI (AS2516) has 0% APNIC score and is also PARTIAL. Japan's two largest transit operators both sit in the mixed zone.

**SoftBank (AS17676)** and **NTT OCN (AS4713)** are `ACTIVE LOCAL ROV` — bright spots with strong APNIC confirmation.

Japan's low traffic-protected percentage (39.5%) relative to its APNIC scores reflects a structural problem: the two dominant transit providers (IIJ and KDDI) serve most of the market but have not completed ROV deployment on all their BGP sessions.

**Priority action:** Pressure IIJ and KDDI to complete ROV across all sessions. Their APNIC scores suggest capability exists — deployment is incomplete, not absent.

---

# India — Transit Layer Largely PASSIVE, Customer Layer VULNERABLE

**6,132 networks · Cone gravity 14,733**

| Metric | Value |
|---|---|
| SECURE (Active/Passive) | 192 (3.1%) → protects **75.0%** of traffic |
| VULNERABLE | 2,525 (41.2%) → exposes **16.9%** of traffic |

**Bharti Airtel (AS9498, cone 7,838)** and **TATA Communications (AS4755, cone 2,536)** are both `PASSIVE (Clean Pipe)` — protected by upstream Tier-1 ROV, not local filtering.

**The cascade problem:** Neither of India's two dominant transit operators performs local ROV. 683 + 562 = 1,245 dependent networks inherit PASSIVE status. If a Tier-1 upstream changes policy, all 1,245 lose their protection simultaneously.

**Immediate vulnerability:** CtrlS (AS18229, cone 458, excl% 78%) and Tata Teleservices ISP (AS45820, cone 343, excl% 69%) are `VULNERABLE` with high captive-customer percentages. These are confirmed non-ROV transit providers with largely single-homed customers.

> India has the largest absolute vulnerable-traffic exposure of any APNIC-region country: **16.9% of all Indian routed traffic** flows through confirmed non-ROV transit.

---

# Indonesia — Pockets of Excellence, Deep Fragmentation

**3,885 networks · Cone gravity 12,900**

| Metric | Value |
|---|---|
| SECURE (Active/Passive) | 101 (2.6%) → protects **70.0%** of traffic |
| VULNERABLE | 2,558 (65.8%) → exposes 8.2% of traffic |

**PT Telkom Indonesia (AS7713, cone 6,219)** is `PASSIVE (Clean Pipe)` — Indonesia's dominant transit operator is not doing local ROV.

**Bright spot:** PT Mora Telematika / AS23947 (cone 492) is `ACTIVE LOCAL ROV`. Separately, AS131111 (same company, different ASN) is `VULNERABLE` with 100% ROA signing — a SITV case.

**Regression alert:** PT Indosat Tbk (AS4761, cone 158, APNIC 44%) and PT Sarana Insan Muda Selaras (AS55655, cone 108) are both `REGRESSED` — their APNIC scores show >30-point drops over the past 12 months from previously secure levels.

**65.8% of Indonesian networks are VULNERABLE** — the highest percentage in the APNIC-5 region. Fragmented market structure (3,885 ASNs) with many small ISPs relying on non-ROV transit compounds the problem.

---

# China — The Bifurcation Problem

**6,473 networks · Cone gravity 183,800**

| Metric | Value |
|---|---|
| SECURE (Active/Passive) | 77 (1.2%) → protects **34.8%** of traffic |
| VULNERABLE | 5,046 (78.0%) → exposes **62.7%** of traffic |

**The single most important BGP security story in Asia-Pacific:**

| ASN | Status | Cone | Name |
|---|---|---|---|
| **AS4809** | CORE: ACTIVE PROTECTOR ✅ | 63,887 | China Telecom **Next Generation** |
| **AS4134** | CORE: UNPROTECTED ❌ | 64,579 | China Telecom **Backbone** |
| **AS4837** | CORE: UNPROTECTED ❌ | 47,004 | China Unicom Backbone |
| **AS9808** | CORE: UNPROTECTED ❌ | 2,629 | China Mobile Backbone |

**AS4809 has already deployed ROV at scale** — proof of capability. AS4134 has not, and its 64,579-network cone exposes 62.7% of Chinese traffic.

**CERNET (AS38255)** — China's academic network — provides transit to **3,859** downstream networks, making it the #3 largest potential ASPV enforcer globally, ahead of AT&T (2,267).

---

<!-- _class: section-divider -->

# Part VI: ASPA — The Next Layer

What comes after ROV, and is the internet ready?

---

# Why ROV Alone Is Insufficient: Route Leaks

**ROV validates the origin AS. It cannot validate the AS-PATH.**

```
Legitimate path:   [Cogent] → [IIJ] → [Customer_A]    ← valid
Route leak path:   [Cogent] → [Customer_A] → [IIJ]     ← ROV sees same origin, passes
```

A route leak occurs when a customer AS re-advertises a provider's routes to another provider — creating a path that violates the Gao-Rexford valley-free constraint but is **invisible to ROV**.

**ASPA (Autonomous System Provider Authorization)** solves this:
- Each AS publishes a signed list of its authorized upstream providers in RPKI
- ASPV (ASPA Verification) checks: *"Is this AS allowed to have sent this route to me?"*
- Valley violations become detectable and rejectable

**RFC 9582** (ASPA Objects) + **RFC 9589** (ASPV Algorithm) — both now published.

---

# ASPA Readiness: The Simplicity Opportunity

**Of 118,863 'regular' networks (CDNs excluded):**

```
Trivial (1–2 Providers):    64,781   (54.5%)   ████████████████████████████░░░░░░░░░░░░░░░░░░░░░░
Moderate (3–5 Providers):   13,646   (11.5%)   ██████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
Complex (>5 Providers):      2,232   ( 1.9%)   █░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
No upstreams (stubs):       38,204   (32.1%)
```

> **54.5% of all networks have 1 or 2 providers.** For them, signing an ASPA record is trivial — one or two ASNs, one or two ROA-like objects. This is the immediate opportunity.

**The "Impossibles"** — Networks with >10 upstreams and 0% ROA hygiene — represent an ASPA engineering challenge, not a policy failure:

Apple (25 providers), Dropbox (24), NAVER Cloud (24), Accenture (96) — these need tooling support for automated ASPA management before they can realistically deploy.

---

# The ASPV Enforcers: Who Gets the Biggest Win

**If these networks turn on ASPV, they secure this many customer C2P links:**

| ASN | Customer Links | Name |
|---|---|---|
| AS174 | **6,555** | Cogent Communications |
| AS3356 | **6,430** | Lumen (Level 3) |
| **AS38255** | **3,859** | **CERNET (China)** |
| AS6939 | **3,726** | Hurricane Electric |
| AS1299 | **2,448** | Arelion |
| AS7018 | **2,267** | AT&T |
| AS6461 | **2,176** | Zayo Bandwidth |
| AS2914 | **1,400** | NTT America |

> **CERNET (AS38255) is the #3 global ASPV enforcer** — ahead of AT&T. An academic network in China has more ASPA leverage than most commercial Tier-1s. If CERNET deploys ASPV, 3,859 Chinese and regional networks benefit immediately.

---

# The Reality Gap: 14,184 Links Left Behind

**Total Customer-to-Provider links globally: 168,935**

```
Theoretical Max ASPA Protection (Top 100 providers):   88,073 links  (52.1%)
Realistic Forecast (weighted by current ROV status):   73,888 links  (43.7%)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
THE REALITY GAP:  14,184 links
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**14,184 C2P links cannot benefit from ASPA enforcement** because their providers have not deployed ROV yet. ASPA is built on top of ROV — a provider that doesn't validate origins cannot validate paths either.

> **The ASPA conversation is often framed as "ASPA isn't ready yet."**
> The data says something different: **the ROV holdouts are also blocking the ASPA future.** Fixing ROV is simultaneously fixing the ASPA deployment blocker.

---

<!-- _class: section-divider -->

# Part VII: Recommendations

Concrete actions by audience

---

# Recommendations: For Network Operators

**If you have not signed ROAs yet:**
- Sign them. This week. It takes hours, not weeks.
- Use your RIR's hosted RPKI — no HSM, no infrastructure required.
- For large networks with many prefixes: start with your most-specific /24s (the most hijackable).

**If you have ROAs but haven't deployed ROV:**
- Enable BGP origin validation in your router software — it's already there.
- Start with `invalid = preferred-false` (lower local-preference), not drop.
- Monitor for false positives for 30 days, then move to `invalid = reject`.
- Your upstream Tier-1s have already done the hard work. You are receiving clean routing tables — you just need to tell your router to use them.

**If you are a transit provider:**
- Your ROV status is a public good — your customers' ROAs are only useful if you filter.
- Glass Houses (large cone, unsigned routes) are a reputational and security liability.
- ASPA signing is now tractable for most transit providers (1–5 upstreams).

---

# Recommendations: For RIRs and Policy Bodies

**APNIC-specific actions:**

1. **Target SITV networks first.** Networks like Converge ICT (PH, cone 42,698, 97.9% signed, 0/10 secure upstreams) have done everything right — their diligence is being negated by providers. RIR-facilitated pressure on the transit providers is needed.

2. **Weighted outreach campaigns.** Use the Impact Score metric (Provider Cone × Unsigned Customers) to prioritize customer outreach. The top 25 providers' customers represent the highest ROA density per outreach dollar.

3. **Publish national routing security scorecards.** Transparent reporting by country — with trend data — creates accountability. APNIC Labs already publishes raw RPKI data; structured per-country verdicts add actionable signal.

4. **ASPA tooling support.** The 2,232 networks with >5 providers need automated ASPA management tooling before they can practically deploy. RIR-provided tooling (like the Hosted RPKI portal) should be extended to ASPA signing.

5. **Address APNIC AS4608/AS4777's VULNERABLE status.** Even if "member lockout" during ROA misconfiguration is a genuine concern, transparent RPKI validation on all sessions is achievable — start with non-member peer sessions.

---

# Recommendations: For the Ecosystem

**The three-layer RPKI stack — in deployment priority order:**

```
┌─────────────────────────────────────────────────────────┐
│  Layer 3: ASPA (Path Validation)          ← Deploy now  │
│  Prevents route leaks and valley violations             │
│  Requires: ROV + ASPA records                           │
├─────────────────────────────────────────────────────────┤
│  Layer 2: ROV (Origin Validation)         ← Complete    │
│  Filters RPKI-invalid route announcements               │
│  Requires: ROA records from origin AS                   │
├─────────────────────────────────────────────────────────┤
│  Layer 1: ROA (Route Origin Authorization)← Foundation  │
│  Claims your prefixes in the RPKI                       │
│  Requires: RIR membership + hosted RPKI                 │
└─────────────────────────────────────────────────────────┘
```

**The order matters.** ROA without ROV is meaningless (no one checks). ROV without ROA breaks legitimate prefixes. ASPA without ROV has no foundation.

**The message for 2026:** The global core is close to herd immunity. The remaining gap is structurally concentrated in 4 networks (CN Telecom Backbone, CN Unicom, CN Mobile, TransTeleCom) with a combined cone of ~150,000 networks. These are diplomatic and regulatory problems, not technical ones.

---

<!-- _class: section-divider -->

# Part VIII: Conclusion

---

# What the Data Says — Honestly

**The good news:**
- 82.8% of global traffic is already protected at the core layer
- The 21 Core Active Protectors (Cogent, Lumen, HE, Arelion, NTT, etc.) are doing their job
- AS4809 (China Telecom Next-Gen) proves that ROV at scale is achievable in China
- 54.5% of networks have trivial ASPA complexity — the signing burden is low

**The uncomfortable news:**
- 48.6% of ASNs are VULNERABLE — that's 58,961 networks
- The 4 CORE: UNPROTECTED networks expose 4.5% of global traffic — that's hundreds of millions of users
- India: 16.9% of traffic exposed through confirmed non-ROV transit
- Indonesia: 65.8% of networks VULNERABLE
- SITV is concentrated in the APNIC region — regional diligence is being undercut by global holdouts

**The structural truth:**
The internet is not uniformly close to security. Traffic coverage is high; network coverage is not. The long tail of small vulnerable transit providers represents real harm to their customers, even if the traffic volumes are small globally.

---

# Summary: Who Should Do What

| Actor | Priority Action | Timeline |
|---|---|---|
| **Small ISP** | Sign ROAs for all prefixes | This quarter |
| **Regional transit** | Deploy ROV (invalid = reject) | This quarter |
| **Large transit** | Sign ASPA records | Next 6 months |
| **CN Telecom Backbone** | Align with AS4809 ROV deployment | Ongoing |
| **IN Bharti Airtel** | Move from PASSIVE → ACTIVE LOCAL ROV | This year |
| **ID Telkom Indonesia** | Move from PASSIVE → ACTIVE LOCAL ROV | This year |
| **APNIC** | Publish national scorecards; target SITV | Ongoing |
| **IETF** | ASPA tooling standardization (RFC 9582+) | In progress |

> **The herd immunity threshold is within reach.** Closing the gap requires political will at the provider layer — not new technology.

---

# Questions & Discussion

**Contact:** Terry Sweetser · tcs@ieisi.org

**Repository:** https://github.com/IEISI-ORG/rov_audit

**Discussion prompts:**

- How do we create regulatory or commercial pressure on CORE: UNPROTECTED transit providers?
- Is "member lockout" a valid justification for APNIC's own infrastructure remaining VULNERABLE?
- Should RIRs tie transit provider membership benefits to minimum ROV deployment standards?
- What is the right incentive structure for the 60% of networks with zero ROA coverage?
- CERNET as #3 global ASPV enforcer — is this a diplomatic opportunity for APNIC?

---

<!-- _class: section-divider -->

# Appendices

---

# Appendix A: Full Verdict Taxonomy

| Verdict | Meaning | classify_verdict() |
|---|---|---|
| `CORE: ACTIVE PROTECTOR` | Tier-1, confirmed ROV, cone ≥5,000 | SECURE |
| `ACTIVE LOCAL ROV` | Local ROV confirmed (bgp.tools + APNIC ≥95% or Atlas) | SECURE |
| `STUB: ACTIVE LOCAL ROV` | Stub, local ROV confirmed | SECURE |
| `PASSIVE (Clean Pipe)` | Protected by upstream ROV, not local | SECURE |
| `STUB: PASSIVE` | Stub, upstream protected | SECURE |
| `STUB: FORTUITOUS ROV` | Stub, APNIC ≥95% but no direct ROV confirmation | SECURE |
| `VOLATILE` | APNIC score oscillating >30pts over 90 days | PARTIAL |
| `PARTIAL: VULNERABLE (Mixed)` | Some sessions ROV, some not | PARTIAL |
| `REGRESSED` | APNIC timeseries shows >30pt drop in 12-month lookback | VULNERABLE |
| `INCONSISTENT` | In bgp.tools rov_set but APNIC <30% | VULNERABLE |
| `VULNERABLE` | No evidence of ROV from any source | VULNERABLE |
| `CORE: UNPROTECTED` | Tier-1, confirmed non-ROV, cone ≥5,000 | VULNERABLE |
| `VULNERABLE (Atlas Verified)` | Atlas forensics confirmed non-ROV | VULNERABLE |

---

# Appendix B: IXP Phantom Mitigation Detail

**The AMS-IX effect — why naive topology inference fails:**

IXP route servers strip their own ASN (RFC 7947). A network peering with 500 ASNs at AMS-IX appears to have 500 direct BGP neighbors in the MRT dumps — an inflated degree count. The 4× ratio fires, and the IXP participant appears as a provider to all 500 peers.

**Backstop: `cone_quality(asn)`**
For any non-Tier-1 with cone > 100:
- Compute `excl_pct` = % of direct "customers" with ≤2 total providers
- Legitimate transit: captive customers (high excl_pct — they can't route around you)
- IXP phantom: peers with 10-20 providers each (low excl_pct — they don't need you)
- Threshold: `excl_pct ≥ 5%` required to count for herd immunity

**Result in this audit:**
83 networks excluded from herd immunity calculations as IXP phantoms.
Example: AS7717 (OpenIXP Route Servers, ID) — cone 174, excl_pct 32% (borderline), excluded.

---

# Appendix C: APNIC Timeseries Regression Detection

**The regression signal:**

```python
historical_max = max(rates[-365:])   # 1-year lookback, not all-time
current = rates[-30:]                 # most recent 30 days
current_for_regression = [r for r, n in current if n >= 100]

if historical_max >= 50 and current_mean < historical_max - 30:
    regression = True
```

**Why 1-year lookback (not all-time):**
Early APNIC measurements (2019–2020) had noise spikes unrelated to actual ROV deployment. Using `max(all_time)` falsely flagged 2,803 stable networks as REGRESSED, including AT&T (stable 55–58% for years, with a 2019 noise spike to 100%).

**The `n ≥ 100` current samples threshold:**
Large transit ASNs can have low-traffic periods where APNIC ad impressions drop below 30/day. A 3-day sample of 90 impressions at 0% (congestion, routing change, etc.) is noise, not a policy rollback. We require 100+ samples before a current=0% reading can trigger REGRESSED status.

**Current result:** 940 networks carry `REGRESSED` status (0.8% of all ASNs, 5.0% of traffic impact).
