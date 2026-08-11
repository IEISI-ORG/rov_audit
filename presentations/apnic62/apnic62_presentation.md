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
3. **Global Results** — 122,277 ASNs audited
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
  (239 countries)         (1,269 ROV tags)
  APNIC Timeseries        Cloudflare Safe List
  (11,498 ASNs)           (466 ASNs)
         └──────────┬──────────┘
                    ↓
         RIPE Atlas Forensic Engine
         (7-verdict path taxonomy)
                    ↓
         122,277 ASNs audited
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

**Result:** 89 IXP phantom networks excluded from herd immunity calculations (e.g. AS7717 OpenIXP Route Servers, ID — cone 224, excl% 30%).

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

122,277 ASNs · August 2026

---

# Global Verdict Breakdown

**122,277 ASNs audited across 239 countries.**

| Verdict | ASNs | % | Avg Cone | Traffic Impact |
|---|---|---|---|---|
| **CORE: ACTIVE PROTECTOR** | 21 | 0.02% | 62,275 | **53.0%** |
| ACTIVE LOCAL ROV | 287 | 0.23% | 496 | 5.8% |
| PASSIVE (Clean Pipe) | 986 | 0.81% | 259 | 10.3% |
| STUB: PASSIVE | 19,318 | 15.8% | 0 | 0.0% |
| PARTIAL: VULNERABLE | 3,606 | 3.0% | 127 | 18.6% |
| REGRESSED | 1,432 | 1.2% | 78 | 4.5% |
| STUB: VULNERABLE | 54,151 | 44.3% | 0 | 0.0% |
| CORE: UNPROTECTED | 3 | <0.01% | 38,165 | **4.6%** |

**Overall:** SECURE 23,055 (18.9%) · PARTIAL 3,606 (3.0%) · VULNERABLE 56,856 (46.5%)

> 21 networks protect 53.0% of global traffic. 3 networks expose 4.6%.

---

# The Herd Immunity Scoreboard

```
[GLOBAL CORE] Top 100 legitimate transit networks

  Networks Secure:      59 / 100  (59.0%)
  Traffic Protected:   81.1%  (by Cone Weight)

  ████████████████████████████████████████░░░░░░░░░

[TRANSIT LAYER] Top 1,000 legitimate transit networks

  Networks Secure:     294 / 1,000  (29.4%)
  Traffic Protected:   78.9%  (by Cone Weight)

  ███████████████████████████████████████░░░░░░░░░░░
```

**Interpretation:** We are asymptotically close to herd immunity at the traffic level — but not at the network count level. The long tail of vulnerable small transit ASNs represent real exposure for their direct customers.

---

# The Holdouts: Top Vulnerable Transit Networks

*Networks whose ROV deployment would have the highest impact:*

| Rank | ASN | CC | Cone | Excl% | Name |
|---|---|---|---|---|---|
| #15 | AS4134 | CN | 65,065 | 79% | China Telecom Backbone |
| #21 | AS4837 | CN | 47,013 | 62% | China Unicom Backbone |
| #26 | AS3216 | RU | 26,017 | 33% | Vimpelcom PJSC |
| #35 | AS52468 | PA | 5,800 | 50% | UFINET PANAMA |
| #49 | AS9808 | CN | 2,418 | 73% | China Mobile Backbone |
| #55 | AS9304 | HK | 1,976 | 32% | HGC Global Communications |
| #58 | AS9929 | CN | 1,693 | 67% | China Unicom Industrial Internet Backbone |
| #112 | AS18229 | IN | 435 | 80% | CtrlS |
| #126 | AS45820 | IN | 352 | 69% | Tata Teleservices ISP |

**`Excl%`** = percentage of direct customers with ≤2 total providers — a measure of captive dependence. High excl% means customers *cannot* route around this provider.

---

# The ROV Quadrant Map

| | **Provider: SECURE** | **Provider: VULNERABLE** |
|---|---|---|
| **Customers: Signed (>60%)** | ✅ **Q1: Gold Standard** | 📢 **Q2: Screaming Into The Void** |
| **Customers: Unsigned (<60%)** | 🏚 **Q3: Glass Houses** | 🌵 **Q4: The Swamp** |

**Q1 Gold Standard examples:** Hurricane Electric (cone 79,819, 68.4% customer signing), Arelion (70,841, 73.7%), NTT America (68,189, 71.5%), TATA Communications America (67,066, 75.7%), PCCW Global (66,610, 76.2%)

**Q2 Screaming Into The Void:** China Telecom Backbone / CN (cone 65,065, 87.8% customer signing — non-ROV), China Unicom Backbone / CN (47,013, 81.7%), RETN / GB (45,263, 78.1%)

**Q3 Glass Houses:** Lumen/Level 3 (cone 73,943, only 38.5% customer signing), Cogent (73,283, 51.0%), Zayo (71,693, 43.9%), GTT (69,138, 58.7%), AT&T (69,034, 18.9%)

**Q4 The Swamp:** SG.GS (cone 64,564, 0% customer signing), Virtual Technologies & Solutions / BF (58,097, 0%), Converge ICT / PH (43,014, 0%)

> **Correction note:** a bug in the quadrant-classification script (`"PROTECTED" in verdict` matched `CORE: UNPROTECTED` as a false positive) previously misplaced non-ROV Tier-1s into Q1. Fixed to use `rov_utils.is_secure()`; China Telecom/Unicom Backbone now correctly appear in Q2, and several large ROV-enforcing-but-unsigned transit providers (Cogent, Lumen, Zayo, GTT, AT&T) are confirmed in Q3.

---

<!-- _class: section-divider -->

# Part IV: ROA Signing

Where is the inventory, and who is wasting it?

---

# Global ROA Signing Status

**Of 122,277 ASNs with active routing:**

```
  Fully Signed (>90%):    45,196   (37.0%)  ██████████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
  Partially Signed:        6,018   ( 4.9%)  ██░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
  Totally Unsigned:       71,063   (58.1%)  █████████████████████████████░░░░░░░░░░░░░░░░░░░░░
```

**More than half of all routed networks have zero ROA coverage.**

This means ROV-enforcing providers — even those doing everything right — are regularly seeing legitimate-but-unsigned routes from their customers. Enforcing strict invalid-drop is operationally difficult when 60% of customer prefixes are unprotected by a ROA.

ROA signing is the **foundation** of the entire RPKI ecosystem. Without it, ROV is filtering noise; with it, ROV becomes a precision instrument.

---

# Glass Houses: Secure Providers, Unsigned Routes

*These networks filter RPKI invalids for their customers, but expose their own prefixes:*

| ASN | CC | Cone | Signed% | Name |
|---|---|---|---|---|
| AS48185 | BE | 21,696 | 0.0% | team.blue NV |
| AS16735 | BR | 2,319 | 0.0% | Algar Telecom |
| AS205794 | CN | 1,690 | 0.0% | JINZE YANG |
| AS46887 | US | 1,383 | 0.3% | Zayo Bandwidth |
| AS3786 | KR | 545 | 0.2% | LG DACOM Corporation |
| AS2764 | AU | 413 | 0.8% | AAPT Limited |

> **The irony:** team.blue (21,696-network cone) actively drops invalid routes for its 21,696 downstream customers, but 100% of its own prefixes are unsigned — meaning any attacker announcing a more-specific prefix wins by longest-match, and because team.blue has no ROA, ROV-enforcing networks have no basis to reject the attacker's announcement as Invalid — it is simply *NotFound*.
>
> **Note:** Vimpelcom PJSC (AS3216) — the prior top example — has since dropped out of the Glass Houses list entirely because its own ROV status regressed to VULNERABLE (now rank #26 on the Top Vulnerable Transit Networks table), not because it fixed its signing.

---

# Screaming Into The Void

*Networks with excellent ROA hygiene whose upstream transit negates the protection:*

| ASN | CC | Cone | Signed% | Secure Feeds | Name |
|---|---|---|---|---|---|
| AS4134 | CN | 65,065 | 100.0% | 0/0 | China Telecom Backbone |
| AS37721 | BF | 58,097 | 100.0% | 1/16 | Virtual Technologies & Solutions |
| AS4837 | CN | 47,013 | 98.8% | 0/0 | China Unicom Backbone |
| AS17639 | PH | 43,014 | 97.8% | 0/10 | Converge ICT Solutions |
| AS38001 | SG | 7,939 | 100.0% | 0/8 | NewMedia Express |
| AS52468 | PA | 5,800 | 100.0% | 0/8 | UFINET PANAMA |
| AS9304 | HK | 1,976 | 100.0% | 2/15 | HGC Global Communications |
| AS18229 | IN | 435 | 100.0% | 1/1 | CtrlS (India) |
| AS131111 | ID | 228 | 100.0% | 1/1 | PT Mora Telematika Indonesia |

> **SITV is now dominated by the two largest Chinese backbones.** AS4134 (China Telecom Backbone, 65,065-network cone, 100% self-signed) and AS4837 (China Unicom Backbone, 47,013-network cone) top the list — their own ROA hygiene is exemplary, but neither performs ROV, negating the effect for their combined ~112,000 downstream networks. 3 of 9 top-listed SITV networks remain in APAC.

---

# Weighted ROA Evangelism: Where to Focus

*Impact = (Provider Cone) × (Count of Unsigned Customers)*

| ASN | Cone | Unsigned Customers | Impact Score | Name |
|---|---|---|---|---|
| AS6939 | 79,819 | 31,949 | **2.55 Billion** | Hurricane Electric |
| AS3356 | 73,943 | 28,716 | **2.12 Billion** | Lumen (Level 3) |
| AS174 | 73,283 | 25,405 | **1.86 Billion** | Cogent |
| AS1299 | 70,841 | 26,090 | **1.85 Billion** | Arelion |
| AS4637 | 66,492 | 22,724 | **1.51 Billion** | Telstra International |
| AS4134 | 65,065 | 18,620 | **1.21 Billion** | China Telecom Backbone |
| AS4809 | 64,782 | 7,992 | **518 Million** | China Telecom Next-Gen |

**Recommendation:** RIR outreach campaigns should target customers of the top 25 providers by Impact Score. These networks will generate the highest ROA density per outreach effort.

---

<!-- _class: section-divider -->

# Part V: APNIC Region Deep-Dive

AU · NZ · JP · IN · ID · CN

---

# Australia — Strong Foundation, Fragmented Middle

**2,915 networks · Cone gravity 12,745**

| Metric | Value |
|---|---|
| SECURE (Active/Passive) | 772 (26.5%) → protects **91.8%** of traffic |
| VULNERABLE | 717 (24.6%) → exposes only 0.7% of traffic |

**The AU core is largely secure:** AARNet (AS7575), Vocus (AS4826), Telstra (AS1221), Aussie Fibre (AS4764) are all ACTIVE LOCAL ROV.

**Key concern:** TPG Telecom (AS7545) — the #2 transit provider with 258 dependent customers — is `PARTIAL: VULNERABLE (Mixed)`. SingTel Optus (AS7474) with 140 dependents is similarly mixed.

**Glass House alert:** AAPT Limited (AS2764) — cone 413, only 0.8% of prefixes signed. Actively filtering but completely unsigned.

> AU sits well above global average but the partial-VULNERABLE providers in the transit supply chain represent real risk for the ~2,100 networks that don't route directly through AARNet or Telstra.

---

# New Zealand — Good Traffic Coverage, Mixed Middle Tier

**706 networks · Cone gravity 2,287**

| Metric | Value |
|---|---|
| SECURE (Active/Passive) | 78 (11.0%) → protects **82.2%** of traffic |
| VULNERABLE | 288 (40.8%) → exposes only 0.1% of traffic |

**Vetta Group** (AS64073, cone 1,761) is the dominant transit entity and `PASSIVE (Clean Pipe)` — protected via upstream ROV, not doing its own filtering.

**Two Degrees** (AS9790) is `ACTIVE LOCAL ROV` — the clearest direct-filtering operator in the NZ market.

**Almost the entire middle tier** — Spark, Devoli, Feenix, Mercury, REANNZ — is `PARTIAL: VULNERABLE (Mixed)`. NZ traffic protection comes primarily from Cogent and Hurricane Electric at the Tier-1 layer, not from domestic filtering.

**Action:** NZ ISPs need to progress from PASSIVE to ACTIVE. The upstream protection is real but not resilient — any upstream policy change loses the benefit immediately.

---

# Japan — High APNIC Scores, Low Structural Security

**968 networks · Cone gravity 1,799**

| Metric | Value |
|---|---|
| SECURE (Active/Passive) | 292 (30.2%) → protects **53.9%** of traffic |
| VULNERABLE | 396 (40.9%) → exposes 1.1% of traffic |

> **The paradox:** IIJ (AS2497) has 98% APNIC score but is `PARTIAL: VULNERABLE (Mixed)`. KDDI (AS2516) has 0% APNIC score and is also PARTIAL. Japan's two largest transit operators both sit in the mixed zone.

**SoftBank (AS17676)** and **NTT OCN (AS4713)** are `ACTIVE LOCAL ROV` — bright spots with strong APNIC confirmation.

Japan's traffic-protected percentage (53.9%, up from 39.5% previously) is improving but still trails its APNIC scores: the two dominant transit providers (IIJ and KDDI) serve most of the market but have not completed ROV deployment on all their BGP sessions.

**Priority action:** Pressure IIJ and KDDI to complete ROV across all sessions. Their APNIC scores suggest capability exists — deployment is incomplete, not absent.

---

# India — Transit Layer Largely PASSIVE, Customer Layer VULNERABLE

**6,173 networks · Cone gravity 14,176**

| Metric | Value |
|---|---|
| SECURE (Active/Passive) | 182 (2.9%) → protects **69.7%** of traffic |
| VULNERABLE | 2,590 (42.0%) → exposes **22.2%** of traffic |

**Bharti Airtel (AS9498, cone 7,328)** and **TATA Communications (AS4755, cone 2,530)** are both `PASSIVE (Clean Pipe)` — protected by upstream Tier-1 ROV, not local filtering.

**The cascade problem:** Neither of India's two dominant transit operators performs local ROV. 707 + 589 = 1,296 dependent networks inherit PASSIVE status. If a Tier-1 upstream changes policy, all 1,296 lose their protection simultaneously.

**Immediate vulnerability:** CtrlS (AS18229, cone 435, excl% 80%) and Tata Teleservices ISP (AS45820, cone 352, excl% 69%) are `VULNERABLE` with high captive-customer percentages. These are confirmed non-ROV transit providers with largely single-homed customers.

> India has the largest absolute vulnerable-traffic exposure of any APNIC-region country, and it has grown since the last audit: **22.2% of all Indian routed traffic** now flows through confirmed non-ROV transit (up from 16.9%).

---

# Indonesia — Pockets of Excellence, Deep Fragmentation

**3,969 networks · Cone gravity 11,928**

| Metric | Value |
|---|---|
| SECURE (Active/Passive) | 63 (1.6%) → protects **70.2%** of traffic |
| VULNERABLE | 2,676 (67.4%) → exposes 11.4% of traffic |

**PT Telkom Indonesia (AS7713, cone 4,804)** is `PASSIVE (Clean Pipe)` — Indonesia's dominant transit operator is not doing local ROV.

**Status change:** PT Mora Telematika / AS23947 (cone 473) has moved from `ACTIVE LOCAL ROV` to `PASSIVE (Clean Pipe)` — it is still protected, but no longer confirmed as filtering locally. AS131111 (same company, different ASN) remains `VULNERABLE` with 100% ROA signing — a persistent SITV case.

**Regression alert:** PT Indosat Tbk (AS4761, cone 148, APNIC 42%) and PT Sarana Insan Muda Selaras (AS55655, cone dropped to 0) are both `REGRESSED` — their APNIC scores show >30-point drops over the past 12 months from previously secure levels.

**67.4% of Indonesian networks are VULNERABLE** — the highest percentage in the APNIC-5 region, and worse than the prior audit's 65.8%. Fragmented market structure (3,969 ASNs) with many small ISPs relying on non-ROV transit compounds the problem.

---

# China — The Bifurcation Problem

**6,491 networks · Cone gravity 187,932**

| Metric | Value |
|---|---|
| SECURE (Active/Passive) | 69 (1.1%) → protects **37.6%** of traffic |
| VULNERABLE | 5,064 (78.0%) → exposes **62.1%** of traffic |

**The single most important BGP security story in Asia-Pacific:**

| ASN | Status | Cone | Name |
|---|---|---|---|
| **AS4809** | CORE: ACTIVE PROTECTOR ✅ | 64,782 | China Telecom **Next Generation** |
| **AS4134** | CORE: UNPROTECTED ❌ | 65,065 | China Telecom **Backbone** |
| **AS4837** | CORE: UNPROTECTED ❌ | 47,013 | China Unicom Backbone |
| **AS9808** | CORE: UNPROTECTED ❌ | 2,418 | China Mobile Backbone |

**AS4809 has already deployed ROV at scale** — proof of capability. AS4134 has not, and its 65,065-network cone remains the largest single contributor to Chinese traffic exposure.

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

**Of 121,152 'regular' networks (CDNs excluded):**

```
Trivial (1–2 Providers):    64,786   (53.5%)   ███████████████████████████░░░░░░░░░░░░░░░░░░░░░░░
Moderate (3–5 Providers):   13,648   (11.3%)   █████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
Complex (>5 Providers):      2,230   ( 1.8%)   █░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
No upstreams (stubs):       40,488   (33.4%)
```

> **53.5% of all networks have 1 or 2 providers.** For them, signing an ASPA record is trivial — one or two ASNs, one or two ROA-like objects. This is the immediate opportunity.

**The "Impossibles"** — Networks with >10 upstreams and 0% ROA hygiene — represent an ASPA engineering challenge, not a policy failure:

Apple (25 providers), Dropbox (22), NAVER Cloud (21), Accenture (18) — these need tooling support for automated ASPA management before they can realistically deploy.

---

# The ASPV Enforcers: Who Gets the Biggest Win

**If these networks turn on ASPV, they secure this many customer C2P links:**

| ASN | Customer Links | Name |
|---|---|---|
| AS174 | **6,555** | Cogent Communications |
| AS3356 | **6,431** | Lumen (Level 3) |
| **AS38255** | **3,859** | **CERNET (China)** |
| AS6939 | **3,726** | Hurricane Electric |
| AS1299 | **2,448** | Arelion |
| AS7018 | **2,267** | AT&T |
| AS6461 | **2,177** | Zayo Bandwidth |
| AS2914 | **1,401** | NTT America |

> **CERNET (AS38255) is the #3 global ASPV enforcer** — ahead of AT&T. An academic network in China has more ASPA leverage than most commercial Tier-1s. If CERNET deploys ASPV, 3,859 Chinese and regional networks benefit immediately.

---

# The Reality Gap: 9,986 Links Left Behind

**Total Customer-to-Provider links globally: 167,792**

```
Theoretical Max ASPA Protection (Top 100 providers):   87,155 links  (51.9%)
Realistic Forecast (weighted by current ROV status):   77,168 links  (46.0%)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
THE REALITY GAP:  9,986 links
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**9,986 C2P links cannot benefit from ASPA enforcement** because their providers have not deployed ROV yet — down from 14,184 in the prior audit, reflecting genuine ROV progress among mid-tier providers. ASPA is built on top of ROV — a provider that doesn't validate origins cannot validate paths either.

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

1. **Target SITV networks first.** Networks like Converge ICT (PH, cone 43,014, 97.8% signed, 0/10 secure upstreams) have done everything right — their diligence is being negated by providers. RIR-facilitated pressure on the transit providers is needed.

2. **Weighted outreach campaigns.** Use the Impact Score metric (Provider Cone × Unsigned Customers) to prioritize customer outreach. The top 25 providers' customers represent the highest ROA density per outreach dollar.

3. **Publish national routing security scorecards.** Transparent reporting by country — with trend data — creates accountability. APNIC Labs already publishes raw RPKI data; structured per-country verdicts add actionable signal.

4. **ASPA tooling support.** The 2,230 networks with >5 providers need automated ASPA management tooling before they can practically deploy. RIR-provided tooling (like the Hosted RPKI portal) should be extended to ASPA signing.

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

**The message for 2026:** The global core is close to herd immunity. The remaining gap is structurally concentrated in a handful of networks — the 3 `CORE: UNPROTECTED` Tier-1s (CN Telecom Backbone, CN Unicom, CN Mobile) plus regional giants like Vimpelcom (RU) — with a combined cone of ~140,500 networks. These are diplomatic and regulatory problems, not technical ones.

---

<!-- _class: section-divider -->

# Part VIII: Conclusion

---

# What the Data Says — Honestly

**The good news:**
- 81.1% of global traffic is already protected at the core layer
- The 21 Core Active Protectors (Cogent, Lumen, HE, Arelion, NTT, etc.) are doing their job
- AS4809 (China Telecom Next-Gen) proves that ROV at scale is achievable in China
- 53.5% of networks have trivial ASPA complexity — the signing burden is low
- The ASPA Reality Gap has shrunk from 14,184 to 9,986 links since the last audit

**The uncomfortable news:**
- 46.5% of ASNs are VULNERABLE — that's 56,856 networks
- The 3 CORE: UNPROTECTED networks expose 4.6% of global traffic — that's hundreds of millions of users
- India: 22.2% of traffic exposed through confirmed non-ROV transit — up from 16.9%
- Indonesia: 67.4% of networks VULNERABLE — up from 65.8%
- SITV is now dominated by China Telecom and China Unicom Backbone — regional diligence is being undercut by global holdouts

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
89 networks excluded from herd immunity calculations as IXP phantoms.
Example: AS7717 (OpenIXP Route Servers, ID) — cone 224, excl_pct 30% (borderline), excluded.

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

**Current result:** 1,432 networks carry `REGRESSED` status (1.2% of all ASNs, 4.5% of traffic impact).
