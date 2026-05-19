# APNIC-62 Presentation — Claims & Conclusions Verification Prompt

Use this prompt with Claude (or another LLM with access to the audit data) to systematically verify every factual assertion in `apnic62_presentation.md` before the talk.

---

## Instructions for the verifier

You are fact-checking the APNIC-62 presentation `apnic62_presentation.md` against the May 2026 rov_audit_v22 output. For each claim below, locate the authoritative source in the listed report file, confirm the number or statement matches, and flag any discrepancy. Where the claim is a technical assertion about RPKI/BGP protocol behaviour (not an audit statistic), evaluate it against RFC text or established operator practice.

Use this working directory: `/home/terry/rov_audit/`

**Verdict for each claim:** ✅ Confirmed / ⚠️ Close but imprecise / ❌ Wrong / ❓ Not found in source

---

## Section I — Global Statistics (slide 13)

Source: `reports/statistics.md`

| Claim | Source field |
|---|---|
| 121,363 ASNs audited | total ASN count |
| CORE: ACTIVE PROTECTOR — 21 ASNs, 52.7% traffic | verdict breakdown table |
| ACTIVE LOCAL ROV — 170 ASNs, 5.7% traffic | verdict breakdown |
| PASSIVE (Clean Pipe) — 912 ASNs, 10.7% traffic | verdict breakdown |
| STUB: PASSIVE — 18,392 ASNs | verdict breakdown |
| PARTIAL: VULNERABLE — 3,760 ASNs, 18.3% traffic | verdict breakdown |
| REGRESSED — 940 ASNs, 5.0% traffic | verdict breakdown |
| STUB: VULNERABLE — 56,786 ASNs | verdict breakdown |
| CORE: UNPROTECTED — 4 ASNs, 4.5% traffic | verdict breakdown |
| Overall: SECURE 20,462 (16.9%), PARTIAL 3,760 (3.1%), VULNERABLE 58,961 (48.6%) | aggregated counts |

---

## Section II — Herd Immunity (slide 14–15)

Source: `reports/analyze_herd_immunity.md`

| Claim | Source field |
|---|---|
| Top 100 core: 58/100 secure (58.0%) | core layer table |
| Top 100 core: 82.8% traffic protected | core layer traffic weight |
| Top 1,000 transit: 272/1,000 secure (27.2%) | transit layer table |
| Top 1,000 transit: 80.5% traffic protected | transit layer traffic weight |

**Holdout table (slide 15)** — verify each row against `reports/analyze_herd_immunity.md` holdout section:

| ASN | Cone | Excl% | Verdict in report |
|---|---|---|---|
| AS4134 | 64,579 | 81% | |
| AS4837 | 47,004 | 67% | |
| AS20485 | 28,703 | 22% | |
| AS9304 | 5,182 | 22% | |
| AS52468 | 4,857 | 50% | |
| AS8220 | 4,784 | 55% | |
| AS9808 | 2,629 | 76% | |
| AS18229 | 458 | 78% | |
| AS45820 | 343 | 69% | |

---

## Section III — ROA Signing (slides 18–21)

Source: `reports/analyze_roa_signing.md`

| Claim | Source field |
|---|---|
| Fully Signed (>90%): 43,150 ASNs (35.6%) | signing distribution |
| Partially Signed: 5,900 ASNs (4.9%) | signing distribution |
| Totally Unsigned: 72,313 ASNs (59.6%) | signing distribution |

**Glass Houses table (slide 19)** — verify Signed% for each network against the report:

| ASN | Name | Cone | Signed% claimed |
|---|---|---|---|
| AS3216 | Vimpelcom PJSC | 34,717 | 1.3% |
| AS48185 | team.blue NV | 22,344 | 0.0% |
| AS16735 | Algar Telecom | 2,619 | 0.0% |
| AS14840 | BR.DIGITAL | 1,457 | 0.0% |
| AS46887 | Crown Castle Fiber LLC | 1,372 | 0.3% |
| AS2764 | AAPT Limited | 424 | 0.6% |

**SITV table (slide 20)** — verify Signed% and Secure Feeds count for each network:

| ASN | Name | Cone | Signed% | Secure Feeds |
|---|---|---|---|---|
| AS37721 | Virtual Technologies & Solutions | 58,192 | 100% | 1/17 |
| AS17639 | Converge ICT Solutions | 42,698 | 97.9% | 0/10 |
| AS38001 | NewMedia Express | 7,938 | 100% | 0/8 |
| AS9304 | HGC Global Communications | 5,182 | 100% | 2/15 |
| AS52468 | UFINET PANAMA | 4,857 | 100% | 0/7 |
| AS8220 | COLT | 4,784 | 100% | 0/12 |
| AS18229 | CtrlS (India) | 458 | 96.2% | 1/1 |
| AS131111 | PT Mora Telematika Indonesia | 210 | 100% | 1/1 |
| AS4761 | PT Indosat Tbk | 158 | 100% | 3/10 |

**Weighted Evangelism table (slide 21)** — verify Impact Scores:

Source: `reports/analyze_roa_strategy.md`

| ASN | Name | Cone | Unsigned Customers | Impact Score |
|---|---|---|---|---|
| AS3356 | Lumen (Level 3) | 73,602 | 30,138 | 2.22 Billion |
| AS6939 | Hurricane Electric | 74,338 | 28,694 | 2.13 Billion |
| AS174 | Cogent | 73,036 | 27,410 | 2.00 Billion |
| AS1299 | Arelion | 70,453 | 27,353 | 1.93 Billion |
| AS4637 | Telstra International | 64,917 | 24,059 | 1.56 Billion |
| AS4134 | China Telecom Backbone | 64,579 | 20,073 | 1.30 Billion |
| AS4809 | China Telecom Next-Gen | 63,887 | 7,652 | 489 Million |

Check: Impact Score = Cone × Unsigned Customers (verify arithmetic for each row).

---

## Section IV — APNIC Region (slides 23–28)

Source: `reports/au_report.md`, `nz_report.md`, `jp_report.md`, `in_report.md`, `id_report.md`, `cn_report.md`

| Country | Claim | Source |
|---|---|---|
| AU | 2,976 networks, 26.3% secure, 93.8% traffic protected | au_report.md |
| AU | TPG Telecom AS7545: PARTIAL: VULNERABLE | au_report.md |
| AU | AAPT AS2764: cone 424, 0.6% signed | au_report.md |
| NZ | 718 networks, 9.5% secure, 82.2% traffic protected | nz_report.md |
| NZ | Vetta Group AS64073: cone 1,902, PASSIVE | nz_report.md |
| JP | 973 networks, 23.7% secure, 39.5% traffic protected | jp_report.md |
| JP | IIJ AS2497: 99% APNIC score, PARTIAL: VULNERABLE | jp_report.md |
| IN | 6,132 networks, 3.1% secure, 16.9% exposed traffic | in_report.md |
| IN | Bharti Airtel AS9498: cone 7,838, PASSIVE | in_report.md |
| IN | TATA AS4755: cone 2,536, PASSIVE | in_report.md |
| ID | 3,885 networks, 2.6% secure, 65.8% VULNERABLE | id_report.md |
| ID | PT Telkom Indonesia AS7713: cone 6,219, PASSIVE | id_report.md |
| ID | Indosat AS4761 and AS55655: REGRESSED | id_report.md |
| CN | 6,473 networks, 1.2% secure | cn_report.md |
| CN | AS4809 CORE: ACTIVE PROTECTOR, cone 63,887 | cn_report.md |
| CN | AS4134 CORE: UNPROTECTED, cone 64,579 | cn_report.md |
| CN | AS4837 CORE: UNPROTECTED, cone 47,004 | cn_report.md |
| CN | CERNET AS38255: 3,859 downstream networks | cn_report.md or analyze_aspa_readiness.md |

---

## Section V — ASPA (slides 30–33)

Source: `reports/analyze_aspa_realistic.md`, `reports/analyze_aspa_readiness.md`

| Claim | Source |
|---|---|
| Trivial (1–2 providers): 64,781 networks (54.5%) | analyze_aspa_readiness.md |
| Moderate (3–5): 13,646 (11.5%) | analyze_aspa_readiness.md |
| Complex (>5): 2,232 (1.9%) | analyze_aspa_readiness.md |
| No upstreams (stubs): 38,204 (32.1%) | analyze_aspa_readiness.md |
| Apple: 25 providers, Dropbox: 24, Accenture: 96 | analyze_aspa_readiness.md |
| ASPV Enforcers top 8: Cogent 6,555, Lumen 6,430, CERNET 3,859, HE 3,726, Arelion 2,448, AT&T 2,267, Zayo 2,176, NTT 1,400 | analyze_aspa_realistic.md |
| Reality Gap: 14,184 C2P links cannot benefit from ASPA | analyze_aspa_readiness.md |
| Total C2P links: 168,935 | analyze_aspa_readiness.md |
| Theoretical max ASPA protection: 88,073 links (52.1%) | analyze_aspa_readiness.md |
| Realistic forecast: 73,888 links (43.7%) | analyze_aspa_readiness.md |

---

## Section VI — ROV Quadrant (slide 16)

Source: `reports/analyze_rov_quadrants.md`

| Claim | Source |
|---|---|
| Q1 Gold Standard: Hurricane Electric cone 68,256 | quadrant report |
| Q1: SG.GS cone 65,410, Arelion cone 48,082 | quadrant report |
| Q2 SITV: Virtual Technologies/BF cone 58,181, 66.8% signed | quadrant report |
| Q2: F5 Networks SARL/FR cone 50,969, 66.2% signed | quadrant report |
| Q3 Glass Houses: Lumen cone 64,668, 34.1% signed | quadrant report |
| Q3: Cogent cone 64,504, 44.7% signed | quadrant report |
| Q3: Zayo cone 40,790, 33.4% signed | quadrant report |
| Q4 The Swamp: TECHIT.BE SRL cone 24,556, 0% signed | quadrant report |
| Q4: Rostelecom cone 10,447, 37.3% signed | quadrant report |

---

## Section VII — Technical / Protocol Claims

These are evaluated against RFC text and established BGP/RPKI practice, not the audit data.

| Claim | Slide | RFC / Reference |
|---|---|---|
| RPKI has three route states: Valid, Invalid, NotFound | 4, 5 | RFC 6811 §2 |
| ROV drops Invalid routes; NotFound routes pass | 5 | RFC 6811 §5, RFC 7115 |
| A more-specific prefix wins by longest-match regardless of RPKI state | 19 | BGP longest-prefix-match (RFC 4271) |
| Without a covering ROA, ROV provides no protection against more-specific hijacks | 19 | RFC 6811 + RFC 8893 |
| ASPA is built on top of ROV — a non-ROV provider cannot enforce ASPV | 33 | RFC 9589 §5 |
| Valley-free Gao-Rexford constraint: (c→p)* → (peer)? → (p→c)* | 8 | Gao-Rexford 2001, RFC 7908 |
| IXP route servers strip their ASN from AS-paths per RFC 7947 | 9 | RFC 7947 §2.2.2 |
| RFC 9582 = ASPA Objects, RFC 9589 = ASPV Algorithm | 30 | Check publication status |

---

## Section VIII — Consistency Checks (internal to the deck)

| Check | Slides |
|---|---|
| Glass House definition is consistent: ROV enforcer with unsigned own prefixes | 4, 5, 19, 37 |
| Quadrant Q3 "Glass Houses" (unsigned customer base) vs slide 19 "Glass Houses" (unsigned own prefixes) — confirm audience won't conflate | 16, 19 |
| SITV networks appear in both holdout table (non-ROV transit) and SITV slide — confirm verdicts match | 15, 20 |
| AS9304 HGC appears in both holdout table (#41, cone 5,182) and SITV table (cone 5,182, 100% signed) — confirm these are consistent | 15, 20 |
| CERNET cone cited as 3,859 downstream networks (ASPA context) vs AS38255 in China slide — confirm same entity | 28, 32 |
| China 34.8% traffic protected on slide 28 vs 62.7% exposed — confirm these sum to ~97.5% and the gap is PARTIAL/other | 28 |

---

## How to run this verification

```bash
cd /home/terry/rov_audit
# Check a specific report file
cat reports/statistics.md | grep -A5 "CORE: ACTIVE"

# Spot-check impact score arithmetic (Lumen example)
python3 -c "print(73602 * 30138 / 1e9, 'Billion')"

# Check ASPA provider counts
python3 -c "
import json
data = json.load(open('data/downstream_graph.json'))
print('CERNET downstream count:', len(data.get('38255', [])))
"
```
