# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a **BGP/RPKI Route Origin Validation (ROV) audit toolkit**. It audits Autonomous System Numbers (ASNs) globally to determine whether networks are filtering invalid RPKI routes (i.e., protecting the internet from BGP hijacks). Results have been presented at IETF.

## Dependencies

No `requirements.txt` exists. Key libraries used across scripts:
- `pandas`, `numpy`, `requests`, `beautifulsoup4` (bs4)
- `ripe.atlas.cousteau` (for RIPE Atlas measurements)
- `yaml` (for `secrets.yaml` API key)

Install with: `pip install pandas numpy requests beautifulsoup4 ripe-atlas-cousteau pyyaml`

## Data Pipeline (Ordered Workflow)

### Step 1: Collect bgp.tools HTML per ASN
```bash
# Single ASN (also fetches fresh APNIC data for that country):
python3 scrape_single_asn_v2.py <ASN>

# Bulk scrape missing ASNs (cross-references APNIC cache for targets):
python3 scrape_apnic_connectivity.py
```
Output: `data/html/as_<ASN>.html`

### Step 2: Parse HTML into structured JSON
```bash
python3 bulk_html_parser_v2.py
```
Output: `data/parsed/as_<ASN>.json`

### Step 3: Update APNIC RPKI score cache
```bash
python3 update_apnic_data.py <audit_csv>         # respects 24h TTL
python3 update_apnic_data.py <audit_csv> --force  # force refresh all
```
Output: `data/apnic/<CC>.json` (keyed by country code)

### Step 4: Run the global audit
```bash
python3 rov_global_audit_v12.py   # current production version
```
Output: `rov_audit_v12.csv`

### Step 5: Statistical summary
```bash
python3 statistics.py rov_audit_v12.csv
```

### Step 6 (Optional): RIPE Atlas active verification
```bash
# Find high-value vulnerable targets not yet tested:
python3 find_atlas_targets.py rov_audit_v12.csv --limit 20

# Actively verify ROV behavior via traceroute (requires secrets.yaml):
python3 verify_path_ripe_native.py <target_asn> --proxy-asn <customer_asn>
```
Output: `data/atlas/as_<ASN>_via_<proxy_asn>_trace.json`

## Data Directory Structure

| Directory | Contents |
|-----------|----------|
| `data/html/` | Raw HTML pages from bgp.tools (`as_<ASN>.html`) |
| `data/parsed/` | Parsed JSON per ASN (`as_<ASN>.json`) |
| `data/apnic/` | APNIC RPKI score cache per country (`<CC>.json`) — 24h TTL |
| `data/atlas/` | RIPE Atlas traceroute results (`as_<ASN>.json` or `as_<ASN>_via_<proxy>_trace.json`) |
| `data/asns.csv` | ASN metadata (name, country) from bgp.tools/asns.csv |

## Verdict Categories (rov_global_audit_v12.py)

- **SECURE (Full Coverage)** — all upstreams are in the ROV set
- **SECURE (Active Local ROV)** — network itself does ROV (APNIC score ≥ 95%)
- **PARTIAL (Mixed Feeds)** — some but not all upstreams are ROV-capable
- **VULNERABLE (No Coverage)** — no upstreams filtering invalid routes
- **CORE: PROTECTED / UNPROTECTED** — Tier 1 network (hardcoded set in `KNOWN_TIER_1`)
- **IXP / Peer / Stub** — no upstreams (transit-free or edge node)
- **DEAD / INACTIVE** — no connectivity data and unknown country

## Configuration

- `secrets.yaml` — stores `ripe_atlas_key` for Atlas measurement API
- `KNOWN_TIER_1` set in `rov_global_audit_v12.py` — hardcoded list of Tier 1 ASNs
- An ASN is considered "safe" if it appears in bgp.tools `rpkirov.csv` tag OR has APNIC score ≥ 95%

## Script Versioning

Many scripts have `_v2`, `_v12` etc. suffixes. Always use the highest-versioned variant unless debugging an earlier stage. The authoritative analysis script is `rov_global_audit_v12.py`.

## Presentation

`ietf_presentation.md` and `ietf_presentation.html` are a Marp-format slide deck. Render with the Marp CLI or VS Code Marp extension.

## IEISI Presentation Style (Standing Order)

All presentations created for or on behalf of IEISI **must** follow the IEISI Brand Style Guide (source: https://www.ieisi.org/ieisi-style-guide). Apply these rules to any Marp slide deck, HTML presentation, or other visual output.

### Colors

| Role | Name | Hex |
|------|------|-----|
| Primary (headings, hero backgrounds) | Deep Corporate Blue | `#0F2C59` |
| Secondary (borders, supporting elements) | IEISI Blue | `#1A5B8F` |
| Accent (CTAs, emphasis) | Action Red | `#D94838` |
| Accent hover/active | — | `#C0392B` |
| Footer / darkest background | Midnight | `#081832` |
| Alternating section background | Cloud | `#F8F9FA` |
| Body text | Charcoal | `#333333` |
| Secondary text | Slate | `#666666` |
| Navigation text | — | `#2C3E50` |
| Fine print / copyright | Ash | `#888888` |

Recommended proportions: Primary 50%, Secondary 20%, Accent 10%, Neutral 15%, Text 5%.

### Typography

- **Primary font:** Roboto Flex (Google variable font) — `--font-main`
- **Body font:** DM Sans
- **H1 headings:** wght 800, wdth 100, opsz 144 — 3rem, line-height 1.05
- **H2 headings:** wght 700, wdth 100, opsz 36 — 1.8rem, line-height 1.3
- **H3 headings:** wght 700, wdth 100, opsz 36 — 1.2rem, line-height 1.3
- **Body text:** wght 400, wdth 100, opsz 14 — 1rem, line-height 1.6
- **Navigation / labels:** wght 500, wdth 100, opsz 14 — 0.8rem
- **Small / fine print:** 0.9rem

Heading color rule: h1–h3 use `#0F2C59` on light backgrounds; white (`#FFFFFF`) on dark backgrounds.

### Logo

- Maintain clear space equal to the cap-height of "I" on all sides.
- Use the APAC logo graphic alongside the wordmark.
- Never stretch, rotate, add drop shadows, or substitute a different typeface.
- Avoid low-resolution versions.

### Voice & Tone

- **Be:** Authoritative, direct, principled, human (first-person where appropriate).
- **Use:** governance, stewardship, operational discipline, capability building, ecosystem mindset, evidence-based, mission-critical, independent oversight.
- **Avoid:** synergy, thought leader, disruptive, best-in-class, pivot, paradigm shift.

### Components & Layout

- **Cards/callout boxes:** 4px top or left border in Secondary (`#1A5B8F`), subtle shadow.
- **Pull quotes:** 4px left border in `#1A5B8F`, 20px padding-left.
- **Buttons / accent elements:** `#D94838` fill, 4px border-radius.
- **Max content width:** 1100px; section padding 80px desktop / 50px tablet.

### Accessibility

Minimum contrast ratios (WCAG 2.1 AA required, AAA preferred):
- White on Primary `#0F2C59`: 12.63:1 (AAA)
- White on Accent `#D94838`: 4.56:1 (AA)
- Charcoal `#333333` on white: 12.63:1 (AAA)
