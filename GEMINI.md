# GEMINI.md

## Project Overview
The **Global ROV Audit & Triangulation Tool** is a high-performance framework designed to measure RPKI Route Origin Validation (ROV) and ROA Signing adoption across the global internet. It uses deep dependency analysis and a "Valley-Free" routing inference model to quantify "Herd Immunity" and identify routing security regressions.

### Main Technologies
- **Go 1.20+**: High-performance BGP path processing and topology calculation.
- **Python 3.10+**: Data triangulation, statistical analysis, and forensic automation.
- **RIPE Atlas**: Active measurement and forensic verification via a global probe network.
- **Data Sources**: BGP.Tools, APNIC Labs, RIPE RIS, RIPEstat, and Cloudflare.

### Core Architecture
1.  **Topology Engine**: Processes raw BGP MRT dumps to build a global relationship graph.
2.  **Audit Pipeline**: Triangulates multiple security signals to assign safety verdicts to every routed ASN.
3.  **Forensic Layer**: Uses RIPE Atlas to verify data-plane behavior from the perspective of downstream customer cones.
4.  **Reporting**: Generates global, country-specific, and strategic (e.g., ASPA, ROA Strategy) reports.

---

## Building and Running

### 1. Prerequisites
- **bgpdump**: Required for MRT file extraction.
- **Python Dependencies**: `pip install pandas numpy requests pyyaml ruff`
- **Go**: Version 1.20 or later.

### 2. Key Commands
- **Full Data Sync**: `bash do_data_gathering` (Runs the full pipeline from topology to packing).
- **Generate Reports**: `bash do_reports` (Runs all analysis scripts and generates markdown/HTML reports).
- **Compile Go Tools**: `make build` (Compiles `bgp-extractor`, `cone-calculator`, and `fetch-roa`).
- **Policy Integrity Check**: `python3 tests/test_policy_integrity.py` (Verifies foundational routing security assumptions).
- **Smart Forensic Test**: `python3 verify_forensic_smart.py [ASN]` (Tests a provider from its customer cone).
- **ASN Lookup**: `python3 query_asn.py [ASN]` (High-performance query of the packed dataset).

---

## Development Conventions

### 1. Safety Verdicts & Classification
All scripts MUST use the centralized classification logic in `rov_utils.py`:
- **`SECURE`**: Actively filtering (`ACTIVE`) or protected by upstreams (`PASSIVE`).
- **`PARTIAL`**: Mixed upstream environment.
- **`VULNERABLE`**: High-risk states, specifically including `REGRESSED` and `UNRELIABLE`.
- **Infrastructure**: Regional Internet Registries (RIRs) and Root Servers are blacklisted from transit metrics via the `isNonTransit` logic in `cone-calculator.go`.

### 2. Performance & Storage
- **Packed Data**: Individual ASN JSON files in `data/parsed/` are consolidated into `data/as_data.jsonl.gz`. 
- **Ingestion**: Use `rov_utils.load_all_asn_data()` for high-performance loading (<1s).
- **Caching**: All external APNIC Labs and RIPE Atlas fetches follow a **7-day TTL** policy.

### 3. Versioning & Organization
- **logic Updates**: Major logic updates increment the version suffix (e.g., `v21` -> `v22`).
- **Legacy Code**: Archived versions are kept in the `old/` directory.
- **CI**: Every commit is verified via `.github/workflows/ci.yml` for technical correctness (lint/build) and policy correctness (integrity tests).

---

## Key Files
- `rov_utils.py`: Shared library for data loading, classification, and topology ingestion.
- `rov_no_scrape_v21.py`: Main global audit engine.
- `cone-calculator.go`: Go implementation of the Valley-Free topology and Customer Cone logic.
- `sync_transit_timeseries.py`: Proactive regression scanner.
- `triangulate_top_giants.py`: Multi-perspective RIPE Atlas forensic tool.
- `TODO.md`: Central tracker for pending tasks and architectural roadmaps.
