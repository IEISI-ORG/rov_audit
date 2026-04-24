# CLAUDE.md

This file provides guidance to Claude Code when working with the **Global ROV Audit & Triangulation Tool**.

## Project Overview
A toolkit for auditing RPKI Route Origin Validation (ROV) and ROA Signing adoption using BGP dependency analysis ("Herd Immunity").

## Core Architecture
- **Go:** Performance-intensive topology processing (`bgp-extractor.go`, `cone-calculator.go`).
- **Python:** Data gathering, audit engine, and analysis.
- **Shared Utilities:** `rov_utils.py` contains all common logic for data fetching, metadata loading, and topology ingestion.

## Key Files
- `TODO.md`: Tracked tasks and identified regressions to investigate.
- `rov_utils.py`: Central utility module (Authoritative for constants and paths).
- `rov_no_scrape_v21.py`: Main audit engine (produces `rov_audit_v21_final.csv`).
- `statistics_v6.py`: Global statistical summary.
- `do_data_gathering`: Shell script for the Go/Data pipeline.
- `do_reports`: Shell script for generating all audit reports.

## Dependencies
`pip install pandas numpy requests beautifulsoup4 ripe-atlas-cousteau pyyaml`

## Standardized Columns (Audit CSV)
- `asn`: Autonomous System Number
- `verdict`: Safety category (REGRESSED, SECURE, VULNERABLE, VOLATILE, UNRELIABLE, etc.)
- `atlas_result`: RIPE Atlas active verification verdict (Standardized).
- `cone`: Customer cone size (weight).

## Verdict Classification
The toolkit uses a centralized classification system in `rov_utils.py`:
- **SECURE**: `ACTIVE`, `PASSIVE`, `PROTECTOR`, `VOLATILE` (Safe states).
- **VULNERABLE**: `REGRESSED`, `UNRELIABLE`, `UNPROTECTED`, `VULNERABLE` (High-risk states).
- **PARTIAL**: Mixed upstream environments.
- **Priority**: `REGRESSED` and `UNRELIABLE` (Volatility in vulnerable states) take priority as `VULNERABLE`.
- **Sorting**: `NOT ROUTED` and `Unverified` are pushed to the bottom of statistical reports.

## Versioning Policy
- New major logic updates should increment the version suffix (e.g., `v21` -> `v22`).
- Legacy versions must be moved to the `old/` directory.
- Avoid code duplication by utilizing `rov_utils.py`.
