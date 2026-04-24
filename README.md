# Global ROV Audit & Triangulation Tool

**A comprehensive framework to audit RPKI Route Origin Validation (ROV) and ROA Signing adoption across the global internet, using deep dependency analysis to measure "Herd Immunity."**

This project moves beyond simple "Is ROV enabled?" lists. It builds a full dependency graph of the internet to determine if a network is protected actively (by its own routers) or passively (by "clean pipe" inheritance from secure upstream providers). It also performs forensic active verification using RIPE Atlas probes to confirm if "Unverified" giants are actually leaking invalid routes.

[![License: CC BY-NC 4.0](https://img.shields.io/badge/License-CC%20BY--NC%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by-nc/4.0/)

---

## 🚀 Key Capabilities

*   **Zero-Scrape Architecture:** Relies on public bulk datasets (RIPE RIS, BGP.Tools CSVs, APNIC JSON API) to respect server load and ensure speed.
*   **Go-Powered Topology:** Uses a custom Go tool to process the raw 400MB+ BGP Routing Table in seconds, inferring provider/customer relationships via "Valley-Free" logic.
*   **Data Triangulation:** Cross-references data from **BGP.Tools**, **APNIC Labs**, **Cloudflare**, and **RIPEstat** to detect false positives.
*   **Forensic Verification:** Automates **RIPE Atlas** traceroutes to "attack" specific networks with Invalid packets, proving definitively if they filter or leak.
*   **Herd Immunity Analysis:** Calculates how much of the global internet traffic is protected by the "Core" (Tier 1s) regardless of local ISP configuration.

---

## 🛠️ Prerequisites

### 1. System Requirements
*   **Python 3.10+**
*   **Go 1.19+** (For the topology processor)
*   **bgpdump** (For BGP MRT dump extraction)
*   **Disk Space:** ~2GB (For raw BGP table dumps and JSON caches)

### 2. Python Dependencies
```bash
pip install pandas numpy requests beautifulsoup4 pyyaml ripe.atlas.cousteau
```

### 3. API Keys (Optional but Recommended)
To use the **Active Forensic** tools, you need a RIPE Atlas API key.
Create a file named `secrets.yaml` in the root directory (added to `.gitignore`):

```yaml
# secrets.yaml
ripe_atlas_key: "YOUR_UUID_HERE" 
```

---

## ⚙️ Usage Workflow

The two shell scripts `do_data_gathering` and `do_reports` automate the full pipeline. Run them in order.

### Phase 1: Build the Internet Topology (Go)
We use raw BGP data from RIPE RIS to determine who provides transit to whom.

1.  **Compile the Tools:**
    ```bash
    go build -o bgp-extractor bgp-extractor.go
    go build -o cone-calculator cone-calculator.go
    go build -o fetch-roa fetch-roa.go
    ```

2.  **Download & Process** (via `do_data_gathering`):
    ```bash
    # Download latest RIB (~400MB)
    wget http://data.ris.ripe.net/rrc00/latest-bview.gz

    # Extract Relationships
    bgpdump -m latest-bview.gz | ./bgp-extractor -input /dev/stdin -output output -workers 16

    # Calculate Customer Cones (The "Gravity" of each network)
    ./cone-calculator -input output/relationships.csv -output final_as_rank.csv -top 0

    # Fetch ROA signing stats for all ASNs (Fast Go implementation)
    python3 do_roa_sync.py
    ```

### Phase 2: The Audit
Generate the master report (via `do_reports`):

```bash
python3 rov_no_scrape_v21.py
```
*   **Input:** Topology (`final_as_rank.csv`), parsed ASN data (`data/parsed/`), APNIC cache (`data/apnic/`), Atlas results (`data/atlas/`).
*   **Output:** `rov_audit_v21_final.csv`
*   **Logic:** Determines if a network is `SECURE`, `VULNERABLE`, or `PARTIAL` based on its own status **AND** its upstream providers.

### Phase 3: Analysis
Run all analysis scripts (via `do_reports`):

```bash
python3 analyze_roa_signing_v2.py       # "Glass Houses" — filters but doesn't sign
python3 analyze_herd_immunity_v2.py     # % of global traffic protected by Core
python3 analyze_roa_strategy_v3.py      # ROA signing strategy recommendations
python3 analyze_aspa_readiness.py       # ASPA deployment readiness
python3 statistics_v6.py               # Summary statistics
```

Country deep-dives:
```bash
python3 analyze_country_deep_dive_v2.py <CC>   # e.g. FJ, PG, WS, CK
```

### Phase 4: Forensics (RIPE Atlas)
Find and actively verify unknown/unverified networks:

```bash
# Find high-value targets not yet tested
python3 find_atlas_targets.py rov_audit_v21_final.csv --limit 20

# Run forensic trace (Valid vs Invalid path comparison)
python3 verify_forensic_path_v2.py [TARGET_ASN]
```
*Requires `secrets.yaml` with a RIPE Atlas API key. Use `Makefile` to compile helper tools if needed.*

---

## 🛡️ Safety Verdicts

The tool categorizes networks using a standardized classification engine (`rov_utils.classify_verdict`):

| Category | Primary Verdicts | Description |
| :--- | :--- | :--- |
| 🔴 **VULNERABLE** | `REGRESSED`, `UNRELIABLE`, `VULNERABLE` | High-risk: Either leaking routes, has "dirty" upstreams, or shows a regression in security status. |
| 🟡 **PARTIAL** | `PARTIAL: VULNERABLE (Mixed)` | Inconsistent: Has a mix of clean and dirty upstream feeds. |
| 🟢 **SECURE** | `ACTIVE LOCAL ROV`, `PASSIVE (Clean Pipe)`, `VOLATILE` | Safe: Actively filtering or inherited protection from clean providers. |

*Note: `NOT ROUTED` and `Unverified` are considered low-priority and are moved to the bottom of all statistical reports.*

---

## 📂 File Manifest

| File | Description |
| :--- | :--- |
| `do_data_gathering` | Shell script — runs full data collection pipeline |
| `do_reports` | Shell script — runs audit and all analysis/reporting |
| `do_roa_sync.py` | Python wrapper for fast ROA signing data sync |
| `rov_no_scrape_v21.py` | **Main audit engine.** Generates `rov_audit_v21_final.csv` |
| `statistics_v6.py` | Summary statistics from the audit CSV |
| `analyze_herd_immunity_v2.py` | Global protection stats based on Cone Weight |
| `analyze_roa_signing_v2.py` | Identifies "Glass Houses" |
| `analyze_roa_strategy_v3.py` | ROA signing strategy recommendations |
| `analyze_aspa_readiness.py` | ASPA deployment readiness analysis |
| `analyze_cone_quality_v2.py` | Upstream provider quality analysis |
| `analyze_country_deep_dive_v2.py` | Per-country detailed report |
| `verify_forensic_path_v2.py` | Active RIPE Atlas tool — Valid vs Invalid traceroutes |
| `find_atlas_targets.py` | Identifies best candidates for active verification |
| `TODO.md` | Tracked tasks, identified regressions, and feature requests |
| `reports/` | Directory containing generated audit reports (CC-named) |
| `reports/old/` | Archive for legacy or non-standardized reports |
| `bgp-extractor.go` | Go source — parses MRT/BGP dumps |
| `cone-calculator.go` | Go source — Valley-Free logic, calculates customer cones |
| `fetch-roa.go` | Go source — Fast multi-threaded ROA status fetcher |

---

## 📜 License & Attribution

**This project is licensed under [CC BY-NC 4.0](https://creativecommons.org/licenses/by-nc/4.0/).**

### Summary
*   **You are free to:** Share and Adapt this work.
*   **You must:** Give appropriate credit (Attribution).
*   **You cannot:** Use this work for commercial purposes.

### ✍️ Citation
If you use this tool or the data generated for research, presentations, or public analysis, please cite it as:

> **"Global ROV Audit & Triangulation Tool"**  
> *A framework for measuring Internet Routing Security via Dependency Analysis.*
> https://github.com/IEISI-ORG/rov_audit
