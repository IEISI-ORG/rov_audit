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
*   **Disk Space:** ~2GB (For raw BGP table dumps and JSON caches)

### 2. Python Dependencies
```bash
pip install pandas requests beautifulsoup4 pyyaml ripe.atlas.cousteau
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

### Phase 1: Build the Internet Topology (Go)
We use raw BGP data from RIPE RIS to determine who provides transit to whom.

1.  **Compile the Tool:**
    ```bash
    go build -o bgp-extractor go-bgp-relationships.go.txt
    go build -o cone-calculator cone-calculator-v2.go
    ```

2.  **Download & Process:**
    ```bash
    # Download latest RIB (~400MB)
    wget http://data.ris.ripe.net/rrc00/latest-bview.gz

    # Extract Relationships
    bgpdump -m latest-bview.gz | ./bgp-extractor -input /dev/stdin -output output -workers 16

    # Calculate Customer Cones (The "Gravity" of each network)
    ./cone-calculator -input output/relationships.csv -output final_as_rank.csv -top 0
    ```

### Phase 2: Data Ingestion (Python)
We hydrate the topology with metadata, geolocation, and passive security scores.

1.  **Fetch Metadata & APNIC Scores:**
    ```bash
    python3 rov_no_scrape_v17.py
    ```
    *Builds `data/parsed/*.json` with Country Codes, Names, and Validation Scores.*

2.  **Fetch ROA Signing Stats (Aggregated):**
    ```bash
    python3 fetch_roa_bulk_async_v5_aggregated.py
    ```
    *Fetches global signing percentages for all 80k+ ASNs, correcting for APNIC's per-country data fragmentation.*

### Phase 3: The Audit
Generate the master report.

```bash
python3 rov_global_audit_v18.py
```
*   **Input:** Topology, Metadata, APNIC Cache, Atlas Results.
*   **Output:** `rov_audit_v18_final.csv`.
*   **Logic:** Determines if a network is `SECURE`, `VULNERABLE`, or `PARTIAL` based on its own status **AND** its upstream providers.

### Phase 4: Forensics & Analysis
Now that we have the map, we analyze it.

1.  **Check Herd Immunity:**
    ```bash
    python3 analyze_herd_immunity.py
    ```
    *Reports what % of global traffic is protected by the Core.*

2.  **Check Signing Hygiene:**
    ```bash
    python3 analyze_roa_signing.py
    ```
    *Identifies "Glass Houses" (Networks that filter others but don't sign their own routes).*

3.  **Active Target Hunting (RIPE Atlas):**
    Find "Unknown" giants and test them.
    ```bash
    # Find targets
    python3 find_atlas_targets.py rov_audit_v18_final.csv

    # Run Forensic Trace (Trace Valid vs Invalid path)
    python3 verify_forensic_path_v2.py [TARGET_ASN]
    ```
    *If you verify a network, re-run `rov_global_audit_v18.py` to integrate the findings.*

---

## 📂 File Manifest

| File | Description |
| :--- | :--- |
| `rov_global_audit_v18.py` | **Main Engine.** Generates the final CSV audit. |
| `fetch_roa_bulk_async_v5...py` | Mass-fetches ROA signing stats (handling aggregations). |
| `verify_forensic_path_v2.py` | Active RIPE Atlas tool. Compares Valid vs Invalid traceroutes. |
| `analyze_herd_immunity.py` | Calculates global protection statistics based on Cone Weight. |
| `analyze_cone_quality_v3.py` | Deep recursion to find "Toxic" vs "Clean" upstream providers. |
| `go-bgp-relationships.go` | High-performance Go tool to parse MRT/BGP dumps. |
| `cone-calculator-v2.go` | Go tool to implement "Valley-Free" logic and calculate cones. |

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
