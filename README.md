# Global ROV Audit & Triangulation Tool

**A research framework to analyze the true state of RPKI Route Origin Validation (ROV) adoption across the global internet.**

This project moves beyond simple "Is ROV enabled?" lists by analyzing the **upstream connectivity graph**. It determines if a network is protected actively (by its own routers) or passively (by "clean pipe" inheritance from secure upstream providers).

## 🚀 Key Capabilities

*   **Data Triangulation:** Combines data from **BGP.Tools** (Topology/Tags), **APNIC Labs** (Measurement Probes), and **Cloudflare** (Community Data).
*   **Deep Dependency Analysis:** Scrapes and maps upstream transit providers to determine "Inherited Protection."
*   **Vulnerability Detection:** Identifies "Vulnerable Giants" — large ISPs with non-ROV upstream feeds and no local protection.
*   **"Dead" Network Filtering:** Automatically detects and excludes inactive ASNs (Zero Cone, No Peers, No Country) to clean research stats.
*   **Resilient Caching:** Implements a robust local caching system (HTML & JSON) to minimize network load and adhere to scraping etiquette.

---

## 📊 Data Sources & Methodology

The tool classifies every ASN into one of several security states based on the following logic:

### 1. The Inputs
| Source | Purpose | Method |
| :--- | :--- | :--- |
| **BGP.Tools** | Connectivity Graph (Upstreams/Downstreams), Tier 1 Status, Country Data. | HTML Scraping & CSV Dumps |
| **APNIC Labs** | Real-world measurement of invalid route rejection (Scores >95%). | JSON/JS Extraction |
| **Cloudflare** | "Is BGP Safe Yet" operator list for validation. | CSV Import |

### 2. The Verdict Logic
The script audits every ASN and assigns a verdict:

*   **🟢 SECURE (Active Local ROV):** The network has "Dirty" (Non-ROV) upstreams but actively filters invalids itself (Verified by APNIC >95%).
*   **🟢 SECURE (Full Coverage):** The network may not filter locally, but **100%** of its upstream providers are confirmed secure. It inherits a "Clean Pipe."
*   **🟡 PARTIAL (Mixed Feeds):** The network has a mix of Secure and Insecure upstreams and does not filter locally.
*   **🔴 VULNERABLE (No Coverage):** The network has dirty upstreams and performs no local filtering.
*   **🔴 CORE: UNPROTECTED:** A Tier 1 or Global Core network that is not filtering.
*   **💀 DEAD / INACTIVE:** An ASN with no cone, no upstreams, and no routed prefixes (Excluded from stats).

---

## 📂 Project Structure

```text
rov_coverage/
├── data/
│   ├── html/          # Raw cached HTML files from bgp.tools
│   ├── parsed/        # Processed JSON files (Metadata, Connectivity, Status)
│   ├── apnic/         # Cached country-level stats from APNIC Labs
│   └── asns.csv       # Global ASN metadata cache
├── scrape_single_asn.py        # Surgical scraper for specific ASNs
├── bulk_html_parser.py         # Converts raw HTML cache to structured JSON
├── rov_global_audit_v10.py     # Main analysis engine (Generates the report)
├── requirements.txt            # Python dependencies
└── README.md                   # This file

---

## Notes / TODO

* Cached data is not refreshed often or at all
* There are false negatives and positives: submit an issue to tell me!
* Fork and contribute as collaborate is very welcome.



