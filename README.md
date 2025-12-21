# Global ROV Audit & Triangulation Tool (No-Scrape Edition)

**A comprehensive, non-scraping framework to audit RPKI Route Origin Validation (ROV) and ROA Signing adoption across the global internet, analyzing AS dependencies to measure true security.**

This project leverages robust data sources and a multi-stage analysis pipeline to determine:
1.  Which networks actively filter invalid routes.
2.  Which networks are protected by their upstreams ("clean pipes").
3.  Which networks are vulnerable to hijacks.
4.  The overall "herd immunity" status of the internet.

---

## ✨ Key Features

*   **No Web Scraping:** Relies entirely on public CSV/TSV dumps (BGP.Tools, Cloudflare, IPtoASN) and raw BGP RIS data (processed by Go).
*   **Go-Powered Topology:** Uses a custom Go tool for high-performance processing of the full BGP routing table to infer accurate AS relationships (Provider-Customer).
*   **Multi-Source Validation:** Integrates data from BGP.Tools (ROV Tags), Cloudflare (Safe List), APNIC Labs (Measurement Probes), and RIPE Atlas (Active Verification).
*   **Dependency-Aware Audit:** Classifies ASNs based on their own ROV status AND the status of their upstream providers.
*   **Herd Immunity Analysis:** Assesses global ROV adoption by focusing on the protection level of the core internet transit networks.
*   **Resilient Caching:** All fetched external data is cached locally to minimize downloads and maximize speed on subsequent runs.

---

## 🚀 Quick Start Workflow

Follow these steps to generate the full audit report and analyses.

### 1. **Initial Setup (Once)**

```bash
# Clone the repository
git clone https://github.com/yourusername/rov_audit.git
cd rov_audit

# Create data directories
mkdir -p data/apnic data/parsed data/html output

# Install Python dependencies
pip install pandas requests beautifulsoup4 pyyaml ripe.atlas.cousteau

# Install Go (if not already installed)
# Download from https://golang.org/dl/ or use your package manager.

# Compile the Go BGP Relationship Extractor
go build -o bgp-extractor go-bgp-relationships.go.txt

# Compile the Go Cone Calculator (for accurate Cone Sizes)
go build -o cone-calculator cone-calculator-v2.go


