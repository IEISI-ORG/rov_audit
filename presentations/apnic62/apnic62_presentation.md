---
marp: true
theme: default
paginate: true
footer: APNIC-62 · Mumbai, India · September 2026 · tcs@ieisi.org
header: '![IEISI logo](https://www.ieisi.org/images/apac_logo.png)'
backgroundColor: "#ffffff"
color: "#333333"
style: |
  @import url('https://fonts.googleapis.com/css2?family=Roboto+Flex:opsz,wdth,wght@25..151,25..151,100..1000&display=swap&family=DM+Sans:wght@400;500;700&display=swap');
  header {
    position: absolute;
    top: 20px;
    right: 40px;
    padding: 0;
    height: 50px;
    display: flex;
    align-items: center;
  }
  header img {
    height: 40px;
    width: auto;
    margin: 8px;
  }
  section {
    font-family: 'DM Sans', sans-serif;
    font-size: 18px;
    line-height: 1.6;
    padding: 80px 60px 40px;
    background-color: #ffffff;
    color: #333333;
  }
  section h1 {
    font-family: 'Roboto Flex', sans-serif;
    font-variation-settings: 'wght' 800, 'wdth' 100, 'opsz' 144;
    color: #0F2C59;
    font-size: 2em;
    line-height: 1.05;
    border-bottom: 2px solid #1A5B8F;
    padding-bottom: 10px;
  }
  section h2 {
    font-family: 'Roboto Flex', sans-serif;
    font-variation-settings: 'wght' 700, 'wdth' 100, 'opsz' 36;
    color: #0F2C59;
    font-size: 1.4em;
    line-height: 1.3;
  }
---

# Global ROV Audit & Triangulation
### Measuring Internet Routing Security and "Herd Immunity"

**Presenter:** [Your Name]
**Organization:** IEISI
**Location:** APNIC-62, Mumbai, India
**Date:** September 2026

---

# The Problem: Route Leaks and Hijacks
- BGP remains vulnerable despite RPKI deployment.
- **Goal:** How do we measure the *actual* security of a network?
- **Passive vs. Active protection:** 
  - Are you filtering, or are you just lucky?

---

# Methodology: Zero-Scrape Architecture
- Performance-intensive BGP processing in **Go**.
- **Data Triangulation:**
  - BGP.Tools, APNIC Labs, RIPE RIS, RIPE Atlas.
- **The "Valley-Free" Model:**
  - Building a global dependency graph.

---

# The "Herd Immunity" Concept
- Calculating **Customer Cones** (Network Gravity).
- Quantifying how much global traffic is protected by the "Core."
- **Key Finding:** 40%+ of global traffic is affected by ROV regressions.

---

# Forensic Verification: RIPE Atlas
- Testing transit providers from the **Customer Cone**.
- Identifying **Filter Boundaries** and **Leak Paths**.
- Automating a 7-day forensic cycle.

---

# Case Study: The Regression of AS45355
- Digicel Fiji regression from 100% to ~1%.
- How the tool identifies and labels `REGRESSED` status.

---

# The RIR Dilemma: Policy vs. Security
- Even RIR infrastructure (APNIC AS4608/AS4777) remains `VULNERABLE`.
- **The Rationale:** Avoiding "Member Lockout" during ROA misconfiguration.
- **The Impact:** Regional infrastructure continues to propagate invalid routes.
- **Data:** Verified via Customer Cone forensics.

---

# Conclusion & Future Work
- Centralized classification of routing security.
- ASPA Maturity Modeling: The "Reality Gap."
- Future: BGP path validation at scale.

---

# Questions?
### [Your Name]
tcs@ieisi.org
https://github.com/IEISI-ORG/rov_audit
