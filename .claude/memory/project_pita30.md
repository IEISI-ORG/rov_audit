---
name: PITA 30 presentation
description: User is presenting at PITA 30 (Pacific Islands Telecommunications Association), April 13-17 2026, Cook Islands
type: project
---

User is presenting a C-suite/executive adoption talk at PITA 30 on routing security and RPKI.

**Session**: "Routing Security risk for C-suite & Managers" — why executive decisions drive cybersecurity resilience, why RPKI matters for Pacific network stability.

**Deck**: `pita30_presentation.md` (Marp format, same style as ietf_presentation.md)

**Why:** Business/adoption talk, not technical. Audience is CEOs and managers of Pacific telecom operators and ISPs.

**How to apply:** When working on this presentation, keep language non-technical, focus on business risk (financial fraud, service disruption, regulatory pressure), and use Pacific-specific audit data. Real incident to reference: April 2018 Amazon Route 53 BGP hijack (~$150k stolen from MyEtherWallet).

**Key Pacific data points (from rov_audit_v12.csv):**
- Most major Pacific ISPs are VULNERABLE (Digicel Fiji/PNG/Samoa/Tonga, Telecom Fiji, Solomon Telekom, FSM Telecom)
- Tonga Communications (AS38201) is the Pacific leader: SECURE (Active Local ROV), APNIC score 98.27%
- Orange Wallis & Futuna (AS45879): SECURE (Full Coverage), 100% signing
- OPT New Caledonia (AS18200): SECURE (Full Coverage)
- Vodafone Fiji (AS38442): PARTIAL
- PNG DATACO (AS17828): PARTIAL
