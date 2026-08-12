# RPKI RFC Reading List

Reproduced from the archived [RPKI RFCs Graph](https://web.archive.org/web/20220727163730/https://rpki-rfc.routingsecurity.net/) (`rpki-rfc.routingsecurity.net`), a curated RFC reading-dependency map for RPKI/BGP routing security. The original site is no longer live; this reproduction is sourced from the Wayback Machine snapshot at `2022-07-27T16:37:30Z` (nearest available crawl to the `2022-07-24T03:17:23Z` page snapshot originally noted in TODO.md — the underlying data file wasn't crawled at that exact timestamp, but the dataset is effectively unchanged between the two).

This is a **faithful reproduction of the 2022 snapshot only** — RFCs published since then (e.g. ASPA, RFC 9582) are deliberately not included here. If this list is extended later, track that as a separate TODO item.

Tiers reflect the original site's reading-priority curation, not this project's own assessment.

## Must Read (6)

| RFC | Title | Category | Date |
|---|---|---|---|
| [RFC 4271](https://tools.ietf.org/html/rfc4271) | A Border Gateway Protocol 4 (BGP-4). Ed., Ed., Ed. | PROPOSED STANDARD | January 2006 |
| [RFC 6480](https://tools.ietf.org/html/rfc6480) | An Infrastructure to Support Secure Internet Routing | INFORMATIONAL | February 2012 |
| [RFC 6482](https://tools.ietf.org/html/rfc6482) | A Profile for Route Origin Authorizations (ROAs) | PROPOSED STANDARD | February 2012 |
| [RFC 6811](https://tools.ietf.org/html/rfc6811) | BGP Prefix Origin Validation | PROPOSED STANDARD | January 2013 |
| [RFC 7128](https://tools.ietf.org/html/rfc7128) | Resource Public Key Infrastructure (RPKI) Router Implementation Report | INFORMATIONAL | February 2014 |
| [RFC 8897](https://tools.ietf.org/html/rfc8897) | Requirements for Resource Public Key Infrastructure (RPKI) Relying Parties | INFORMATIONAL | September 2020 |

## Should Read (15)

| RFC | Title | Category | Date |
|---|---|---|---|
| [RFC 6483](https://tools.ietf.org/html/rfc6483) | Validation of Route Origination Using the Resource Certificate Public Key Infrastructure (PKI) and Route Origin Authorizations (ROAs) | INFORMATIONAL | February 2012 |
| [RFC 6484](https://tools.ietf.org/html/rfc6484) | Certificate Policy (CP) for the Resource Public Key Infrastructure (RPKI) | BEST CURRENT PRACTICE | February 2012 |
| [RFC 6489](https://tools.ietf.org/html/rfc6489) | Certification Authority (CA) Key Rollover in the Resource Public Key Infrastructure (RPKI) | BEST CURRENT PRACTICE | February 2012 |
| [RFC 6493](https://tools.ietf.org/html/rfc6493) | The Resource Public Key Infrastructure (RPKI) Ghostbusters Record | PROPOSED STANDARD | February 2012 |
| [RFC 6810](https://tools.ietf.org/html/rfc6810) | The Resource Public Key Infrastructure (RPKI) to Router Protocol | PROPOSED STANDARD | January 2013 |
| [RFC 6907](https://tools.ietf.org/html/rfc6907) | Use Cases and Interpretations of Resource Public Key Infrastructure (RPKI) Objects for Issuers and Relying Parties | INFORMATIONAL | March 2013 |
| [RFC 6916](https://tools.ietf.org/html/rfc6916) | Algorithm Agility Procedure for the Resource Public Key Infrastructure (RPKI) | BEST CURRENT PRACTICE | April 2013 |
| [RFC 6945](https://tools.ietf.org/html/rfc6945) | Definitions of Managed Objects for the Resource Public Key Infrastructure (RPKI) to Router Protocol | PROPOSED STANDARD | May 2013 |
| [RFC 7115](https://tools.ietf.org/html/rfc7115) | Origin Validation Operation Based on the Resource Public Key Infrastructure (RPKI) | BEST CURRENT PRACTICE | January 2014 |
| [RFC 7909](https://tools.ietf.org/html/rfc7909) | Securing Routing Policy Specification Language (RPSL) Objects with Resource Public Key Infrastructure (RPKI) Signatures | PROPOSED STANDARD | June 2016 |
| [RFC 8183](https://tools.ietf.org/html/rfc8183) | An Out-of-Band Setup Protocol for Resource Public Key Infrastructure (RPKI) Production Services | PROPOSED STANDARD | July 2017 |
| [RFC 8210](https://tools.ietf.org/html/rfc8210) | The Resource Public Key Infrastructure (RPKI) to Router Protocol, Version 1 | PROPOSED STANDARD | September 2017 |
| [RFC 8481](https://tools.ietf.org/html/rfc8481) | Clarifications to BGP Origin Validation Based on Resource Public Key Infrastructure (RPKI) | PROPOSED STANDARD | September 2018 |
| [RFC 8608](https://tools.ietf.org/html/rfc8608) | BGPsec Algorithms, Key Formats, and Signature Formats | PROPOSED STANDARD | June 2019 |
| [RFC 8630](https://tools.ietf.org/html/rfc8630) | Resource Public Key Infrastructure (RPKI) Trust Anchor Locator | PROPOSED STANDARD | August 2019 |

## May Read (42)

| RFC | Title | Category | Date |
|---|---|---|---|
| [RFC 1771](https://tools.ietf.org/html/rfc1771) | A Border Gateway Protocol 4 (BGP-4) | DRAFT STANDARD | March 1995 |
| [RFC 2425](https://tools.ietf.org/html/rfc2425) | A MIME Content-Type for Directory Information | PROPOSED STANDARD | September 1998 |
| [RFC 2426](https://tools.ietf.org/html/rfc2426) | vCard MIME Directory Profile | PROPOSED STANDARD | September 1998 |
| [RFC 2622](https://tools.ietf.org/html/rfc2622) | Routing Policy Specification Language (RPSL) | PROPOSED STANDARD | June 1999 |
| [RFC 2739](https://tools.ietf.org/html/rfc2739) | Calendar Attributes for vCard and LDASmall, January 2000 [^data-quality] | PROPOSED STANDARD | January 2000 |
| [RFC 3779](https://tools.ietf.org/html/rfc3779) | X.509 Extensions for IP Addresses and AS Identifiers | PROPOSED STANDARD | June 2004 |
| [RFC 4012](https://tools.ietf.org/html/rfc4012) | Routing Policy Specification Language next generation (RPSLng) | PROPOSED STANDARD | March 2005 |
| [RFC 4770](https://tools.ietf.org/html/rfc4770) | vCard Extensions for Instant Messaging (IM). Ed. | PROPOSED STANDARD | January 2007 |
| [RFC 5280](https://tools.ietf.org/html/rfc5280) | Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile | PROPOSED STANDARD | May 2008 |
| [RFC 6286](https://tools.ietf.org/html/rfc6286) | Autonomous-System-Wide Unique BGP Identifier for BGP-4 | PROPOSED STANDARD | June 2011 |
| [RFC 6350](https://tools.ietf.org/html/rfc6350) | vCard Format Specification | PROPOSED STANDARD | August 2011 |
| [RFC 6481](https://tools.ietf.org/html/rfc6481) | A Profile for Resource Certificate Repository Structure | PROPOSED STANDARD | February 2012 |
| [RFC 6485](https://tools.ietf.org/html/rfc6485) | The Profile for Algorithms and Key Sizes for Use in the Resource Public Key Infrastructure (RPKI) | PROPOSED STANDARD | February 2012 |
| [RFC 6486](https://tools.ietf.org/html/rfc6486) | Manifests for the Resource Public Key Infrastructure (RPKI) | PROPOSED STANDARD | February 2012 |
| [RFC 6487](https://tools.ietf.org/html/rfc6487) | A Profile for X.509 PKIX Resource Certificates | PROPOSED STANDARD | February 2012 |
| [RFC 6488](https://tools.ietf.org/html/rfc6488) | Signed Object Template for the Resource Public Key Infrastructure (RPKI) | PROPOSED STANDARD | February 2012 |
| [RFC 6490](https://tools.ietf.org/html/rfc6490) | Resource Public Key Infrastructure (RPKI) Trust Anchor Locator | PROPOSED STANDARD | February 2012 |
| [RFC 6491](https://tools.ietf.org/html/rfc6491) | Resource Public Key Infrastructure (RPKI) Objects Issued by IANManderson, February 2012 [^data-quality] | PROPOSED STANDARD | February 2012 |
| [RFC 6492](https://tools.ietf.org/html/rfc6492) | A Protocol for Provisioning Resource Certificates | PROPOSED STANDARD | February 2012 |
| [RFC 6608](https://tools.ietf.org/html/rfc6608) | Subcodes for BGP Finite State Machine Error | PROPOSED STANDARD | May 2012 |
| [RFC 6793](https://tools.ietf.org/html/rfc6793) | BGP Support for Four-Octet Autonomous System (AS) Number Space | PROPOSED STANDARD | December 2012 |
| [RFC 6818](https://tools.ietf.org/html/rfc6818) | Updates to the Internet X.509 Public Key Infrastructure Certificate and Certificate Revocation List (CRL) Profile | PROPOSED STANDARD | January 2013 |
| [RFC 6868](https://tools.ietf.org/html/rfc6868) | Parameter Value Encoding in iCalendar and vCard | PROPOSED STANDARD | February 2013 |
| [RFC 7318](https://tools.ietf.org/html/rfc7318) | Policy Qualifiers in Resource Public Key Infrastructure (RPKI) Certificates | PROPOSED STANDARD | July 2014 |
| [RFC 7606](https://tools.ietf.org/html/rfc7606) | Revised Error Handling for BGP UPDATE Messages. Ed., Ed., August 2015 [^data-quality] | PROPOSED STANDARD | August 2015 |
| [RFC 7607](https://tools.ietf.org/html/rfc7607) | Codification of AS 0 Processing | PROPOSED STANDARD | August 2015 |
| [RFC 7705](https://tools.ietf.org/html/rfc7705) | Autonomous System Migration Mechanisms and Their Effects on the BGP AS_PATH Attribute | PROPOSED STANDARD | November 2015 |
| [RFC 7730](https://tools.ietf.org/html/rfc7730) | Resource Public Key Infrastructure (RPKI) Trust Anchor Locator | PROPOSED STANDARD | January 2016 |
| [RFC 7935](https://tools.ietf.org/html/rfc7935) | The Profile for Algorithms and Key Sizes for Use in the Resource Public Key Infrastructure. Ed. | PROPOSED STANDARD | August 2016 |
| [RFC 8181](https://tools.ietf.org/html/rfc8181) | A Publication Protocol for the Resource Public Key Infrastructure (RPKI) | PROPOSED STANDARD | July 2017 |
| [RFC 8182](https://tools.ietf.org/html/rfc8182) | The RPKI Repository Delta Protocol (RRDP) | PROPOSED STANDARD | July 2017 |
| [RFC 8205](https://tools.ietf.org/html/rfc8205) | BGPsec Protocol Specification. Ed., Ed. | PROPOSED STANDARD | September 2017 |
| [RFC 8206](https://tools.ietf.org/html/rfc8206) | BGPsec Considerations for Autonomous System (AS) Migration | PROPOSED STANDARD | September 2017 |
| [RFC 8208](https://tools.ietf.org/html/rfc8208) | BGPsec Algorithms, Key Formats, and Signature Formats | PROPOSED STANDARD | September 2017 |
| [RFC 8209](https://tools.ietf.org/html/rfc8209) | A Profile for BGPsec Router Certificates, Certificate Revocation Lists, and Certification Requests | PROPOSED STANDARD | September 2017 |
| [RFC 8211](https://tools.ietf.org/html/rfc8211) | Adverse Actions by a Certification Authority (CA) or Repository Manager in the Resource Public Key Infrastructure (RPKI) | INFORMATIONAL | September 2017 |
| [RFC 8212](https://tools.ietf.org/html/rfc8212) | Default External BGP (EBGP) Route Propagation Behavior without Policies | PROPOSED STANDARD | July 2017 |
| [RFC 8360](https://tools.ietf.org/html/rfc8360) | Resource Public Key Infrastructure (RPKI) Validation Reconsidered | PROPOSED STANDARD | April 2018 |
| [RFC 8416](https://tools.ietf.org/html/rfc8416) | Simplified Local Internet Number Resource Management with the RPKI (SLURM) | PROPOSED STANDARD | August 2018 |
| [RFC 8488](https://tools.ietf.org/html/rfc8488) | RIPE NCC's Implementation of Resource Public Key Infrastructure (RPKI) Certificate Tree Validation | INFORMATIONAL | December 2018 |
| [RFC 8654](https://tools.ietf.org/html/rfc8654) | Extended Message Support for BGBush, October 2019 [^data-quality] | PROPOSED STANDARD | October 2019 |
| [RFC 8893](https://tools.ietf.org/html/rfc8893) | Resource Public Key Infrastructure (RPKI) Origin Validation for BGP Export | PROPOSED STANDARD | September 2020 |

## Relationships

Edges from the original graph expressing `OBSOLETE` and `UPDATE` relationships between RFCs in the list above.

### Obsoletes (8)

- RFC 4271 obsoletes RFC 1771
- RFC 6350 obsoletes RFC 2425
- RFC 6350 obsoletes RFC 2426
- RFC 6350 obsoletes RFC 4770
- RFC 7730 obsoletes RFC 6490
- RFC 7935 obsoletes RFC 6485
- RFC 8608 obsoletes RFC 8208
- RFC 8630 obsoletes RFC 7730

### Updates (21)

- RFC 6286 updates RFC 4271
- RFC 6350 updates RFC 2739
- RFC 6608 updates RFC 4271
- RFC 6793 updates RFC 4271
- RFC 6818 updates RFC 5280
- RFC 6868 updates RFC 6350
- RFC 7318 updates RFC 6487
- RFC 7606 updates RFC 4271
- RFC 7607 updates RFC 4271
- RFC 7705 updates RFC 4271
- RFC 7909 updates RFC 2622
- RFC 7909 updates RFC 4012
- RFC 8206 updates RFC 8205
- RFC 8208 updates RFC 7935
- RFC 8209 updates RFC 6487
- RFC 8210 updates RFC 6810
- RFC 8212 updates RFC 4271
- RFC 8481 updates RFC 6811
- RFC 8608 updates RFC 7935
- RFC 8654 updates RFC 4271
- RFC 8893 updates RFC 6811

---

[^data-quality]: This title is truncated/concatenated in the original source data itself — not a transcription error introduced here. In 3 of these 4 cases (RFC 2739, RFC 6491, RFC 8654) the first author's surname is truncated to a single initial for the same reason. The RFC number and URL are unaffected; follow the link for the correct canonical title.
