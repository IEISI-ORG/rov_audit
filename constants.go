package main

// constants.go — shared topology classification constants for all Go binaries.
//
// This is the Go-side single source of truth, mirroring rov_utils.py:
//   TIER_1_ASNS       → isTier1()
//   NON_TRANSIT_ASNS  → isNonTransit()
//   PROVIDER_RATIO    → PROVIDER_RATIO
//
// To update these lists, edit BOTH this file AND rov_utils.py, then run:
//   python3 -m pytest tests/test_gao_rexford.py
// The sync test will catch any drift between the two.

// PROVIDER_RATIO is the minimum degree ratio for provider-customer inference.
// If degree(A) > PROVIDER_RATIO * degree(B), A is inferred as B's provider.
// Must match rov_utils.PROVIDER_RATIO in Python.
const PROVIDER_RATIO = 4.0

// isTier1 returns true for networks that are never a customer of anyone else.
// Verified 2026-04-26: all entries have zero providers in downstream_graph.json.
// Removed AS1239 (Sprint/Cogent legacy, 0 direct customers).
// Removed AS2828 (Verizon Business/MCI legacy, 0 direct customers).
func isTier1(asn string) bool {
	switch asn {
	case "3356", // Lumen / Level 3
		"1299",  // Arelion (fka Telia Carrier)
		"174",   // Cogent Communications
		"2914",  // NTT America
		"3257",  // GTT Communications
		"6762",  // Telecom Italia Sparkle (Seabone)
		"6939",  // Hurricane Electric
		"6453",  // TATA Communications
		"3491",  // PCCW Global
		"701",   // Verizon Business
		"6461",  // Zayo Bandwidth
		"5511",  // Orange S.A.
		"6830",  // Liberty Global
		"4637",  // Telstra Global
		"7018",  // AT&T
		"3320",  // Deutsche Telekom
		"12956", // Telxius (Telefonica Global)
		"1273",  // Vodafone Group
		"7922",  // Comcast
		"209",   // Lumen (ex-Qwest)
		"4134",  // China Telecom Backbone
		"4809",  // China Telecom Next Generation
		"4837",  // China Unicom Backbone
		"9929",  // China Unicom Industrial Internet
		"9808":  // China Mobile Backbone
		return true
	}
	return false
}

// isNonTransit returns true for ASNs that must be excluded from provider-customer
// inference. This includes DNS root servers, RIRs, and IXP route servers.
//
// Root server ASNs sourced from bgp.tools icrit tag (verified 2026-04-26).
// Do NOT add CDN-tagged ASNs in bulk — some CDNs (e.g. OVH AS16276) also sell transit.
// Removed: AS3661 (Chinese U of HK, not A-Root), AS1941 (Renater, not B-Root),
//
//	AS15061 (Insurance Corp BC, not H-Root) — those ASNs were reassigned.
func isNonTransit(asn string) bool {
	switch asn {
	case "213241", // TECHIT.BE — IXP Route Server
		"13335",  // Cloudflare — CDN/Anycast (non-transit for topology)
		"3333",   // RIPE NCC
		"4608",   // APNIC (refuses ROV to avoid member lockout)
		"4777",   // APNIC (refuses ROV to avoid member lockout)
		"394353", // USC/ISI — B-Root
		"2149",   // Cogent Communications — C-Root
		"10886",  // University of Maryland — D-Root
		"21556",  // NASA Ames Research Center — E-Root
		"3557",   // ISC — F-Root
		"5927",   // US Dept of Defense — G-Root
		"1508",   // US Army Research Lab — H-Root
		"29216",  // Netnod — I-Root
		"26415",  // VeriSign — A-Root & J-Root
		"25152",  // RIPE NCC — K-Root
		"20144",  // ICANN — L-Root
		"7500",   // WIDE Project — M-Root
		"112",    // AS112 Project — RFC 7534 blackhole for private PTR
		"23456",  // AS_TRANS — RFC 6793 (4-byte ASN transition)
		"0":      // RFC 7607 reserved
		return true
	}
	return false
}
