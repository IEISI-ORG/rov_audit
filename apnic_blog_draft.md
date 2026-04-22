# Pacific routing security gets a deadline

**By Terry Sweetser, Chair, APNIC Routing Security SIG**

---

At PITA 30 in Rarotonga last week, I had the chance to put a simple question to a room full of Pacific telco executives: *does your network filter forged route announcements?*

Most of the answers — to the extent there were answers — were somewhere between "probably" and "I'll check with the team."

Fred Christopher, PITA's Manager since 2001 and the closest thing the Pacific has to a permanent secretary-general for telecommunications, cut through it. He agreed the region should be aiming for 100% ROA and ROV coverage — and that PITA 31 is the right target date to hold each other to it.

That is the most useful thing that happened at PITA 30 for routing security. Now the engineers have to deliver it.

## What I told the executives

The presentation I gave was deliberately non-technical. The internet's routing system — BGP — was built on trust. Every network announces to its neighbours: *"send traffic for these addresses through me."* There is no inherent mechanism to verify that the announcement is legitimate.

RPKI fixes that. It adds cryptographically signed certificates — Route Origin Authorizations (ROAs) — that prove which network is authorised to announce which address space. Route Origin Validation (ROV) is the filtering side: configuring your routers to actually *check* those certificates and drop announcements that fail.

Both halves are required. ROA without ROV means you have published your certificate but your routers are still accepting anything. ROV without ROA means you are filtering based on others' records but your own routes are unverifiable. Neither half alone is protection.

I used the April 2018 MyEtherWallet attack as the opening example: a BGP hijack that redirected Amazon's DNS infrastructure for two hours, silently stealing around USD $150,000 from cryptocurrency wallet users who went to the right address and arrived at the wrong server. No passwords were cracked. No malware was deployed. The road signs were simply forged, and nobody on the route was checking them.

The risk framing for a Pacific executive is straightforward: route hijacking enables financial fraud through your network without touching it; accidental route leaks — far more common than attacks — can take down your entire national internet if you have one international cable connection; and regulatory pressure from the US, EU, and Australia is already filtering down to what international partners require of peers.

The cost framing is equally straightforward: ROA registration through APNIC is free, and for a typical Pacific island operator — a handful of prefixes, one or two border routers — signing your routes takes about 30 minutes. Standing up ROV is two Docker containers and some BGP configuration: a realistic one-day job. This is not a multi-quarter infrastructure project.

## Where the Pacific actually stands

Our global audit covers 120,000+ routable networks across 249 territories. The Pacific picture, as of April 2026, is this:

Of the roughly 120 routable ASNs across Pacific island nations, **64 are vulnerable in some form** — either fully exposed or protected only on some paths. The gap is not in documentation: **90 of these networks (75%) have already signed ROAs** for more than half of their address space. The bottleneck is the "dropping" side: Route Origin Validation (ROV).

Currently, only a handful of major incumbent operators in the region are doing active local ROV filtering. The rest are either relying entirely on their upstreams' filtering — which varies significantly in consistency — or are entirely unprotected.

The headline measurement tool here is APNIC Labs' routing security measurement, developed by Geoff Huston. It independently tests both sides of the equation — whether your routes are signed (ROA) and whether your network is actually dropping invalid announcements (ROV) — and reports a single percentile score from 0 to 100%. Think of it as a publicly visible test result for your network's routing hygiene. 

We see a clear divide in the region: a small group of "early adopters" have reached scores of 95-100%, proving that full deployment is achievable with existing hardware. However, a significant portion of the region's primary transit providers still score below 10%, effectively acting as open conduits for route hijacks that affect every customer on their networks.

My own audit goes further, using RIPE Atlas traceroutes to actively verify filtering behaviour from inside the network — and at PITA 30 I encouraged every operator in the room to get a RIPE Atlas probe running. It is free, and it makes your network observable to the global measurement community.

The success stories in the region prove that this is not a budget or hardware issue. Whether it is a commercial ISP in a small island nation or a government-owned incumbent, those who have reached 100% security did so because someone made a decision and it became a project with a named owner. For most operators in this region, the final step from vulnerable to secure is a day's work once that decision is made.

## What needs to happen before PITA 31

The path from vulnerable to secure has three steps, none of which require new hardware or vendor contracts:

**Step 1 — Sign your routes (ROA).** Create Route Origin Authorization records with APNIC for every prefix your network announces. This is done through my.apnic.net under the RPKI section. For a typical Pacific island operator with a handful of prefixes, this is about 30 minutes of work.

**Step 2 — Enable filtering (ROV).** Stand up an RPKI validator — two Docker containers — and configure your border routers to drop BGP announcements that fail validation. Cisco IOS-XR, Juniper JunOS, Nokia SR-OS, and open-source platforms all support this natively. For most operators in this region, this is a one-day job.

**Step 3 — Verify and get a probe.** Check your APNIC Labs routing security test result — it should reach 90%+. Your network should no longer appear as VULNERABLE in bgp.tools or stat.ripe.net. If the score stays low after implementation, something is misconfigured and the measurement tells you exactly that. Also request a RIPE Atlas probe for your network: free hardware, and it makes your routing observable to the global measurement community going forward.

Once you are there, register with MANRS (manrs.org) — the public commitment registry for routing-security-compliant operators. It signals to peers, regulators, and the internet community that your network takes this seriously.

## The PITA 31 accountability moment

Fred Christopher's agreement on a 100% target is useful precisely because it is public and it has a date. That is not a bureaucratic goal — it is a coordination mechanism. Every network operator in the Pacific now has a peer standard to meet, and a meeting at which their score will be visible.

The APNIC Labs test result for your network is a public number. The global ROV audit is a public dataset. At PITA 31, the results will be in the room whether we put them on a slide or not.

The tools to verify your progress are at your fingertips:
- APNIC Labs routing security measurement: [stats.labs.apnic.net/roas](https://stats.labs.apnic.net/roas)
- Public BGP validation status: [bgp.tools](https://bgp.tools)
- ROV audit dataset: [github.com/IEISI-ORG/rov_audit](https://github.com/IEISI-ORG/rov_audit)

APNIC also provides direct technical assistance to Pacific network operators at no cost. If your team needs support with the implementation, contact training@apnic.net — this is exactly what APNIC's capacity-building programmes exist for.

The Routing Security SIG mailing list (sig-routingsecurity@apnic.net) is the right place to share progress, ask questions, and stay current on developments. We want to hear from Pacific operators who are working through implementation, not just the ones who have already finished.

Fred Christopher has been running Pacific telecoms coordination for 25 years. When he says the region should try for something, it tends to happen. The engineering teams now have a clear instruction and a public deadline.

The audit will be updated at PITA 31. The scores will be what they are.

---

*Terry Sweetser is Chair of the APNIC Routing Security SIG and a member of IEISI (Internet Engineering and Internet Standards Institute). The ROV audit dataset used in this post is open source and updated regularly at github.com/IEISI-ORG/rov_audit. The author can be reached at contact@ieisi.org.*
