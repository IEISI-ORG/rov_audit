# Presentations — Scope & Theme

Each subdirectory is a self-contained presentation with its own `Makefile`
(`make html`, `make pdf`, `make all`). This file records the **audience
scope** each one targets, so material doesn't drift between talks meant for
different rooms.

| Directory | Event | Scope / Audience | Theme |
|---|---|---|---|
| [`apnic62/`](apnic62/) | APNIC 62 | The 56 economies in the APNIC service region (as listed on apnic.net) | Asia-Pacific-wide RIR/NOG technical audience |
| [`pita30/`](pita30/) | PITA 30 AGM, Rarotonga, Cook Islands — April 2026 | Pacific Islands specifically — PITA member telcos | Launch of the Pacific routing security push (see below) |
| [`pita31/`](pita31/) | PITA 31 AGM Business Forum & Tradeshow, Fiji (default venue) — 12–16 April 2027 (dates earmarked, per [PITA event page](https://pita.org.fj/events/pita-31-agm-business-forum-tradeshow-2027/)) | Pacific Islands specifically — PITA member telcos | Checkpoint on the routing security initiative below |
| [`ietf/`](ietf/) | IETF | Worldwide — general Internet engineering audience | Global routing security, not region-specific |

PITA30 and PITA31 share the PITA scope (Pacific Islands telcos) but differ in
role: PITA30 launched the initiative, PITA31 reviews progress against it.
APNIC62 and IETF are broader — regional (APAC) and global respectively —
so content there should stay generic rather than assume Pacific-specific
context.

## Pacific Routing Security Initiative

At PITA30, the APNIC Routing Security SIG chair presented routing security
recommendations to PITA, setting PITA31 as the practical checkpoint for
reviewing progress. Background: [Pacific routing security sets a deadline
— APNIC Blog, 2026-04-29](https://blog.apnic.net/2026/04/29/pacific-routing-security-sets-a-deadline/).

- **Goal**: full ROA + ROV coverage across Pacific Island operator networks.
- **Ask of operators**: create ROA records via MyAPNIC (free for members),
  deploy RPKI validators, enable ROV filtering on routers, and verify with
  APNIC Labs' routing security measurements.
- **Checkpoint**: PITA31 (April 2027) reviews progress made since the
  PITA30 launch.

`pita31/` should track this progress explicitly when the deck is drafted —
i.e. compare APNIC/RIPE ROV measurement data for Pacific ASNs between the
two events, not just repeat the PITA30 pitch.

Source for the PITA31 event details: `pita31/pita31-event-page-screenshot.png`
(pita.org.fj event page, captured 2026-08-13; venue/dates marked as
tentative on the source page).
