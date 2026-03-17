---
marp: true
theme: default
paginate: true
footer: PITA 30 · Cook Islands · April 2026 · tcs@ieisi.org
header: '![IEISI logo](https://www.ieisi.org/images/apac_logo.png)'
backgroundColor: #F8F9FA
color: #333333
style: |
  @import url('https://fonts.googleapis.com/css2?family=Roboto+Flex:opsz,wdth,wght@25..151,100..1000&display=swap');
  header {
    position: absolute;
    top: 15px;
    right: 60px;
    padding: 0;
    height: 50px;
    display: flex;
    align-items: center;
  }
  header img {
    height: 45px;
    width: auto;
  }
  section {
    font-family: 'Roboto Flex', sans-serif;
    font-size: 18px;
    padding: 40px 60px;
    background-color: #F8F9FA;
    color: #333333;
  }
  h1 {
    color: #0F2C59;
    font-size: 2em;
    border-bottom: 2px solid #1A5B8F;
    padding-bottom: 10px;
  }
  h2 {
    color: #0F2C59;
    font-size: 1.4em;
  }
  h3 {
    color: #1A5B8F;
    font-size: 1.1em;
  }
  a { color: #1A5B8F; }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85em;
  }
  th {
    background: #D0DEF0;
    color: #0F2C59;
    padding: 6px 12px;
    text-align: left;
  }
  td {
    padding: 5px 12px;
    border-bottom: 1px solid #1A5B8F;
  }
  .columns {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 30px;
  }
  .columns3 {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr;
    gap: 20px;
  }
  .box {
    background: #ffffff;
    border-top: 4px solid #1A5B8F;
    border-radius: 4px;
    padding: 16px;
    margin: 8px 0;
    box-shadow: 0 4px 6px rgba(0,0,0,0.05);
  }
  .box-red {
    background: #fff5f5;
    border-top: 4px solid #D94838;
    border-radius: 4px;
    padding: 16px;
    margin: 8px 0;
    box-shadow: 0 4px 6px rgba(0,0,0,0.05);
  }
  .box-green {
    background: #f0fff4;
    border-top: 4px solid #1e6b2e;
    border-radius: 4px;
    padding: 16px;
    margin: 8px 0;
    box-shadow: 0 4px 6px rgba(0,0,0,0.05);
  }
  .big-number {
    font-size: 3em;
    font-weight: 900;
    color: #0F2C59;
    line-height: 1;
  }
  .big-number-red {
    font-size: 3em;
    font-weight: 900;
    color: #D94838;
    line-height: 1;
  }
  .green { color: #1e6b2e; }
  .red { color: #D94838; }
  .yellow { color: #7a5200; }
  .blue { color: #1A5B8F; }
  .muted { color: #4a4a4a; font-size: 0.85em; }
  section.title {
    display: flex;
    flex-direction: column;
    justify-content: center;
    text-align: center;
    background: #ffffff;
    color: #0F2C59;
    border-top: 8px solid #0F2C59;
  }
  section.title h1 {
    font-size: 2.2em;
    border: none;
    margin-bottom: 10px;
    color: #0F2C59;
  }
  section.title h2 {
    color: #1A5B8F;
    font-size: 1em;
    font-weight: normal;
  }
  section.section-break {
    display: flex;
    flex-direction: column;
    justify-content: center;
    text-align: center;
    background: #ffffff;
    color: #0F2C59;
    border-top: 8px solid #1A5B8F;
  }
  section.section-break h1 {
    font-size: 2.4em;
    border: none;
    color: #0F2C59;
  }
  section.section-break h2 {
    color: #1A5B8F;
    font-weight: normal;
  }
  blockquote {
    border-left: 4px solid #1A5B8F;
    padding-left: 20px;
    color: #4a4a4a;
    font-style: italic;
    margin: 16px 0;
  }
---

<!-- _class: title -->

# Routing Security & RPKI
## Why Executive Decisions Determine Whether Your Network Is a Liability or an Asset

**PITA 30 · Cook Islands · April 2026**

---

<!-- _class: section-break -->

# Let's start with a crime.

---

# April 2018: A Bank Heist Using the Internet's Road Signs

A criminal group didn't break any encryption. They didn't hack any passwords.

They simply **forged the internet's road signs** — and redirected your customers to a fake bank.

<div class="columns">
<div>

### What happened

Amazon's domain name service was rerouted through a criminal server for **two hours**.

Customers of **MyEtherWallet** went to the real address — and arrived at a fake site that stole their credentials.

**~$150,000 USD stolen** before the attack was stopped.

</div>
<div>

### What Amazon, the bank, and the customers had in common

None of them were hacked.

The **road signs were forged** — and nobody on the route was checking whether the signs were real.

The attack was possible because the internet still largely operates on **trust**, not verification.

</div>
</div>

<div class="box-red">

This attack has a name: a **BGP Route Hijack**. And the defence has a name too: **RPKI**. Most Pacific networks do not have it.

</div>

---

# How the Internet's Addressing System Actually Works

No jargon. Just the analogy.

<div class="columns">
<div>

### How it should work

The internet is like a global postal network.

Every network has an address block. When your data travels, routers pass it along — like postal sorting offices — using **route announcements**: *"I can deliver to addresses 203.x.x.x. Send them through me."*

These announcements are supposed to be made only by the legitimate owner.

</div>
<div>

### The problem

Anyone can make an announcement.

Until recently, there was **no signed certificate** proving you owned the address space you claimed. Routers accepted announcements on trust.

A criminal — or a misconfigured network — can announce *your* address block. Your customers' traffic goes to them instead of you.

**Your customers never know.**

</div>
</div>

> RPKI is the system that fixes this. It adds signed, verifiable certificates of address ownership — and requires routers to check those certificates before accepting a route.

---

<!-- _class: section-break -->

# The Pacific Picture

## What the data actually shows about your region

---

# Pacific Routing Security: The Uncomfortable Truth

We audited **every routable network on the internet** — 120,000+ networks across 249 countries.

Here is what the Pacific looks like.

<div class="columns">
<div>

### The numbers

<div class="box-red">

**Most Pacific networks are VULNERABLE.**

Of the major ISPs in Fiji, PNG, Solomon Islands, Samoa, Tonga, Kiribati, FSM, Vanuatu, and Tonga — the majority have **no filtering** of forged route announcements.

Your customers' traffic can be redirected, intercepted, or disrupted — and your router will helpfully forward it.

</div>

</div>
<div>

### What vulnerable means, in practice

| Network | Country | Status |
|---------|---------|--------|
| Telecom Fiji | FJ | VULNERABLE |
| Digicel Fiji | FJ | VULNERABLE |
| Digicel PNG | PG | VULNERABLE |
| Solomon Telekom | SB | VULNERABLE |
| Digicel Samoa | WS | VULNERABLE |
| Digicel Tonga | TO | VULNERABLE |
| FSM Telecom | FM | VULNERABLE |
| Vodafone Fiji | FJ | PARTIAL |
| PNG DATACO | PG | PARTIAL |

</div>
</div>

---

# One Pacific Network Got This Right

Not all Pacific operators are behind. One is a regional leader.

<div class="box-green">

### Tonga Communications Corporation — SECURE (Active Local ROV)

TCC has implemented full route filtering. Their APNIC routing security score is **98.3%** — among the highest of any network in the Pacific.

They made a decision. They assigned a technical resource. It is done.

**This is not a large-network problem. TCC is not the biggest ISP in the region. They just decided.**

</div>

The University of the South Pacific (Fiji) and OPT New Caledonia are also operating securely. These are not the largest networks. They are the most intentional ones.

> The difference between a protected network and a vulnerable one is rarely budget. It is almost always **priority**.

---

<!-- _class: section-break -->

# Why Should the CEO Care?

## Three risks that land on your desk

---

# Risk 1: Your Customers' Money and Data

Route hijacking is not theoretical. It has been used to commit financial fraud.

<div class="columns">
<div>

### The attack chain

1. Criminal announces your upstream's IP block
2. Your customers' banking or payment traffic is intercepted
3. Credentials are harvested at the criminal's server
4. Traffic is quietly forwarded — the customer sees nothing unusual
5. Accounts are drained

This is called a **man-in-the-middle via BGP hijack**. It requires no access to your network, no malware on your customer's device.

</div>
<div>

### Who is liable?

In most Pacific jurisdictions, the legal framework is still developing — but the reputational framework is not.

If your customers' traffic was intercepted **through your network** because you did not implement an available, free, industry-standard protection — that is a conversation you will have in public.

**The question is not whether this can happen. It is whether it will happen to your customers on your watch.**

</div>
</div>

---

# Risk 2: Service Disruption from Route Leaks

The most common routing security incident is not a targeted attack. It is an **accidental route leak** — a misconfigured router at one network that accidentally advertises incorrect routes to the entire internet.

<div class="columns">
<div>

### 2018: Google traffic through Russia and China

A small ISP in Nigeria accidentally leaked Google's routes to Transtelecom (Russia), who passed them to China Telecom.

For **74 minutes**, Google traffic from parts of the world was rerouted through Russian and Chinese infrastructure.

Google Cloud, G Suite, and Search were degraded. Not because Google was hacked — because a network they had no relationship with was not filtering.

</div>
<div>

### What this means for Pacific operators

Your network depends on 1–3 upstream transit providers. If any of them fail to filter route leaks, **your customers experience the outage**.

In larger markets, there is enough redundancy that a leak is survivable. In Pacific island networks — where you may have one or two international cable connections — **a major route leak can be a national internet outage**.

Banking goes down. Government systems go down. Emergency services communications are disrupted.

</div>
</div>

---

# Risk 3: Regulatory and Competitive Pressure Is Coming

The window to act voluntarily is open. It will not stay open.

<div class="columns">
<div>

### What is already happening globally

- **United States** (CISA): Federal agencies required to implement RPKI; mandates extending to critical infrastructure operators
- **European Union** (NIS2 Directive): Network operators must implement "state of the art" routing security measures
- **Australia** (ASD): RPKI implementation included in Essential Eight equivalents for telcos
- **MANRS** (Mutually Agreed Norms for Routing Security): Growing list of ISPs publicly committing — customers and peers check this list

</div>
<div>

### What this means for Pacific operators

**International peering partners are beginning to prefer or require RPKI-enabled peers.**

As traffic volume grows and Pacific networks seek better interconnection arrangements — better latency, lower cost, more peering — your routing security posture will be evaluated.

A network that is publicly listed as VULNERABLE in global audits is a liability in peering negotiations.

**Being secure is increasingly a commercial advantage, not just a technical hygiene measure.**

</div>
</div>

---

<!-- _class: section-break -->

# The Business Case

## Cost versus risk

---

# What Does It Cost to Fix This?

This is where most executives expect a large procurement conversation. It is not.

<div class="columns">
<div>

### The honest answer: mostly your engineers' time

RPKI implementation — for most Pacific networks — is:

- A **software configuration change** on your existing routers
- Supported natively by Cisco IOS-XR, Juniper JunOS, Nokia SR-OS, and open-source platforms
- Deployed in **days to weeks** for a straightforward network
- Free to register certificates (through your RIR — APNIC)
- Operationally maintained with minimal ongoing overhead

**There is no major hardware purchase. There is no new vendor relationship. The standards are published and free.**

</div>
<div>

### The real cost

The real cost is **management attention**.

- Someone has to prioritise it over the next feature request
- The network team needs dedicated time — not "when we have capacity"
- Leadership must make it clear this is not optional

This is exactly the kind of decision that does not happen without executive mandate.

**If you leave the room today and say nothing, your network will still be vulnerable at PITA 31.**

</div>
</div>

<div class="box">

The fix is free. The delay is a choice. The risk accumulates daily.

</div>

---

# The Risk/Cost Frame for the Board

<div class="columns3">

<div class="box-red">

### Doing nothing

- Known vulnerabilities remain
- Customers exposed to financial fraud risk
- Service disruption from upstream leaks unremediated
- Growing regulatory exposure
- Competitive disadvantage as global standards tighten

**Cost: zero upfront. Liability: ongoing and increasing.**

</div>

<div class="box">

### Partial action

- ROA certificates registered but no filtering = incomplete
- Filtering enabled but no certificate = incomplete
- Both required, both must be active

**Common mistake: doing half the job and assuming you're protected.**

</div>

<div class="box-green">

### Full implementation

- Route Origin Authorizations (ROA) registered with APNIC
- Route Origin Validation (ROV) filtering enabled on border routers
- Ongoing monitoring via RIPE RIPEstat or BGP.Tools

**Cost: engineering time. Benefit: customers protected, regulatory exposure reduced, commercial positioning improved.**

</div>

</div>

---

<!-- _class: section-break -->

# What Executive Decision-Making Looks Like Here

---

# The Three Decisions That Change Your Status

You do not need to understand the technology. You need to make three calls.

<div class="columns">
<div>

### Decision 1: Prioritise it

Add routing security implementation to your network team's committed roadmap — not the backlog.

Set a target: **fully implemented before PITA 31**.

This is an instruction, not a request.

---

### Decision 2: Resource it

Assign a named technical owner. Allocate protected time — not "when you have a window".

Budget for APNIC training if your team needs it. The cost is a few thousand dollars. The alternative is the risk on the previous slides.

</div>
<div>

### Decision 3: Verify it

Once implementation is reported complete, verify it.

Your APNIC routing security score should be **above 90%**.
Your network should no longer appear as VULNERABLE in public global audits.

Both are free, public tools that take five minutes to check.

**"My team said it's done" is not verification. A 98% APNIC score is verification — the same score Tonga Communications achieved.**

---

### And then tell people

Register with **MANRS** — the public list of routing-security-committed operators.

Publish your status. Make it part of your network's commercial story.

</div>
</div>

---

# Summary: The Executive Version

<div class="columns">
<div>

### The problem

The internet's routing system was built on trust. That trust is exploited — by criminals, by accidents, by misconfigured networks.

Forged route announcements can redirect your customers' traffic. Money is stolen this way. Services are disrupted this way.

Most Pacific networks — including most of the major ISPs in this room — are currently **not protected**.

</div>
<div>

### The solution

RPKI is the standard fix. It is:
- Free to implement
- Supported on all major network hardware
- Already in use by 86% of the world's top 100 networks
- Already implemented by Tonga Communications Corporation in the Pacific

### Your role

The technology is not the barrier. **The barrier is a decision**.

That decision sits with the people in this room.

</div>
</div>

<div class="box">

**One ask:** Leave today with a named person, a target date, and a commitment to check your APNIC score at PITA 31. That is all it takes to start.

</div>

---

<!-- _class: title -->

# Routing security is not a technology problem.
## It is a leadership decision that happens to be implemented by engineers.

**tcs@ieisi.org · github.com/IEISI-ORG/rov_audit**

*Check your score: stat.ripe.net · bgp.tools*

---

# Appendix: Where to Start Tomorrow

For your technical team — the three-step path to SECURE status.

<div class="columns3">

<div class="box">

### Step 1: Register your routes
Create Route Origin Authorization (ROA) records with APNIC for every prefix your network announces.

**Resource:** my.apnic.net → RPKI

**Time:** 1–2 days for a typical Pacific ISP

</div>

<div class="box">

### Step 2: Enable filtering
Configure your border routers to drop BGP announcements that fail RPKI validation.

**Resource:** RIPE NCC RPKI documentation; your router vendor's RPKI implementation guide

**Time:** 1–5 days depending on platform

</div>

<div class="box">

### Step 3: Verify and monitor
Check your score on **stat.ripe.net/app/launchpad** and **bgp.tools** — your network's RPKI status is publicly visible.

Target: APNIC routing security score **≥ 95%**

**Time:** Ongoing; alerts available

</div>

</div>

<div class="box">

**Regional support:** APNIC provides training, documentation, and direct technical assistance to Pacific network operators at no cost. Contact: training@apnic.net

</div>
