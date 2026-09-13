<h1 align="center">Ashford Grove Capital</h1>
<p align="center"><b>SOC L1 Detection &amp; Investigation Portfolio</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/scenarios-0%2F100-blue">
  <img src="https://img.shields.io/badge/categories-16-informational">
  <img src="https://img.shields.io/badge/MITRE_ATT%26CK-mapped-red">
  <img src="https://img.shields.io/badge/stack-100%25_open_source-success">
  <img src="https://img.shields.io/badge/license-MIT-brightgreen">
</p>

<p align="center">
  <a href="#the-premise">Premise</a> ·
  <a href="#how-to-read-this-repository">How to Read This</a> ·
  <a href="#the-environment">Environment</a> ·
  <a href="#anatomy-of-a-scenario">Scenario Anatomy</a> ·
  <a href="#scenario-catalog">Catalog</a> ·
  <a href="#analysis-principles">Principles</a> ·
  <a href="#repository-structure">Structure</a> ·
  <a href="#documentation">Docs</a>
</p>

---

**One hundred detection and investigation scenarios, worked end-to-end against a live open-source SOC lab, from a single phishing-led breach of a fictional financial firm — each evidenced, MITRE-mapped, and reasoned through the way an L1 analyst works a real case.**

Author: **TOOSHY2** · SOC Analysis · Detection & Investigation

---

## Documentation

| Doc | What's in it |
|---|---|
| [`01-docs/01-architecture.md`](01-docs/01-architecture.md) | Zones, IPs, VM specs, firewall rules |
| [`01-docs/02-attack-narrative.md`](01-docs/02-attack-narrative.md) | The breach story end-to-end, and why scenarios are numbered the way they are |
| [`01-docs/03-scenario-template.md`](01-docs/03-scenario-template.md) | Field-by-field guide to the scenario format |
| [`01-docs/04-detection-tuning-log.md`](01-docs/04-detection-tuning-log.md) | Detection rules tuned after false positives |
| [`02-scenarios/00-index.md`](02-scenarios/00-index.md) | Full 100-scenario index |
| [`attack-navigator-layer.json`](attack-navigator-layer.json) | Importable MITRE ATT&CK coverage heatmap |

## The premise

**Ashford Grove Capital** is a fictional mid-size financial-services firm. It runs what most firms its size run: a Windows Active Directory domain, a handful of employee workstations, a public-facing web server in a DMZ, and a small security team watching it all from a monitoring segment.

On an ordinary Tuesday, an external attacker emails one of its employees. The employee clicks.

Everything after that click — the attacker establishing a foothold, digging in, escalating, harvesting credentials, mapping the network, moving laterally, calling home, staging data, exfiltrating it, and finally trying to cover their tracks and cause damage — is simulated safely inside an isolated lab, detected with production-grade open-source tooling, and then **investigated and written up as a hundred individual cases**.

This repository is those hundred cases. It is not a build guide and not a tool tutorial. It is the analyst's side of a breach.

## How to read this repository

Three different readers want three different things from a portfolio. Pick the path that matches yours.

| If you want to… | Read it as | Start at |
|---|---|---|
| **Understand one incident deeply** | A narrative — one continuous breach across sequential scenarios, each linking to the step before and after | [AGC-001](02-scenarios/01-phishing/AGC-001-spoofed-display-name/README.md), then follow the `Chain` field forward |
| **Assess analytical skill quickly** | A skills sample — four complete incidents plus twenty judgment calls where the answer isn't obvious | [AGC-077](02-scenarios/13-full-attack-chain/AGC-077-full-chain-credential-to-ransomware/README.md) and [AGC-085](02-scenarios/14-false-positive/AGC-085-offhours-service-account/README.md) |
| **Find a specific technique** | A reference — indexed by ID, category, and ATT&CK technique | [`02-scenarios/00-index.md`](02-scenarios/00-index.md) |
| **See coverage at a glance** | A heatmap — every technique across the full ATT&CK matrix | [`attack-navigator-layer.json`](attack-navigator-layer.json) → import into [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) |

## What this does that comparable portfolios don't

Most public SOC labs demonstrate that a SIEM was installed and an alert fired. Three deliberate choices separate this one:

**The attacker starts outside.** Over 90% of real breaches begin with phishing, yet most lab projects start with an attacker box already sitting inside the LAN. Here the attacker occupies its own isolated segment, reachable only through a single narrow, logged firewall rule — so "how did they get in" has a real answer, and every scenario inherits it.

**Twenty scenarios test judgment, not detection.** Eighty scenarios follow the attacker's lifecycle. The remaining twenty test the skills that actually separate an analyst from an alert-reader: correctly **ruling an alert a false positive** with evidence (the single most-asked-about skill in L1 interviews), **hunting with no alert to start from**, and recognizing that the threat is sometimes a **legitimate, authenticated employee**. These require the opposite detection posture from everything else here — baseline deviation instead of indicators of compromise.

**Every verdict carries a confidence level.** True Positive / False Positive / Benign / Escalated is only half a call. Each verdict is rated Critical, High, or Medium, because a real analyst knows the difference between evidence that is conclusive and evidence that is a lead.

## The environment

```
╔════════════════════════════════════════════════════════════════════╗
║   UNTRUSTED   ·   OUTSIDE THE PERIMETER                            ║
║                                                                    ║
║   EXT-ATTACKER-SIM      10.10.40.10      Kali Linux                ║
║   phishing sink · credential portal · DNS · C2 sink                ║
╚══════════════════════════════════╤═════════════════════════════════╝
                                   │
              a single logged rule crosses the perimeter
            COMPROMISED-HOST-01   →   SMTP · HTTP/S · DNS
                                   │
                                   ▼
                ┌────────────────────────────────────┐
                │            OPNsense-FW             │
                │ default-deny  ·  all flows logged  │
                └────────────────────────────────────┘
                                   │
           ┌───────────────────────┴───────────────────────┐
           │                       │                       │
┌────────────────────┐  ┌────────────────────┐  ┌────────────────────┐
│ LAN-NET            │  │ DMZ-NET            │  │ SOC-NET            │
│ 10.10.10.0/24      │  │ 10.10.20.0/24      │  │ 10.10.30.0/24      │
│ TRUSTED            │  │ EXPOSED            │  │ MONITORING         │
├────────────────────┤  ├────────────────────┤  ├────────────────────┤
│ AD-DC-01           │  │ DMZ-LINUX-01       │  │ WAZUH-SIEM-01      │
│ WIN-CLIENT-01 / 02 │  │ nginx · SSH        │  │ SECURITY-ONION-01  │
│ COMPROMISED-HOST-01│  │ auditd             │  │ Zeek · Suricata    │
│ MGMT-GUI-TEMP      │  │                    │  │                    │
└────────────────────┘  └────────────────────┘  └────────────────────┘
```

| Zone | Contents | Trust posture |
|---|---|---|
| **LAN-NET** | Domain controller (`ashfordgrove.local`), two employee workstations, the phishing victim | Trusted — the crown jewels |
| **DMZ-NET** | nginx web server with SSH and auditd | Exposed — reachable inward on SSH only, logged |
| **SOC-NET** | Wazuh (SIEM/EDR), Security Onion (Zeek + Suricata) | Monitoring — receives telemetry, initiates nothing outbound |
| **EXT-SIM-NET** | Kali attacker: phishing sink, credential-harvest portal, DNS responder | Untrusted — architecturally outside |

Each zone sits behind its own dedicated firewall interface rather than a shared VLAN trunk. Shared trunks are common in real enterprises for cost reasons, but they open VLAN-hopping as an attack class; dedicated interfaces close it entirely. Realism here means making the call a security-conscious firm would make, not copying every real-world shortcut.

Full specification — VM specs, addressing policy, complete firewall ruleset: [`01-docs/01-architecture.md`](01-docs/01-architecture.md)

## Anatomy of a scenario

Every scenario is a single page with an identical shape, so the hundredth reads like the first.

```
Card                     ID · category · ATT&CK technique · verdict · confidence
                         affected systems · time to detect · time to triage
                         ◀ previous scenario  ·  next scenario ▶

Attacker Perspective
  ├── Tradecraft         Why this technique, at this point in the chain, and
  │                      exactly where it surfaces in this lab's telemetry
  │                      (Sysmon Event ID / Wazuh rule / Zeek-Suricata signature)
  └── Simulation         The precise steps taken — reproducible from this alone

SOC Perspective
  ├── Detection          What fired: alert ID, rule, raw log excerpt, timestamp
  │                      (threat hunts state the hypothesis BEFORE the query)
  ├── Investigation      The reasoning trail — each check motivated by the last,
  │                      dead ends included, not just the path that worked
  ├── Report             Verdict + confidence + the evidence it rests on +
  │                      the containment recommendation a real SOC would make
  └── MITRE Mapping      Each technique tied to the specific field that evidences it
```

The four full-chain incidents add two sections: an **attacker-vs-analyst timeline** showing both sides against the same clock, and a **mock escalation** — the message an analyst would actually send a manager.

Field-by-field guide: [`01-docs/03-scenario-template.md`](01-docs/03-scenario-template.md)

## Scenario catalog

| Category | Track | Count | Progress |
|---|---|---:|:---|
| [01 · Phishing & Initial Access](02-scenarios/01-phishing/) | Lifecycle | 10 | `▱▱▱▱▱▱▱▱▱▱` 0/10 |
| [02 · Execution](02-scenarios/02-execution/) | Lifecycle | 8 | `▱▱▱▱▱▱▱▱` 0/8 |
| [03 · Persistence](02-scenarios/03-persistence/) | Lifecycle | 6 | `▱▱▱▱▱▱` 0/6 |
| [04 · Privilege Escalation](02-scenarios/04-privilege-escalation/) | Lifecycle | 6 | `▱▱▱▱▱▱` 0/6 |
| [05 · Credential Access](02-scenarios/05-credential-access/) | Lifecycle | 6 | `▱▱▱▱▱▱` 0/6 |
| [06 · Discovery](02-scenarios/06-discovery/) | Lifecycle | 6 | `▱▱▱▱▱▱` 0/6 |
| [07 · Lateral Movement](02-scenarios/07-lateral-movement/) | Lifecycle | 8 | `▱▱▱▱▱▱▱▱` 0/8 |
| [08 · Command & Control](02-scenarios/08-command-control/) | Lifecycle | 6 | `▱▱▱▱▱▱` 0/6 |
| [09 · Collection](02-scenarios/09-collection/) | Lifecycle | 5 | `▱▱▱▱▱` 0/5 |
| [10 · Exfiltration](02-scenarios/10-exfiltration/) | Lifecycle | 5 | `▱▱▱▱▱` 0/5 |
| [11 · Defense Evasion](02-scenarios/11-defense-evasion/) | Lifecycle | 5 | `▱▱▱▱▱` 0/5 |
| [12 · Impact & Recovery](02-scenarios/12-impact-recovery/) | Lifecycle | 5 | `▱▱▱▱▱` 0/5 |
| [13 · Full Attack Chain](02-scenarios/13-full-attack-chain/) | Capstone | 4 | `▱▱▱▱` 0/4 |
| [14 · False Positive Triage](02-scenarios/14-false-positive/) | Judgment | 8 | `▱▱▱▱▱▱▱▱` 0/8 |
| [15 · Proactive Threat Hunting](02-scenarios/15-threat-hunting/) | Judgment | 6 | `▱▱▱▱▱▱` 0/6 |
| [16 · Insider Threat](02-scenarios/16-insider-threat/) | Judgment | 6 | `▱▱▱▱▱▱` 0/6 |
| **Total** | | **100** | **0 / 100** |

Complete ID-by-ID index with verdicts and confidence ratings: [`02-scenarios/00-index.md`](02-scenarios/00-index.md)

## Coverage milestones

Maturity markers tied to real portfolio bars — each activates when genuinely met.

| Milestone | Criterion | Status |
|---|---|:---:|
| Lifecycle represented | At least one scenario in each of the 12 lifecycle categories | 0 / 12 |
| Judgment tracks live | False-positive, hunting, and insider scenarios all documented | 0 / 3 |
| Full-chain set complete | All four end-to-end incident writeups published | 0 / 4 |
| ATT&CK breadth | Every tactic in the catalog evidenced at least once | pending |
| Tuning demonstrated | At least one detection rule tuned and logged after a false positive | pending |
| Catalog complete | All 100 scenarios published | 0 / 100 |

## Analysis principles

Five rules govern every scenario here.

**Evidence, or it didn't happen.** No scenario is marked complete on a description of a finding. Every claim rests on an artifact — a raw log excerpt, an alert ID, a captioned screenshot. A screenshot without a caption asks the reader to do the analyst's job for them, so every image says what to look at.

**The reasoning is the deliverable.** Anyone can paste a query result. The investigation section records what was checked, in what order, and *why* — each step motivated by the ambiguity in the previous one. Dead ends stay in: a check that came back clean and ruled something out is part of the reasoning, not a failure to hide.

**Confidence is part of the verdict.** Critical means near-zero false-positive rate on definitive evidence. High means strong evidence with a small chance of an alternate explanation. Medium means a hunting lead — correlated, not conclusive alone. A SOC that treats all three the same drowns.

**Correlation over single events.** The strongest calls chain evidence across sources — a host-based event that only becomes meaningful alongside a network-side observation. Where one source alone was insufficient to reach the verdict, the scenario says so explicitly.

**A false positive is a finding, not a failure.** When triage proves an alert benign, the discriminating evidence is stated plainly — the specific fact that separates this from the real attack it resembles — and any resulting rule change is recorded in the [detection tuning log](01-docs/04-detection-tuning-log.md). Correctly clearing an alert and improving the rule behind it is analyst work, not wasted work.

## Repository structure

```
.
├── README.md                          ← you are here
├── attack-navigator-layer.json        Importable ATT&CK Navigator coverage layer
├── 01-docs/
│   ├── 01-architecture.md             Full environment spec: zones, VMs, firewall rules
│   ├── 02-attack-narrative.md         The breach story end-to-end, and scenario sequencing
│   ├── 03-scenario-template.md        Field-by-field guide to the scenario format
│   ├── 04-detection-tuning-log.md     Rule changes made in response to false positives
│   └── templates/                     Copy-paste scenario skeletons
└── 02-scenarios/
    ├── 00-index.md                    All 100 scenarios: ID, category, verdict, confidence
    ├── 01-phishing/ … 16-insider-threat/
    │   └── AGC-XXX-<name>/
    │       ├── README.md              The complete scenario
    │       └── screenshots/           Evidence images, numbered in reference order
```

## Toolchain

Entirely free and open-source — no commercial licenses, no trial keys, nothing that expires.

| Tool | Role |
|---|---|
| [OPNsense](https://opnsense.org/) | Firewall, routing, zone segmentation, flow logging |
| [Wazuh](https://wazuh.com/) | SIEM and EDR — host telemetry, detection rules, alerting |
| [Security Onion](https://securityonionsolutions.com/) | Network security monitoring — Zeek and Suricata |
| [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) | Windows process, network, and file telemetry |
| Windows Server 2022 / Windows 11 Pro | Active Directory domain and endpoints |
| Ubuntu 24.04 LTS · Kali Linux | DMZ services, SOC hosts, attacker infrastructure |

## Scope and safety

This lab is an on-premises enterprise simulation. Cloud identity, SaaS telemetry, and mobile endpoints are deliberately **out of scope** — the environment contains no systems that would produce authentic evidence for them, and a scenario without real evidence behind it would undercut the standard every other scenario here is held to.

All simulation is confined to lab-owned systems. No live malware, no real phishing to real people, no external targets. Safe test artifacts (EICAR and synthetic equivalents) stand in wherever a real payload would otherwise be required. The attacker segment is isolated and reachable only through one logged firewall rule.

## License

MIT — see [`LICENSE`](LICENSE). Use it, adapt it, build on it.

---

*Built as an ongoing exercise in SOC analysis, detection engineering, and incident documentation. Feedback welcome.*
