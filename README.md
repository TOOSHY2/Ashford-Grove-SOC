<h1 align="center">Ashford Grove Capital</h1>
<p align="center"><b>SOC L1 Detection &amp; Investigation Portfolio</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/scenarios-100%2F100-brightgreen">
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
| [`docs/01-architecture.md`](docs/01-architecture.md) | Zones, IPs, VM specs, firewall rules |
| [`docs/02-attack-narrative.md`](docs/02-attack-narrative.md) | The breach story end-to-end, and why scenarios are numbered the way they are |
| [`docs/03-scenario-template.md`](docs/03-scenario-template.md) | Field-by-field guide to the scenario format |
| [`docs/04-detection-tuning-log.md`](docs/04-detection-tuning-log.md) | Detection rules tuned after false positives |
| [`scenarios/00-index.md`](scenarios/00-index.md) | Full 100-scenario index |
| [`MITRE-Mapping/layers/master-coverage.json`](MITRE-Mapping/layers/master-coverage.json) | Merged MITRE ATT&CK coverage heatmap (all 100 scenarios) |

## The premise

**Ashford Grove Capital** is a fictional mid-size financial-services firm. It runs what most firms its size run: a Windows Active Directory domain, a handful of employee workstations, a public-facing web server in a DMZ, and a small security team watching it all from a monitoring segment.

On an ordinary Tuesday, an external attacker emails one of its employees. The employee clicks.

Everything after that click — the attacker establishing a foothold, digging in, escalating, harvesting credentials, mapping the network, moving laterally, calling home, staging data, exfiltrating it, and finally trying to cover their tracks and cause damage — is simulated safely inside an isolated lab, detected with production-grade open-source tooling, and then **investigated and written up as a hundred individual cases**.

This repository is those hundred cases. It is not a build guide and not a tool tutorial. It is the analyst's side of a breach.

## How to read this repository

Three different readers want three different things from a portfolio. Pick the path that matches yours.

| If you want to… | Read it as | Start at |
|---|---|---|
| **Understand one incident deeply** | A narrative — one continuous breach across sequential scenarios, each linking to the step before and after | [`docs/02-attack-narrative.md`](docs/02-attack-narrative.md) for the end-to-end story now; [AGC-001](scenarios/01-phishing/AGC-001-spoofed-display-name/README.md) → follow the `Chain` field will anchor this path once scenarios are published |
| **Assess analytical skill quickly** | A skills sample — four end-to-end incidents plus twenty judgment calls where the answer isn't obvious | [`docs/03-scenario-template.md`](docs/03-scenario-template.md) and the [`scenarios/00-index.md`](scenarios/00-index.md) skeleton now; [AGC-077](scenarios/13-full-attack-chain/AGC-077-full-chain-credential-to-ransomware/README.md) (full-chain) and [AGC-085](scenarios/14-false-positive/AGC-085-offhours-service-account/README.md) (false-positive) will anchor this path once published |
| **Find a specific technique** | A reference — indexed by ID, category, and ATT&CK technique | [`scenarios/00-index.md`](scenarios/00-index.md) |
| **See coverage at a glance** | A heatmap — every technique across the full ATT&CK matrix | [`attack-navigator-layer.json`](attack-navigator-layer.json) → import into [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) |

## What this does that comparable portfolios don't

Most public SOC labs demonstrate that a SIEM was installed and an alert fired. Three deliberate choices separate this one:

**The attacker starts outside.** Over 90% of real breaches begin with phishing, yet most lab projects start with an attacker box already sitting inside the LAN. Here the attacker occupies its own isolated segment, reachable only through a single narrow, logged firewall rule — so "how did they get in" has a real answer, and every scenario inherits it.

**Twenty scenarios test judgment, not detection.** Eighty scenarios follow the attacker's lifecycle. The remaining twenty test the skills that actually separate an analyst from an alert-reader: correctly **ruling an alert a false positive** with evidence (the single most-asked-about skill in L1 interviews), **hunting with no alert to start from**, and recognizing that the threat is sometimes a **legitimate, authenticated employee**. These require the opposite detection posture from everything else here — baseline deviation instead of indicators of compromise.

**Every verdict carries a confidence level.** True Positive / False Positive / Benign / Escalated is only half a call. Each verdict is rated Critical, High, or Medium, because a real analyst knows the difference between evidence that is conclusive and evidence that is a lead.

## The environment

```
╔════════════════════════════════════════════════════════════════════╗
║              UNTRUSTED   ·   OUTSIDE THE PERIMETER                 ║
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

Full specification — VM specs, addressing policy, complete firewall ruleset: [`docs/01-architecture.md`](docs/01-architecture.md)

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

Field-by-field guide: [`docs/03-scenario-template.md`](docs/03-scenario-template.md)

## Scenario catalog

| Category | Track | Count | Progress |
|---|---|---:|:---|
| [01 · Phishing & Initial Access](scenarios/01-phishing/) | Lifecycle | 10 | `██████████` 10/10 |
| [02 · Execution](scenarios/02-execution/) | Lifecycle | 8 | `████████` 8/8 |
| [03 · Persistence](scenarios/03-persistence/) | Lifecycle | 6 | `██████` 6/6 |
| [04 · Privilege Escalation](scenarios/04-privilege-escalation/) | Lifecycle | 6 | `██████` 6/6 |
| [05 · Credential Access](scenarios/05-credential-access/) | Lifecycle | 6 | `██████` 6/6 |
| [06 · Discovery](scenarios/06-discovery/) | Lifecycle | 6 | `██████` 6/6 |
| [07 · Lateral Movement](scenarios/07-lateral-movement/) | Lifecycle | 8 | `████████` 8/8 |
| [08 · Command & Control](scenarios/08-command-control/) | Lifecycle | 6 | `██████` 6/6 |
| [09 · Collection](scenarios/09-collection/) | Lifecycle | 5 | `█████` 5/5 |
| [10 · Exfiltration](scenarios/10-exfiltration/) | Lifecycle | 5 | `█████` 5/5 |
| [11 · Defense Evasion](scenarios/11-defense-evasion/) | Lifecycle | 5 | `█████` 5/5 |
| [12 · Impact & Recovery](scenarios/12-impact-recovery/) | Lifecycle | 5 | `█████` 5/5 |
| [13 · Full Attack Chain](scenarios/13-full-attack-chain/) | Capstone | 4 | `████` 4/4 |
| [14 · False Positive Triage](scenarios/14-false-positive/) | Judgment | 8 | `████████` 8/8 |
| [15 · Proactive Threat Hunting](scenarios/15-threat-hunting/) | Judgment | 6 | `██████` 6/6 |
| [16 · Insider Threat](scenarios/16-insider-threat/) | Judgment | 6 | `██████` 6/6 |
| **Total** | | **100** | **100 / 100** |

Complete ID-by-ID index with verdicts and confidence ratings: [`scenarios/00-index.md`](scenarios/00-index.md)

## Coverage milestones

Maturity markers tied to real portfolio bars — each activates when genuinely met.

| Milestone | Criterion | Status |
|---|---|:---:|
| Lifecycle represented | At least one scenario in each of the 12 lifecycle categories | 12 / 12 |
| Judgment tracks live | False-positive, hunting, and insider scenarios all documented | 3 / 3 |
| Full-chain set complete | All four end-to-end incident writeups published | 4 / 4 |
| ATT&CK breadth | Every tactic in the catalog evidenced at least once | 12 / 12 |
| Tuning demonstrated | At least one detection rule tuned and logged after a false positive | done |
| Catalog complete | All 100 scenarios published | 100 / 100 |

## Analysis principles

Five rules govern every scenario here.

**Evidence, or it didn't happen.** No scenario is marked complete on a description of a finding. Every claim rests on an artifact — a raw log excerpt, an alert ID, a captioned screenshot. A screenshot without a caption asks the reader to do the analyst's job for them, so every image says what to look at.

**The reasoning is the deliverable.** Anyone can paste a query result. The investigation section records what was checked, in what order, and *why* — each step motivated by the ambiguity in the previous one. Dead ends stay in: a check that came back clean and ruled something out is part of the reasoning, not a failure to hide.

**Confidence is part of the verdict.** Critical means near-zero false-positive rate on definitive evidence. High means strong evidence with a small chance of an alternate explanation. Medium means a hunting lead — correlated, not conclusive alone. A SOC that treats all three the same drowns.

**Correlation over single events.** The strongest calls chain evidence across sources — a host-based event that only becomes meaningful alongside a network-side observation. Where one source alone was insufficient to reach the verdict, the scenario says so explicitly.

**A false positive is a finding, not a failure.** When triage proves an alert benign, the discriminating evidence is stated plainly — the specific fact that separates this from the real attack it resembles — and any resulting rule change is recorded in the [detection tuning log](docs/04-detection-tuning-log.md). Correctly clearing an alert and improving the rule behind it is analyst work, not wasted work.

## Repository structure

```
.
├── README.md                          ← you are here
├── attack-navigator-layer.json        Importable ATT&CK Navigator coverage layer
├── docs/
│   ├── 01-architecture.md             Full environment spec: zones, VMs, firewall rules
│   ├── 02-attack-narrative.md         The breach story end-to-end, and scenario sequencing
│   ├── 03-scenario-template.md        Field-by-field guide to the scenario format
│   ├── 04-detection-tuning-log.md     Rule changes made in response to false positives
│   └── templates/                     Copy-paste scenario skeletons
└── scenarios/
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

## Methodology — How This Portfolio Was Built

This project was built in two deliberate phases, and both are documented
transparently rather than blended together.

**Phase one — AI-built reference pass.** Claude (Anthropic AI) executed
and documented an initial complete pass across all 100 scenarios,
operating autonomously against this lab's live infrastructure. Every
report from this phase carries its own explicit disclosure block stating
exactly that, including a note on how the execution method (VirtualBox
Guest Control) shapes what its evidence looks like. This phase served a
specific purpose: produce a rigorous, consistently-structured model —
correctly calibrated confidence levels, honest negative-evidence
documentation, accurate cross-scenario correlation — worth learning from,
rather than a shortcut worth hiding.

**Phase two — independent manual re-implementation.** Every scenario is
being personally re-executed by hand, scenario by scenario, using the
phase-one version purely as a structural reference — never copied
content. Each manual pass uses independently chosen data and methods,
adds real screenshot evidence (absent from phase one by design), and
carries its own accurate disclosure reflecting what actually happened
for that specific scenario. This is deliberately paced at a realistic
1–2 scenarios per weekday, because the pace itself is part of the
evidence: a two-month timeline of naturally-spaced commits is what real,
hands-on work actually looks like — the opposite of a rushed batch.

**Why build it this way.** Treating an AI-built first pass as something
to hide would have meant either lying about it or discarding genuinely
useful reference work. Treating it as a deliberate, disclosed model to
learn from and independently reproduce turns the same starting point
into real skill-building — the two phases are not in tension, they're
sequential: study a rigorous example, then independently prove the same
capability by hand.

**What this means if you're reading the repository's history.** You'll
see two layers of work against the same 100 scenario IDs over time — an
initial AI-authored commit for each, followed later by a human-authored
revision as phase two reaches that scenario. That's expected, and it's
the whole point: this repository's git history is itself part of the
evidence of the process described here, not something to reconcile away.

<!-- Update note for when phase two completes: change "is being personally
re-executed" to "has been personally re-executed", and consider adding
completion date. -->

## Final Engagement Report

### Executive Summary

All 100 detection and investigation scenarios for the Ashford Grove Capital SOC L1 engagement have been executed, documented, and individually committed. Each scenario was simulated against live VirtualBox lab infrastructure running production-grade open-source tooling (Wazuh SIEM/EDR, Security Onion NSM, Sysmon endpoint telemetry), with real detection evidence captured and analyzed.

The engagement covers the full MITRE ATT&CK lifecycle from Initial Access through Impact, plus 20 judgment-track scenarios testing false-positive triage, proactive threat hunting, and insider threat detection -- skills that separate an analyst from an alert reader.

### Coverage Breakdown

| Track | Categories | Scenarios | Verdicts |
|---|---|---:|---|
| **Lifecycle** | 12 (Phishing through Impact) | 76 | 72 True Positive, 1 Pipeline Pass, 1 Triage Complete, 1 Containment Validated, 1 True Positive (conceptual) |
| **Capstone** | 1 (Full Attack Chain) | 4 | 4 True Positive (multi-phase) |
| **Judgment** | 3 (FP, Hunting, Insider) | 20 | 8 False Positive / Benign, 6 Hunt Complete, 6 Insider findings |
| **Total** | **16** | **100** | |

### MITRE ATT&CK Coverage

- **85 unique technique-tactic pairs** mapped across all 100 scenarios
- **12 of 12 ATT&CK tactics** covered: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact
- **Confidence distribution**: 18 Critical, 60 High, 14 Medium (8 non-standard verdict types)
- **Master heatmap**: [`MITRE-Mapping/layers/master-coverage.json`](MITRE-Mapping/layers/master-coverage.json) -- import into [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- **Per-scenario layers**: [`MITRE-Mapping/layers/AGC-XXX.json`](MITRE-Mapping/layers/) (97 individual layers; 3 scenarios had no distinct MITRE technique)

### Category Results

| # | Category | Count | Key Techniques |
|---|---|---:|---|
| 01 | Phishing & Initial Access | 10 | T1566.001, T1566.002 |
| 02 | Execution | 8 | T1059.001, T1059.003, T1047, T1204.002, T1218.005 |
| 03 | Persistence | 6 | T1547.001, T1053.005, T1543.003, T1546.003, T1136.001 |
| 04 | Privilege Escalation | 6 | T1548.002, T1548.003, T1078.002, T1098, T1574.001 |
| 05 | Credential Access | 6 | T1003.001, T1003.002, T1555.003, T1110.003, T1557.001 |
| 06 | Discovery | 6 | T1082, T1033, T1016, T1069, T1135, T1482 |
| 07 | Lateral Movement | 8 | T1021.001/002/004/006, T1550.002, T1046 |
| 08 | Command & Control | 6 | T1071.001, T1071.004, T1571, T1573 |
| 09 | Collection | 5 | T1560.001, T1113, T1074.001, T1039 |
| 10 | Exfiltration | 5 | T1041, T1048.003, T1052.001, T1567.002 |
| 11 | Defense Evasion | 5 | T1070.001, T1562.001, T1070.004, T1027.010 |
| 12 | Impact & Recovery | 5 | T1486, T1489, T1491.002, T1484.001 |
| 13 | Full Attack Chain | 4 | Multi-technique chains (8-14 techniques each) |
| 14 | False Positive Triage | 8 | Same techniques as malicious twins, benign context |
| 15 | Proactive Threat Hunting | 6 | T1546.003, T1218, T1071, T1078, T1053.005 |
| 16 | Insider Threat | 6 | T1567.002 (1 scenario); 5 baseline-deviation only |

### Detection Stack Performance

| Source | Events Captured | Role |
|---|---|---|
| Sysmon (SwiftOnSecurity config) | EID 1, 11, 13, 19-22 | Primary host telemetry |
| Windows Security Log | EID 4624, 4625, 4698, 4732, 1102 | Authentication and audit |
| Windows Defender | Real-time detection, Tamper Protection | Endpoint protection |
| journalctl/auditd (Linux) | sudo, SSH, service events | Linux host telemetry |

### Lab Constraints Documented

- Security Onion network telemetry inaccessible (no Guest Additions)
- Wazuh indexer API offline (port 9200 refused)
- Domain trust broken on COMPROMISED-HOST-01 (NTLM-only authentication)
- Sysmon EID 7 (Image Loaded) and EID 10 (ProcessAccess) disabled in config
- Admin shares (C$) blocked between lab endpoints
- DMZ-LINUX-01 Guest Additions at RunLevel=0

Each constraint is documented in the affected scenario's investigation section with the workaround used and its impact on detection fidelity.

## License

MIT -- see [`LICENSE`](LICENSE). Use it, adapt it, build on it.

---

*Built as an ongoing exercise in SOC analysis, detection engineering, and incident documentation. Feedback welcome.*
