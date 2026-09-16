# Scenario Template — Field Guide

This document describes the structure every scenario `README.md` in this repository follows, and why. For the actual copy-paste starting point of a new scenario, use one of the blank skeletons:

- [`templates/standard-scenario-readme.md`](templates/standard-scenario-readme.md) — for the 96 regular scenarios.
- [`templates/full-chain-scenario-readme.md`](templates/full-chain-scenario-readme.md) — for the 4 Full Attack-Chain scenarios (AGC-077 through AGC-080).

[AGC-001](../scenarios/01-phishing/AGC-001-spoofed-display-name/README.md) is the reference implementation of the standard structure; [AGC-077](../scenarios/13-full-attack-chain/AGC-077-full-chain-credential-to-ransomware/README.md) is the reference for the full-chain variant.

## Why two perspectives

Every scenario is written as two sides of the same event: what the **attacker** did to cause the alert, and what the **SOC** did to detect, investigate, and report it. The split is deliberate. Reading only the SOC side hides the technique; reading only the attacker side hides the decision-making that separates a real analyst from a checklist. The two-column reading matches how detection engineers actually think: emulate the technique first, then hunt for it.

## Section structure

Every scenario `README.md` is organised in this order:

1. `## Card`
2. `## Attacker Perspective`
   - `### Tradecraft`
   - `### Simulation`
3. `## SOC Perspective`
   - `### Detection`
   - `### Investigation`
   - `### Report`
   - `### MITRE Mapping`

Every scenario ends with a short `## Evidence` section that states whether screenshot evidence exists for that scenario yet (see [Evidence](#evidence)).

Full Attack-Chain scenarios (AGC-077 through AGC-080) add two additional top-level sections after MITRE Mapping — see [Full Attack-Chain scenarios](#full-attack-chain-scenarios-agc-077agc-080).

### Structural variants

Three kinds of scenario legitimately omit part of the standard shape. The omission is the point, not a gap:

| Variant | Scenarios | What changes | Why |
|---|---|---|---|
| **Threat hunt** | AGC-089 – AGC-094 | No `## Attacker Perspective`. `### Detection` becomes `### Hypothesis`; `### Investigation` holds `#### Methodology`, `#### Results`, and triage | A hunt starts from a hypothesis, not from a simulated action or an alert |
| **False positive / benign** | AGC-081 – AGC-088 | `### Tradecraft` omitted; `### Report` carries a `#### Discriminating evidence (benign vs malicious)` table | There is no adversary technique to explain — the activity is legitimate, and the deliverable is how it was told apart from its malicious twin |
| **Recovery closure** | AGC-076 | No `## Attacker Perspective`; `### Investigation` holds the affected-host inventory and recovery validation, `### Report` holds lessons learned | Incident-response closure for AGC-001 – AGC-075; nothing is attacked |

AGC-018 (EICAR pipeline test) and AGC-079 / AGC-080 keep the full shape but document why the "attacker" side is a validation test or a phased chain rather than a single technique.

### `## Card`

A markdown table pinned to the top of the file. One field per row:

| Field | Value |
|---|---|
| **ID** | `AGC-nnn` |
| **Category** | one of the 16 categories (e.g. `01-phishing`) |
| **MITRE Technique** | primary technique ID(s), e.g. `T1566.002` |
| **Verdict** | `True Positive` \| `False Positive` \| `Benign` \| `Escalated` |
| **Confidence** | `Critical` \| `High` \| `Medium` |
| **Time to Detect** | `mm:ss` from event to alert |
| **Time to Triage** | `mm:ss` from alert to verdict |
| **Affected Systems** | hostnames + IPs |
| **Chain** | `◀ AGC-prev · next AGC-next ▶` (see [Chain notation](#chain-notation)) |
| **One-line Summary** | ≤120 characters, one sentence |

**Verdict values.**

- **True Positive** — real malicious activity confirmed by evidence.
- **False Positive** — the alert fired on benign activity that resembles the technique; the Report section documents the *discriminating evidence* that separates this from the real attack it mimics.
- **Benign** — activity confirmed as expected or authorised (e.g. an approved change ticket, a documented maintenance window).
- **Escalated** — verdict not reachable at L1; handed off to L2 / incident response, with the reasoning trail preserved.

**Confidence values.**

- **Critical** — near-zero false-positive rate; definitive evidence (typically a specific Event ID + field combination unique to the technique).
- **High** — strong evidence, small chance of an alternate explanation; multiple independent detection sources agree.
- **Medium** — a hunting lead; correlated but not conclusive alone; would need a second data source to promote to High.

### `## Attacker Perspective`

Two subsections, in order:

#### `### Tradecraft`

Written **before** simulation — this subsection proves you understood the technique before you generated the alert for it. Covers:

- **What** the technique is.
- **Why at this lifecycle stage** — why an attacker uses it now, and what it buys them for the next stage.
- **Where in this lab** — the specific detection surface in *this* stack: which Sysmon Event ID(s), which Wazuh rule ID(s), which Zeek log(s), which Suricata SID(s). Concrete artefacts, not a generic ATT&CK reference.

#### `### Simulation`

The reproducible act of generating the alert. Complete enough that someone with a rebuilt lab can reproduce the scenario from this subsection alone:

- Exact commands (including flags), tool versions, source host, target host.
- Absolute UTC timestamps of every step.
- Any pre-conditions (files staged, agents restarted, snapshots restored).
- Any post-conditions to clean up.

### `## SOC Perspective`

Four subsections, in order:

#### `### Detection`

What actually fired:

- Alert ID(s) + rule name(s).
- Raw log excerpt(s) — verbatim, timestamps included; trim sensitive values only when they are genuinely sensitive.
- Timestamp(s) matching the Simulation subsection.
- Source (Wazuh manager dashboard, Security Onion Hunt UI, Suricata `eve.json`, etc.).

**Threat-Hunting scenarios (`15-threat-hunting/*`) replace this subsection with `### Hypothesis`** — the hunt hypothesis stated *before* the query is run, not after. Threat hunting is a search, not a triage; documenting the hypothesis first is what distinguishes a hunt from a rationalisation.

#### `### Investigation`

The reasoning trail. This is the subsection that separates a portfolio from a checklist:

- What was checked, in what order, and **why** — each step motivated by the previous one.
- Dead ends included, not just the successful path — showing the alternatives you ruled out is the point.
- Cross-source correlation: a Wazuh alert corroborated by Zeek + Suricata + AD event logs is worth more than three copies of the same signal.

#### `### Report`

The final analyst product:

- Verdict + confidence (matching the Card).
- Evidence the verdict rests on — a numbered list of the concrete artefacts.
- Response recommendation — what should happen next (contain, notify, hunt, tune, preserve, …).

**False-Positive scenarios (`14-false-positive/*`) must state the DISCRIMINATING evidence** that separates the benign case from the real attack it resembles — not just "determined to be benign." A false-positive writeup that only says the alert was wrong isn't a portfolio scenario; showing *how* you told them apart is.

#### `### MITRE Mapping`

A table, one row per technique the scenario exercises:

| Tactic | Technique ID | Technique Name | Evidence (Event ID / Rule / Field) | Confidence |
|---|---|---|---|---|

Sub-techniques get their own row when they add signal (e.g. `T1566.002` under `T1566`). Related resource-development or impact techniques used in support belong here too.

## Full Attack-Chain scenarios (AGC-077…AGC-080)

The four scenarios in [`13-full-attack-chain/`](../scenarios/13-full-attack-chain/) are each a **complete, standalone incident narrative** — starting at initial phishing access and running all the way through to an Impact-stage outcome, not a partial segment. Each of the four follows a **different technique path** through the kill chain (different execution, persistence, lateral-movement, C2, exfiltration, and impact choices), so the four read as four distinct incidents, not four copies of the same one.

They use [`templates/full-chain-scenario-readme.md`](templates/full-chain-scenario-readme.md), which adds two extra top-level sections *after* MITRE Mapping:

### `## Attacker vs Analyst`

A side-by-side timeline: what the attacker did versus what the analyst saw and did, aligned on the same UTC timestamps. Two columns, one row per event.

### `## Mock Escalation`

A mock Slack message or ticket to a manager. Four short paragraphs — **what happened**, **impact / blast radius**, **actions taken**, **recommendation** — written in the voice an L1 would actually use: plain language, no hedging, no filler.

## Scenario folder layout

Every scenario folder is **markdown-only**: a single `README.md`, nothing else. Evidence is textual — command output, log excerpts, Sysmon Event IDs, Wazuh alert JSON — embedded directly in the report's Detection and Investigation sections. Screenshots are not part of the automated pipeline; if an analyst later adds manual screenshots, they go in a `screenshots/` subfolder.

(The four Full Attack-Chain scenarios may later gain one optional raw-evidence file — a PCAP, an `.eml`, or a JSON export — added by hand when the writeup earns it. That's the single, deliberate exception; the 96 regular scenarios never take on extra file types.)

## Project-wide MITRE view

Each scenario's own `### MITRE Mapping` table covers the techniques *that scenario* exercises. The **`attack-navigator-layer.json`** at the repository root aggregates all 100 scenarios' MITRE coverage into a single importable heatmap for the official [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) — a project-wide view that no single scenario's own table can provide. Import it into the Navigator to see, at a glance, which tactics and techniques the portfolio covers and which are still open.

## Chain notation

The **Chain** field on the Card uses this format:

- `◀ AGC-nnn · next AGC-nnn ▶` — normal case; link both directions.
- `◀ — (first scenario) · next AGC-002 ▶` — first scenario.
- `◀ AGC-099 · — (last scenario) ▶` — last scenario.

Each side of the chain is a clickable relative link to the neighbour scenario's `README.md`. The chain lets a reader walk the whole narrative kill chain end-to-end, one scenario at a time, without going back to the index. A short parenthetical after an ID marks a category boundary, e.g. `next AGC-019 (Persistence category) ▶`. AGC-076 closes the main narrative and points forward to the first full-chain capstone; AGC-077 – AGC-080 link to each other as `related:` rather than `next`, because each is a standalone incident.

## Evidence

All evidence is **textual and embedded directly** in the report sections (Detection, Investigation). This includes:

- Command output (verbatim, timestamped)
- Sysmon Event IDs and field values
- Wazuh alert JSON excerpts
- Security Onion / Zeek / Suricata log entries
- File contents and header analysis

The reference pass (executed and documented by Claude Code under direction and review by Ali, through VirtualBox Guest Control) captured no screenshots, so every scenario's `## Evidence` section currently reads:

> Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

When a scenario is re-executed by hand, its screenshots go in a `screenshots/` subfolder next to the `README.md`, numbered in reference order (`01-*.png`, `02-*.png`), each embedded inline in the subsection it evidences with a caption saying what to look at. The folder is created only when the first image lands — an empty `screenshots/` folder is never committed.

## Starting a new scenario

Copy the appropriate template into the target scenario folder and rename to `README.md`:

- **Regular scenarios (96 of them):** copy [`templates/standard-scenario-readme.md`](templates/standard-scenario-readme.md) to `scenarios/<category>/<AGC-nnn-slug>/README.md`.
- **Full Attack-Chain scenarios (AGC-077…080):** copy [`templates/full-chain-scenario-readme.md`](templates/full-chain-scenario-readme.md) to `scenarios/13-full-attack-chain/<AGC-nnn-slug>/README.md`.

Then fill each section top-to-bottom, in the same order a real incident unfolds: understand the tradecraft, run the simulation, watch the detection fire, work the investigation, write the report, map to MITRE.
