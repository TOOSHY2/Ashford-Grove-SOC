# AGC-084 — DNS Beacon Pattern: Legitimate SaaS Update Checker (False Positive)

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-084` |
| Title | DNS Beacon Pattern: Legitimate SaaS Update-Checker |
| Category | `14-false-positive` — False Positive Triage |
| Severity | Medium (alert trigger) |
| MITRE Technique | T1071.004 (observed, not malicious) |
| Verdict | False Positive / Benign |
| Confidence | High |
| Malicious Twin | AGC-052 (DNS C2 Beaconing) |
| Chain | ◀ [AGC-083](../AGC-083-lsass-av-selfscan/README.md) · next [AGC-085](../AGC-085-offhours-service-account/README.md) ▶ |

## Attacker Perspective

### Simulation

Documented a software inventory entry for AGC084DemoApp v2.1 (installed 2026-09-02, vendor update domain recorded). Then ran 4 `nslookup` queries for `a1b2c3d4-update.agc084vendor-demo.local` at 15-second intervals against the external DNS server (10.10.40.10). The instance ID `a1b2c3d4` stayed constant across all four.

**Execution window**: 00:45:54 - 00:46:39 UTC on COMPROMISED-HOST-01

## SOC Perspective

### Detection

COMPROMISED-HOST-01 sent periodic DNS queries for `a1b2c3d4-update.agc084vendor-demo.local` at regular ~15-second intervals (60 seconds in production). The cadence and subdomain structure match the DNS C2 beaconing signature (AGC-052). The triage question: an application checking for updates, or DNS-based command-and-control?

### Investigation

#### Step 1: Identify the DNS Pattern

**Sysmon EID 1 — nslookup.exe query 1 (PID 3600):**
```
UtcTime: 2026-09-16 00:45:54.212
ProcessId: 3600
Image: C:\Windows\System32\nslookup.exe
CommandLine: "C:\WINDOWS\system32\nslookup.exe" a1b2c3d4-update.agc084vendor-demo.local 10.10.40.10
User: COMPROMISED-01\Administrator
```

**Sysmon EID 1 — nslookup.exe query 2 (PID 4472):**
```
UtcTime: 2026-09-16 00:46:09.301
ProcessId: 4472
Image: C:\Windows\System32\nslookup.exe
CommandLine: "C:\WINDOWS\system32\nslookup.exe" a1b2c3d4-update.agc084vendor-demo.local 10.10.40.10
```

**Sysmon EID 1 — nslookup.exe query 3 (PID 3932):**
```
UtcTime: 2026-09-16 00:46:24.378
ProcessId: 3932
Image: C:\Windows\System32\nslookup.exe
CommandLine: "C:\WINDOWS\system32\nslookup.exe" a1b2c3d4-update.agc084vendor-demo.local 10.10.40.10
```

**DNS response** (all 4 queries identical):
```
Server: 10.10.40.10
Name: a1b2c3d4-update.agc084vendor-demo.local
Address: 10.10.40.10
```

Interval analysis: Query 1 at :54, Query 2 at :09 (+15s), Query 3 at :24 (+15s), Query 4 at :39 (+15s). Regular cadence.

#### Step 2: Subdomain Consistency Analysis (Critical Discriminator)

Comparing the subdomain component across all 4 queries:

| Query | Timestamp | Subdomain | Instance ID |
|-------|-----------|-----------|-------------|
| 1 | 00:45:54 | `a1b2c3d4-update` | `a1b2c3d4` |
| 2 | 00:46:09 | `a1b2c3d4-update` | `a1b2c3d4` |
| 3 | 00:46:24 | `a1b2c3d4-update` | `a1b2c3d4` |
| 4 | 00:46:39 | `a1b2c3d4-update` | `a1b2c3d4` |

The instance ID is **constant** across all queries. That is the structural difference from DNS C2 beaconing (AGC-052), where each query carries a **random** subdomain that encodes exfiltrated data or C2 instructions.

#### Step 3: Cross-Reference Software Inventory

Pre-documented software inventory entry (installed 2026-09-02):

```
Software Inventory Entry
Application: AGC084DemoApp v2.1
Installed: 2026-09-02
Vendor: AGC Demo Software Inc.
Update Check Domain: update.agc084vendor-demo.local
Update Check Interval: 60 seconds
Subdomain Pattern: <instance-id>-update.agc084vendor-demo.local
Instance ID: a1b2c3d4 (fixed per installation)
Approved By: IT Operations
```

The inventory entry:
- Names the exact domain (`update.agc084vendor-demo.local`) matching the queries
- Documents the subdomain pattern (`<instance-id>-update`) matching observed structure
- Specifies the instance ID (`a1b2c3d4`) matching all observed queries
- Documents the polling interval (60 seconds; the lab used 15s to save time)

#### Step 4: Entropy Analysis

The subdomain `a1b2c3d4` has moderate entropy but is deterministic — the same value repeats every cycle. DNS C2 subdomains have high entropy AND change with every query. A detection that scores entropy alone would flag both; the signal that separates them is consistency over time.

### Report

**Verdict: False Positive / Benign** — The periodic DNS queries to `a1b2c3d4-update.agc084vendor-demo.local` come from the AGC084DemoApp v2.1 update checker. The subdomain is a static installation identifier that never changes between queries, unlike DNS C2 beaconing where every query carries a fresh random subdomain. Domain and polling interval match the software inventory entry.

**Recommendation**: Close as Benign. Add the `*-update.agc084vendor-demo.local` pattern to the DNS allowlist with the documented instance ID. Refine the rule to score subdomain variability over a time window instead of single-query entropy — that drops update pollers like this one while still catching DNS C2 beaconing.

**Cross-reference**: The malicious twin is **AGC-052**, where each periodic query carries a random subdomain encoding C2 traffic and no software inventory entry explains the domain.

#### Discriminating evidence (benign vs malicious)

| Factor | AGC-084 (Benign) | AGC-052 (Malicious) |
|--------|-------------------|---------------------|
| **Subdomain consistency** | CONSTANT (`a1b2c3d4` every query) | RANDOM (new value each query) |
| **Software inventory** | Documented: AGC084DemoApp, domain + interval match | No inventory match for queried domain |
| **Subdomain purpose** | Static installation identifier | Encoded data exfiltration or C2 commands |
| **Domain reputation** | Vendor domain in approved inventory | Unknown or suspicious domain |
| **Interval pattern** | Matches documented vendor specification | Matches C2 jitter pattern |
| **DNS query type** | Standard A/TXT lookup | TXT records with encoded payloads |

**The subdomain consistency check is the strongest technical discriminator.** An inventory match alone is not enough — a compromised application still appears in inventory. Both checks together give a clean false positive.

### MITRE Mapping

No malicious technique applies. The alert fires through the same detection rules as AGC-052:

| Technique ID | Name | Tactic | Disposition |
|-------------|------|--------|-------------|
| T1071.004 | Application Layer Protocol: DNS | Command and Control | **Observed, Benign** — Periodic DNS queries with constant subdomain (`a1b2c3d4`) to documented vendor domain. Matches software inventory for AGC084DemoApp v2.1. |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
