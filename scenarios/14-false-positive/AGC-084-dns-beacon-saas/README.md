# AGC-084: DNS Beacon Pattern -- Legitimate SaaS Update Checker (False Positive)

## Scenario Overview

| Field              | Value                                                        |
|--------------------|--------------------------------------------------------------|
| **Scenario ID**    | AGC-084                                                      |
| **Title**          | DNS Beacon Pattern: Legitimate SaaS Update-Checker           |
| **Category**       | False Positive Triage (14-false-positive)                    |
| **Severity**       | Medium (alert trigger)                                       |
| **MITRE Techniques** | T1071.004 (observed, not malicious)                        |
| **Verdict**        | False Positive / Benign                                      |
| **Confidence**     | High                                                         |
| **Malicious Twin** | AGC-052 (DNS C2 Beaconing)                                   |

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

**Navigation:** [< AGC-083](../../14-false-positive/AGC-083-lsass-av-selfscan/README.md) | [AGC-085 >](../../14-false-positive/AGC-085-offhours-service-account/README.md)

## Alert / Trigger

Periodic DNS queries to `a1b2c3d4-update.agc084vendor-demo.local` detected from COMPROMISED-HOST-01, repeating at regular ~15-second intervals (60 seconds in production). The periodic pattern and subdomain structure match the detection signature for DNS C2 beaconing (AGC-052). The triage question: is this a legitimate application update check, or DNS-based command-and-control communication?

## Simulation Summary

Documented a software inventory entry for AGC084DemoApp v2.1 (installed 2026-09-02, vendor update domain documented). Then executed 4 DNS queries to `a1b2c3d4-update.agc084vendor-demo.local` at 15-second intervals via `nslookup` against the external DNS server (10.10.40.10). The instance ID `a1b2c3d4` remained constant across all queries.

**Execution window**: 00:45:54 - 00:46:39 UTC on COMPROMISED-HOST-01

## Investigation

### Step 1: Identify the DNS Pattern

**Sysmon EID 1 -- nslookup.exe query 1 (PID 3600):**
```
UtcTime: 2026-09-16 00:45:54.212
ProcessId: 3600
Image: C:\Windows\System32\nslookup.exe
CommandLine: "C:\WINDOWS\system32\nslookup.exe" a1b2c3d4-update.agc084vendor-demo.local 10.10.40.10
User: COMPROMISED-01\Administrator
```

**Sysmon EID 1 -- nslookup.exe query 2 (PID 4472):**
```
UtcTime: 2026-09-16 00:46:09.301
ProcessId: 4472
Image: C:\Windows\System32\nslookup.exe
CommandLine: "C:\WINDOWS\system32\nslookup.exe" a1b2c3d4-update.agc084vendor-demo.local 10.10.40.10
```

**Sysmon EID 1 -- nslookup.exe query 3 (PID 3932):**
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

### Step 2: Subdomain Consistency Analysis (Critical Discriminator)

Comparing the subdomain component across all 4 queries:

| Query | Timestamp | Subdomain | Instance ID |
|-------|-----------|-----------|-------------|
| 1 | 00:45:54 | `a1b2c3d4-update` | `a1b2c3d4` |
| 2 | 00:46:09 | `a1b2c3d4-update` | `a1b2c3d4` |
| 3 | 00:46:24 | `a1b2c3d4-update` | `a1b2c3d4` |
| 4 | 00:46:39 | `a1b2c3d4-update` | `a1b2c3d4` |

The instance ID is **constant** across all queries. This is the structural difference from DNS C2 beaconing (AGC-052), where each query contains a **random** subdomain encoding exfiltrated data or C2 instructions.

### Step 3: Cross-Reference Software Inventory

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
- Documents the polling interval (60 seconds; lab used 15s for efficiency)

### Step 4: Entropy Analysis

The subdomain `a1b2c3d4` has moderate entropy but is deterministic -- the same value repeats every cycle. In contrast, DNS C2 subdomains exhibit high entropy AND variability (new random string each query). A naive entropy-based detection would flag both; the discriminating signal is consistency across time, not entropy of a single query.

## Discriminating Evidence (Benign vs Malicious)

| Factor | AGC-084 (Benign) | AGC-052 (Malicious) |
|--------|-------------------|---------------------|
| **Subdomain consistency** | CONSTANT (`a1b2c3d4` every query) | RANDOM (new value each query) |
| **Software inventory** | Documented: AGC084DemoApp, domain + interval match | No inventory match for queried domain |
| **Subdomain purpose** | Static installation identifier | Encoded data exfiltration or C2 commands |
| **Domain reputation** | Vendor domain in approved inventory | Unknown or suspicious domain |
| **Interval pattern** | Matches documented vendor specification | Matches C2 jitter pattern |
| **DNS query type** | Standard A/TXT lookup | TXT records with encoded payloads |

**The subdomain consistency check is the strongest technical discriminator.** Software inventory match alone is insufficient (the application could be compromised while still appearing in inventory). Both checks together produce a clean False Positive determination.

## MITRE ATT&CK Mapping

No malicious technique applies. The alert fires through the same detection rules as AGC-052:

| Technique ID | Name | Tactic | Disposition |
|-------------|------|--------|-------------|
| T1071.004 | Application Layer Protocol: DNS | Command and Control | **Observed, Benign** -- Periodic DNS queries with constant subdomain (`a1b2c3d4`) to documented vendor domain. Matches software inventory for AGC084DemoApp v2.1. |

## Conclusion

**Verdict: False Positive / Benign** -- The periodic DNS queries to `a1b2c3d4-update.agc084vendor-demo.local` are generated by a legitimate SaaS update checker (AGC084DemoApp v2.1). The subdomain is constant across all queries (static installation identifier), distinguishing it from DNS C2 beaconing where each query contains a unique random subdomain. The domain and polling behavior match the documented software inventory entry.

**Recommendation**: Close as Benign. Add the `*-update.agc084vendor-demo.local` pattern to the DNS detection allowlist with the documented instance ID. Consider implementing a detection refinement that checks subdomain variability over time windows rather than flagging on individual query entropy -- this would reduce false positives from legitimate update pollers while preserving detection of actual DNS C2 beaconing.

**Cross-reference**: The malicious twin of this scenario is **AGC-052**, where periodic DNS queries use random subdomains per query to encode C2 communication, with no corresponding software inventory documentation.
