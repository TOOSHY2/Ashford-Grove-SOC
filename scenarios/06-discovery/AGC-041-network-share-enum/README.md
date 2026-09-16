# AGC-041 — Network Share Enumeration Sweep

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-041` |
| Category | `06-discovery` — Discovery |
| MITRE Technique | `T1135` Network Share Discovery |
| Verdict | True Positive |
| Confidence | Medium |
| Time to Detect | Immediate — Sysmon EID 1 captures `net.exe view` with target IP in command line |
| Time to Triage | 03:00 (count distinct destination IPs in the sweep; check for subsequent file access on discovered shares) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) as source; targets: AD-DC-01 (10.10.10.10), WIN-CLIENT-01 (10.10.10.101), WIN-CLIENT-02 (10.10.10.102) |
| Chain | ◀ [AGC-040](../AGC-040-service-process-discovery/README.md) · next [AGC-042](../AGC-042-ad-object-query-burst/README.md) ▶ |
| One-line Summary | Systematic multi-host network share enumeration: `net view` against DC (10.10.10.10), WIN-CLIENT-01 (10.10.10.101), WIN-CLIENT-02 (10.10.10.102), and self (10.10.10.103), plus `net share` for local shares. All remote targets returned error 53 (network path not found). Local shares: C$, IPC$, ADMIN$ (default admin shares only). 6 Sysmon EID 1 events captured. The multi-host sweep pattern distinguishes this from routine single-share access. |

## Attacker Perspective

### Tradecraft

**What:** Network share discovery enumerates SMB/CIFS shares across the network to identify:
- **Data stores** — file shares containing sensitive documents, databases, backups
- **Administrative shares** — C$, ADMIN$, IPC$ that indicate admin-level access is possible
- **Lateral movement paths** — writable shares that can be used to stage payloads

The key tradecraft distinction is the **sweep pattern**: querying multiple hosts sequentially from a single source. A legitimate user typically accesses one known share path. An attacker systematically enumerates shares across all reachable hosts, often using IP addresses rather than hostnames (indicating enumeration from a list rather than from memory).

**Why at this lifecycle stage:** After identifying the network (AGC-037), domain (AGC-038), privileged accounts (AGC-039), and security tools (AGC-040), the attacker now maps accessible data. Network shares are the primary data stores in enterprise environments and the most common exfiltration source. This also informs lateral movement — writable shares on other hosts can be used to stage and execute payloads.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.
- Target VMs running: AD-DC-01, WIN-CLIENT-01, WIN-CLIENT-02.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Result |
|---|---|---|---|---|
| 1 | 2026-09-15 20:49:06 | net view \\\\10.10.10.10 | COMPROMISED-HOST-01 | Error 53: network path not found (DC unreachable) |
| 2 | 2026-09-15 20:49:28 | net view \\\\10.10.10.101 | COMPROMISED-HOST-01 | Error 53: network path not found |
| 3 | 2026-09-15 20:49:49 | net view \\\\10.10.10.102 | COMPROMISED-HOST-01 | Error 53: network path not found |
| 4 | 2026-09-15 20:50:10 | net view \\\\10.10.10.103 | COMPROMISED-HOST-01 | "There are no entries in the list" (no shared folders) |
| 5 | 2026-09-15 20:50:10 | net share | COMPROMISED-HOST-01 | Local shares: C$, IPC$, ADMIN$ (defaults only) |

Each remote `net view` timed out after ~20 seconds before returning error 53.

**Key findings:**
- All three remote hosts returned error 53 — network connectivity issues prevent share enumeration (consistent with broken domain trust and network isolation observed in prior scenarios)
- Self-enumeration (10.10.10.103) returned no shared folders — no custom shares configured
- Local `net share` confirmed only default administrative shares (C$, IPC$, ADMIN$)
- Despite failures, the **enumeration attempt** itself is the indicator — the attacker tried to map shares across 4 hosts systematically

**Cleanup:** No persistent artifacts. Commands are read-only.

## SOC Perspective

### Detection

**Sysmon EID 1 — Process Create (6 events across 64 seconds):**

| Timestamp (UTC) | Image | CommandLine | PID | User |
|---|---|---|---|---|
| 2026-09-15 20:49:06 | net.exe | `net.exe view \\10.10.10.10` | 5816 | Administrator |
| 2026-09-15 20:49:28 | net.exe | `net.exe view \\10.10.10.101` | 5692 | Administrator |
| 2026-09-15 20:49:49 | net.exe | `net.exe view \\10.10.10.102` | 4952 | Administrator |
| 2026-09-15 20:50:10 | net.exe | `net.exe view \\10.10.10.103` | 8 | Administrator |
| 2026-09-15 20:50:10 | net.exe | `net.exe share` | 3560 | Administrator |
| 2026-09-15 20:50:10 | net1.exe | `net1 share` | 5592 | Administrator |

All share `LogonGuid: {eb65e329-af42-6aa9-df20-570000000000}`, confirming single session.

**Sysmon EID 3 (Network Connection):** 0 events — EID 3 is filtered for `net.exe` by the SwiftOnSecurity Sysmon configuration. SMB connection attempts were not logged at the Sysmon level. Network-level detection (Security Onion, firewall logs) would capture these connection attempts.

### Investigation

**Step 1 — Identify the multi-host sweep pattern:**
The critical indicator is `net view` targeting **4 distinct IP addresses** from the same source within 64 seconds. A legitimate user browses to a known share path (e.g., `\\fileserver\shared`). An attacker enumerates shares across multiple hosts by IP address, indicating systematic reconnaissance from a host list rather than routine file access.

**Step 2 — Check for follow-on file access:**
After share enumeration, check whether the source host subsequently accessed any discovered shares (SMB read/write operations, file copies). Share enumeration WITHOUT follow-on access is consistent with reconnaissance-only behavior. Share enumeration WITH follow-on access could indicate either legitimate use or data staging for exfiltration.

In this case: all remote enumeration failed (error 53), so no follow-on access was possible. The reconnaissance intent is unambiguous.

**Step 3 — Correlate with discovery chain:**
This is the fifth stage of the documented discovery progression:
- AGC-037: Host discovery -> AGC-038: Domain trust -> AGC-039: Privileged groups -> AGC-040: Services/processes -> AGC-041: Network shares

The consistent progression from general to specific, targeting increasingly operational intelligence, confirms coordinated attack reconnaissance.

**Step 4 — Detection reuse:**
Alert rule: 2+ `net view \\<IP>` commands from the same LogonGuid targeting distinct destination IPs within 5 minutes. This detects the sweep pattern while excluding single-share lookups. Combining with the AGC-037 burst detection further reduces false positives.

### Report

**Verdict: True Positive** — Systematic multi-host share enumeration was executed from a compromised workstation, targeting the DC and two client workstations.

**Confidence: Medium** — Calibrated assessment:
1. `net view` is a standard networking tool, and a single `net view \\server` is common IT troubleshooting.
2. The multi-host sweep pattern (4 distinct IPs in 64 seconds, by IP rather than hostname) is not typical of legitimate use and distinguishes this from routine activity.
3. All remote enumerations failed (error 53), confirming this was a blind sweep rather than targeted access to known shares.
4. Confidence stays Medium because `net view` sweeps can be generated by legitimate network inventory tools or IT troubleshooting scripts. Elevation to High requires confirmation that no IT inventory tool or script was running.

**Response recommendation:**
1. **Monitor discovered shares** — the attacker now knows that COMPROMISED-HOST-01 has only default admin shares (C$, IPC$, ADMIN$). If network connectivity is restored, expect the attacker to target C$ on other hosts for lateral movement.
2. **No direct remediation needed** for the enumeration itself (read-only) — but use it to anticipate the next attack stage (data collection or lateral movement via SMB).
3. **Detection rule:** Alert on 2+ `net view` commands targeting distinct IPs from the same source within 5 minutes. Cross-correlate with prior discovery alerts from the same LogonGuid.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Discovery (TA0007) | T1135 | Network Share Discovery | Sysmon EID 1: `net.exe view` against 4 distinct IPs (10.10.10.10, .101, .102, .103) plus `net.exe share` for local shares. Multi-host sweep pattern in 64 seconds. Remote targets: error 53. Local: C$, IPC$, ADMIN$ defaults. | Medium |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### Local shares (net share)

```
Share name   Resource                        Remark

-------------------------------------------------------------------------------
C$           C:\                             Default share
IPC$                                         Remote IPC
ADMIN$       C:\WINDOWS                      Remote Admin
The command completed successfully.
```

### Raw Sysmon EID 1 (net view \\10.10.10.10)

```
Process Create:
UtcTime: 2026-09-15 20:49:06.930
ProcessId: 5816
Image: C:\Windows\System32\net.exe
OriginalFileName: net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" view \\10.10.10.10
User: COMPROMISED-01\Administrator
LogonGuid: {eb65e329-af42-6aa9-df20-570000000000}
LogonId: 0x5720DF
IntegrityLevel: High
Hashes: MD5=8A1E71312BD2AAE202652113049CDBD1
```

### Raw Sysmon EID 1 (net view \\10.10.10.101)

```
Process Create:
UtcTime: 2026-09-15 20:49:28.028
ProcessId: 5692
Image: C:\Windows\System32\net.exe
OriginalFileName: net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" view \\10.10.10.101
User: COMPROMISED-01\Administrator
LogonGuid: {eb65e329-af42-6aa9-df20-570000000000}
LogonId: 0x5720DF
IntegrityLevel: High
Hashes: MD5=8A1E71312BD2AAE202652113049CDBD1
```

### Raw Sysmon EID 1 (net view \\10.10.10.102)

```
Process Create:
UtcTime: 2026-09-15 20:49:49.115
ProcessId: 4952
Image: C:\Windows\System32\net.exe
OriginalFileName: net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" view \\10.10.10.102
User: COMPROMISED-01\Administrator
LogonGuid: {eb65e329-af42-6aa9-df20-570000000000}
LogonId: 0x5720DF
IntegrityLevel: High
Hashes: MD5=8A1E71312BD2AAE202652113049CDBD1
```
