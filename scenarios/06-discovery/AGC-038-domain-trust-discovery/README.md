# AGC-038 -- Domain Trust Discovery

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-038` |
| Category | `06-discovery` -- Discovery |
| MITRE Technique | `T1482` Domain Trust Discovery |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Immediate -- Sysmon EID 1 captures `nltest.exe` with trust enumeration arguments |
| Time to Triage | 02:00 (verify account context -- `nltest /domain_trusts` from a workstation/non-admin account is highly unusual) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | < AGC-037 . next AGC-039 > |
| One-line Summary | Domain trust enumeration via `nltest /domain_trusts`, `nltest /trusted_domains`, `nltest /dsgetdc:`, and `net group "Domain Admins" /domain` from Administrator on a workstation. Sysmon EID 1 captured all 5 process creation events. Single-domain forest (ASHFORDGROVE) confirmed; no external trusts. DC discovery failed (broken domain trust). |

## Attacker Perspective

### Tradecraft

**What:** Domain trust discovery maps the Active Directory trust relationships to identify paths for lateral movement across domain boundaries. In a multi-domain or multi-forest environment, trust relationships define which domains can authenticate to each other. An attacker enumerates trusts to:
- Identify other domains or forests that can be reached from the current domain
- Find bidirectional trusts that allow lateral movement without additional credentials
- Discover forest trusts that may lead to higher-value targets (parent domain, resource forests)

Key enumeration tools:
- `nltest /domain_trusts` -- lists all trusted domains with trust type and attributes
- `nltest /trusted_domains` -- simplified trust listing
- `nltest /dsgetdc:<domain>` -- discovers domain controllers for a specific domain
- `Get-ADTrust -Filter *` -- PowerShell RSAT cmdlet for detailed trust information
- `net group "Domain Admins" /domain` -- enumerates domain admin group members

**Why at this lifecycle stage:** After the discovery burst (AGC-037) established basic host context, the attacker escalates to domain-level reconnaissance. Trust enumeration answers: "can I reach other domains from here?" and "who are the domain admins I need to target?" This directly informs lateral movement strategy.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.
- `AD-DC-01` running (domain controller services -- but unreachable from COMPROMISED-HOST-01).

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Result |
|---|---|---|---|---|
| 1 | 2026-09-15 20:36:40 | nltest /domain_trusts | COMPROMISED-HOST-01 | `ASHFORDGROVE ashfordgrove.local (NT 5) (Forest Tree Root) (Primary Domain) (Native)` -- single domain, no external trusts |
| 2 | 2026-09-15 20:36:52 | nltest /trusted_domains | COMPROMISED-HOST-01 | Same result -- confirms single-domain forest |
| 3 | 2026-09-15 20:36:52 | nltest /dsgetdc:ashfordgrove.local | COMPROMISED-HOST-01 | `ERROR_NO_SUCH_DOMAIN` (Status 1355) -- cannot locate DC due to broken domain trust |
| 4 | 2026-09-15 20:36:52 | Get-ADTrust -Filter * | COMPROMISED-HOST-01 | Command not recognized -- RSAT AD module not installed on workstation |
| 5 | 2026-09-15 20:36:53 | net group "Domain Admins" /domain | COMPROMISED-HOST-01 | Error 1355: "specified domain either does not exist or could not be contacted" |

**Key findings:**
- Single-domain forest (`ASHFORDGROVE`), no external or forest trusts -- lateral movement is limited to this domain
- Domain controller discovery fails (broken trust) -- attacker cannot reach the DC for further domain queries
- RSAT AD module not installed -- `Get-ADTrust` unavailable on workstation (typical for non-admin workstations)

**Cleanup:** No persistent artifacts. Commands are read-only.

## SOC Perspective

### Detection

**Sysmon EID 1 -- Process Create (5 events in 13 seconds):**

| Timestamp (UTC) | Image | CommandLine | PID | User | IntegrityLevel |
|---|---|---|---|---|---|
| 2026-09-15 20:36:40 | nltest.exe | `nltest.exe /domain_trusts` | 5556 | Administrator | High |
| 2026-09-15 20:36:52 | nltest.exe | `nltest.exe /trusted_domains` | 6080 | Administrator | High |
| 2026-09-15 20:36:52 | nltest.exe | `nltest.exe /dsgetdc:ashfordgrove.local` | 3360 | Administrator | High |
| 2026-09-15 20:36:53 | net.exe | `net.exe group "Domain Admins" /domain` | 5716 | Administrator | High |
| 2026-09-15 20:36:53 | net1.exe | `net1 group "Domain Admins" /domain` | 5980 | Administrator | High |

All share `LogonGuid: {eb65e329-ac58-6aa9-47ff-540000000000}`, same session as discovery burst.
nltest.exe hash: `MD5=55F4C5F19EE3E0C5C6640D02AF0D14EE`.

### Investigation

**Step 1 -- Assess nltest usage context:**
`nltest /domain_trusts` and `/trusted_domains` are rarely used in routine desktop activity. These are domain-administration and troubleshooting commands. A single occurrence from a non-IT-admin account or from a standard workstation warrants review. In this case: executed by Administrator (RID-500) on COMPROMISED-HOST-01, a member workstation -- not a domain controller or IT management station.

**Step 2 -- Account context analysis:**
The executing account is the built-in Administrator, which gained access through the attack chain (AGC-001 phishing -> privilege escalation). This is NOT a helpdesk account performing legitimate domain diagnostics. The account context strongly supports malicious intent.

**Step 3 -- Correlate with surrounding activity:**
This follows immediately after the AGC-037 discovery burst (systeminfo, whoami, ipconfig, net user) from the same host. The escalation from host-level discovery (AGC-037) to domain-level discovery (AGC-038) is a natural attack progression: after mapping the local host, the attacker maps the domain.

The `net group "Domain Admins" /domain` command is particularly significant -- it attempts to enumerate the domain admin group, which is the highest-value target for privilege escalation across the domain.

**Step 4 -- Detection reuse:**
Alert rule: any `nltest.exe` execution with `/domain_trusts`, `/trusted_domains`, or `/dsgetdc:` arguments from a non-domain-controller host. This is a low-noise, high-value detection because these arguments have almost no legitimate use on workstations.

### Report

**Verdict: True Positive** -- Domain trust enumeration was executed from a compromised workstation by the Administrator account, following host-level discovery (AGC-037).

**Confidence: High** -- Calibrated assessment:
1. `nltest /domain_trusts` from a workstation has almost no legitimate use case -- unlike `systeminfo` or `ipconfig`, it is not a standard troubleshooting command.
2. Account context (Administrator on a compromised workstation) provides no benign explanation.
3. The progression from host discovery (AGC-037) to domain trust discovery (AGC-038) follows a documented attack pattern.
4. The `net group "Domain Admins"` command explicitly targets privilege escalation intelligence.

**Response recommendation:**
1. **Investigate the account and host** for broader compromise indicators -- this is not an isolated event but part of a chain.
2. **No direct remediation needed** for the discovery itself (read-only commands) -- but it confirms the attacker is actively mapping the domain for lateral movement.
3. **Anticipate the next step** -- after trust discovery, expect lateral movement attempts (RDP, PsExec, WMI to other domain hosts) or targeted attacks against the domain admin accounts identified.
4. **Detection rule:** Alert on `nltest.exe` with trust-related arguments from non-DC hosts. Low false-positive rate, high signal value.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Discovery (TA0007) | T1482 | Domain Trust Discovery | Sysmon EID 1: `nltest.exe /domain_trusts`, `/trusted_domains`, `/dsgetdc:ashfordgrove.local` executed by Administrator on workstation. Single-domain forest (ASHFORDGROVE) enumerated. DC discovery failed (broken trust). `net group "Domain Admins" /domain` attempted (error 1355). | High |

## Evidence

Screenshots: not applicable (text-based evidence collection only).

### Raw nltest output

```
List of domain trusts:
    0: ASHFORDGROVE ashfordgrove.local (NT 5) (Forest Tree Root) (Primary Domain) (Native)
The command completed successfully
```

### Raw Sysmon EID 1 (nltest /domain_trusts)

```
Process Create:
UtcTime: 2026-09-15 20:36:40.791
ProcessId: 5556
Image: C:\Windows\System32\nltest.exe
OriginalFileName: nltestrk.exe
CommandLine: "C:\WINDOWS\system32\nltest.exe" /domain_trusts
User: COMPROMISED-01\Administrator
LogonGuid: {eb65e329-ac58-6aa9-47ff-540000000000}
LogonId: 0x54FF47
IntegrityLevel: High
Hashes: MD5=55F4C5F19EE3E0C5C6640D02AF0D14EE
```

### Raw Sysmon EID 1 (net group "Domain Admins")

```
Process Create:
UtcTime: 2026-09-15 20:36:53.833
ProcessId: 5716
Image: C:\Windows\System32\net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" group "Domain Admins" /domain
User: COMPROMISED-01\Administrator
LogonGuid: {eb65e329-ac58-6aa9-47ff-540000000000}
IntegrityLevel: High
Hashes: MD5=8A1E71312BD2AAE202652113049CDBD1
```
