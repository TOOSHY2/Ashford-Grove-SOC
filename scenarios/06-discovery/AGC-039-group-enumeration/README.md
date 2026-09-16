# AGC-039 — Privileged Group Enumeration

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-039` |
| Category | `06-discovery` — Discovery |
| MITRE Technique | `T1069.001` Permission Groups Discovery: Local Groups / `T1069.002` Permission Groups Discovery: Domain Groups |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Immediate — Sysmon EID 1 captures `net.exe localgroup` and `net.exe group` with group names in command line |
| Time to Triage | 02:00 (check whether the queried group names are privileged — "Domain Admins" / "Enterprise Admins" vs. generic local groups) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ [AGC-038](../AGC-038-domain-trust-discovery/README.md) · next [AGC-040](../AGC-040-service-process-discovery/README.md) ▶ |
| One-line Summary | Targeted enumeration of privileged groups: `net localgroup administrators`, `net localgroup "Remote Desktop Users"`, `net group "Domain Admins" /domain`, `net group "Enterprise Admins" /domain`, and `Get-ADGroupMember` attempt. 8 Sysmon EID 1 events in 12 seconds. Local administrators group revealed: Administrator + wadmin. Domain group queries failed (broken trust, error 1355). The specificity of querying "Domain Admins" and "Enterprise Admins" by name distinguishes this from routine discovery. |

## Attacker Perspective

### Tradecraft

**What:** Permission groups discovery lists group memberships to find privileged accounts worth targeting. Two sub-techniques apply:

- **T1069.001 — Local Groups:** `net localgroup administrators` shows which accounts hold local admin rights on the host. Those accounts become credential-harvesting targets and candidates for lateral movement.
- **T1069.002 — Domain Groups:** `net group "Domain Admins" /domain` and `net group "Enterprise Admins" /domain` list the highest-privilege domain groups. Their members are the end targets — those credentials unlock the whole domain.

The tradecraft tell is **specificity**. An attacker who asks for "Domain Admins" by name has already chosen the target and is collecting membership. That is a step past the broad discovery in AGC-037 and the trust mapping in AGC-038.

**Why at this lifecycle stage:** After host discovery (AGC-037) and trust discovery (AGC-038), the attacker needs names. The progression runs: What system am I on? -> What domain is this? -> Who are the admins? The answer feeds lateral movement (AGC-043+) and credential targeting.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.
- `AD-DC-01` running (domain controller services — but unreachable from COMPROMISED-HOST-01 due to broken trust).

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Result |
|---|---|---|---|---|
| 1 | 2026-09-15 20:42:57 | net localgroup administrators | COMPROMISED-HOST-01 | Members: `Administrator`, `wadmin` |
| 2 | 2026-09-15 20:43:09 | net localgroup "Remote Desktop Users" | COMPROMISED-HOST-01 | Empty group (no RDP users configured) |
| 3 | 2026-09-15 20:43:09 | net group "Domain Admins" /domain | COMPROMISED-HOST-01 | Error 1355: DC unreachable (broken trust) |
| 4 | 2026-09-15 20:43:09 | net group "Enterprise Admins" /domain | COMPROMISED-HOST-01 | Error 1355: DC unreachable (broken trust) |
| 5 | 2026-09-15 20:43:09 | Get-ADGroupMember -Identity "Domain Admins" | COMPROMISED-HOST-01 | Not available (RSAT AD module not installed) |

**Key findings:**
- Local admin group contains `Administrator` (RID-500) and `wadmin` — both are credential targets
- Remote Desktop Users is empty — no RDP lateral movement targets from this group
- Domain group queries failed due to broken trust — attacker cannot enumerate domain admin members from this host
- RSAT AD module not installed — `Get-ADGroupMember` unavailable on workstation

**Cleanup:** No persistent artifacts. All commands are read-only.

## SOC Perspective

### Detection

**Sysmon EID 1 — Process Create (8 events in 12 seconds):**

| Timestamp (UTC) | Image | CommandLine | PID | User | IntegrityLevel |
|---|---|---|---|---|---|
| 2026-09-15 20:42:57 | net.exe | `net.exe localgroup administrators` | 3240 | Administrator | High |
| 2026-09-15 20:42:57 | net1.exe | `net1 localgroup administrators` | 2192 | Administrator | High |
| 2026-09-15 20:43:09 | net.exe | `net.exe localgroup "Remote Desktop Users"` | 4552 | Administrator | High |
| 2026-09-15 20:43:09 | net1.exe | `net1 localgroup "Remote Desktop Users"` | 3968 | Administrator | High |
| 2026-09-15 20:43:09 | net.exe | `net.exe group "Domain Admins" /domain` | 4400 | Administrator | High |
| 2026-09-15 20:43:09 | net1.exe | `net1 group "Domain Admins" /domain` | 4436 | Administrator | High |
| 2026-09-15 20:43:09 | net.exe | `net.exe group "Enterprise Admins" /domain` | 5976 | Administrator | High |
| 2026-09-15 20:43:09 | net1.exe | `net1 group "Enterprise Admins" /domain` | 3820 | Administrator | High |

All share `LogonGuid: {eb65e329-add0-6aa9-ebd7-550000000000}`, confirming single session.

### Investigation

**Step 1 — Assess the specificity of group queries:**
The signal is not "someone ran `net localgroup`" — IT does that all the time. The signal is **querying privileged groups by name**: "Domain Admins" and "Enterprise Admins". Whoever asks for those groups by name is mapping the privilege hierarchy, not poking around.

Compare:
- `net localgroup` (no argument) — broad, low signal
- `net localgroup administrators` — moderate signal (common for both IT and attackers)
- `net group "Domain Admins" /domain` — high signal (specific privileged group targeting)
- `net group "Enterprise Admins" /domain` — highest signal (enterprise-level privilege targeting)

**Step 2 — Account context:**
The executing account is the built-in Administrator (RID-500) on a workstation, not a domain controller or IT management station. No IT workflow needs "Enterprise Admins" membership pulled from a standard workstation. The account context offers no benign explanation.

**Step 3 — Correlate with prior discovery chain:**
This is the third stage of the discovery progression in this attack chain:
- AGC-037: Host-level discovery burst (systeminfo, whoami, ipconfig) — "What system am I on?"
- AGC-038: Domain trust discovery (nltest /domain_trusts) — "What domain is this?"
- AGC-039: Privileged group enumeration — "Who are the admins?"

General to specific, within the same attack session, rules out coincidence.

**Step 4 — Detection reuse:**
Same pattern as AGC-038: net.exe process creation captured by Sysmon EID 1. Alert rule: any `net.exe` command line containing "Domain Admins" OR "Enterprise Admins" OR "Schema Admins" from a non-DC host. False positives are rare because those group names have no routine use on workstations.

### Report

**Verdict: True Positive** — The Administrator account on COMPROMISED-HOST-01 queried "Domain Admins" and "Enterprise Admins" by name as the third stage of the discovery chain.

**Confidence: High** — Calibrated assessment:
1. Naming "Domain Admins" and "Enterprise Admins" is the differentiator. IT might run `net localgroup` routinely; nobody maps enterprise privilege by accident.
2. Administrator on a compromised workstation offers no benign explanation.
3. It follows AGC-037 (host discovery) and AGC-038 (domain trust discovery) in the expected order.
4. The failed domain queries (error 1355) still count — the attempt to list domain admin membership is the indicator, not the result.

**Response recommendation:**
1. **The local admin enumeration gave the attacker something usable** — they now know `Administrator` and `wadmin` are local admins. Rotate the `wadmin` credentials and watch the account for unauthorized use.
2. **The domain group queries failed (broken trust)** — which worked in the defenders' favor here. The attacker could not read domain admin membership. With the trust intact, that list would feed straight into targeted credential harvesting.
3. **Anticipate the next step** — with the local admins named, expect credential harvesting against those two accounts (SAM dump, LSASS access, Kerberoasting if the trust is restored).
4. **Detection rule:** Alert on `net.exe` command lines containing privileged group names ("Domain Admins", "Enterprise Admins", "Schema Admins", "Account Operators", "Backup Operators") from non-DC hosts. Near-zero false positives.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Discovery (TA0007) | T1069.001 | Permission Groups Discovery: Local Groups | Sysmon EID 1: `net.exe localgroup administrators` and `net.exe localgroup "Remote Desktop Users"` executed by Administrator. Local admin members: Administrator, wadmin. | High |
| Discovery (TA0007) | T1069.002 | Permission Groups Discovery: Domain Groups | Sysmon EID 1: `net.exe group "Domain Admins" /domain` and `net.exe group "Enterprise Admins" /domain` attempted by Administrator. Both failed (error 1355, broken trust). The attempt itself is the indicator. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### Raw net localgroup administrators output

```
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
wadmin
The command completed successfully.
```

### Raw Sysmon EID 1 (net localgroup administrators)

```
Process Create:
UtcTime: 2026-09-15 20:42:57.076
ProcessId: 3240
Image: C:\Windows\System32\net.exe
OriginalFileName: net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" localgroup administrators
User: COMPROMISED-01\Administrator
LogonGuid: {eb65e329-add0-6aa9-ebd7-550000000000}
LogonId: 0x55D7EB
IntegrityLevel: High
Hashes: MD5=8A1E71312BD2AAE202652113049CDBD1
```

### Raw Sysmon EID 1 (net group "Domain Admins" /domain)

```
Process Create:
UtcTime: 2026-09-15 20:43:09.301
ProcessId: 4400
Image: C:\Windows\System32\net.exe
OriginalFileName: net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" group "Domain Admins" /domain
User: COMPROMISED-01\Administrator
LogonGuid: {eb65e329-add0-6aa9-ebd7-550000000000}
LogonId: 0x55D7EB
IntegrityLevel: High
Hashes: MD5=8A1E71312BD2AAE202652113049CDBD1
```

### Raw Sysmon EID 1 (net group "Enterprise Admins" /domain)

```
Process Create:
UtcTime: 2026-09-15 20:43:09.393
ProcessId: 5976
Image: C:\Windows\System32\net.exe
OriginalFileName: net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" group "Enterprise Admins" /domain
User: COMPROMISED-01\Administrator
LogonGuid: {eb65e329-add0-6aa9-ebd7-550000000000}
LogonId: 0x55D7EB
IntegrityLevel: High
Hashes: MD5=8A1E71312BD2AAE202652113049CDBD1
```
