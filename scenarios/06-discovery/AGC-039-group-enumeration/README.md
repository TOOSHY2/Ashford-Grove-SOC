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

**What:** Permission groups discovery enumerates group memberships to identify privileged accounts for targeting. This splits into two sub-techniques:

- **T1069.001 — Local Groups:** `net localgroup administrators` reveals which accounts have local admin rights on the current host. This identifies accounts worth targeting for credential harvesting and informs which accounts can be used for lateral movement.
- **T1069.002 — Domain Groups:** `net group "Domain Admins" /domain` and `net group "Enterprise Admins" /domain` enumerate the highest-privilege domain groups. The members of these groups are the ultimate targets — their credentials unlock full domain control.

The key tradecraft distinction is **specificity**. An attacker who queries "Domain Admins" by name has already identified their target and is collecting membership for a targeted attack. This is more advanced than broad discovery (AGC-037) or trust mapping (AGC-038).

**Why at this lifecycle stage:** After host-level discovery (AGC-037) and domain trust discovery (AGC-038), the attacker now needs to know WHO the high-value targets are. The progression: What system am I on? -> What domain is this? -> Who are the admins? This directly feeds lateral movement (AGC-043+) and credential targeting.

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
The critical detection signal is NOT just "someone ran `net localgroup`" — that is common IT troubleshooting. The signal is the **targeted querying of privileged groups by name**: "Domain Admins" and "Enterprise Admins". An attacker who knows to query these groups by name is not performing casual discovery — they are mapping the privilege hierarchy for a targeted attack.

Compare:
- `net localgroup` (no argument) — broad, low signal
- `net localgroup administrators` — moderate signal (common for both IT and attackers)
- `net group "Domain Admins" /domain` — high signal (specific privileged group targeting)
- `net group "Enterprise Admins" /domain` — highest signal (enterprise-level privilege targeting)

**Step 2 — Account context:**
The executing account is the built-in Administrator (RID-500) on a workstation, not a domain controller or IT management station. There is no legitimate IT workflow that requires enumerating "Enterprise Admins" from a standard workstation. The account context provides no benign explanation.

**Step 3 — Correlate with prior discovery chain:**
This is the third stage of a documented discovery progression from the same attack chain:
- AGC-037: Host-level discovery burst (systeminfo, whoami, ipconfig) — "What system am I on?"
- AGC-038: Domain trust discovery (nltest /domain_trusts) — "What domain is this?"
- AGC-039: Privileged group enumeration — "Who are the admins?"

The progression from general to specific, within the same attack session, eliminates isolated coincidence as an explanation.

**Step 4 — Detection reuse:**
This reuses the same pattern as AGC-038 (net.exe process creation captured by Sysmon EID 1). Alert rule: any `net.exe` command line containing "Domain Admins" OR "Enterprise Admins" OR "Schema Admins" from a non-DC host. This is extremely low false-positive because these specific group names have no routine use on workstations.

### Report

**Verdict: True Positive** — Targeted enumeration of privileged groups ("Domain Admins", "Enterprise Admins") was executed from a compromised workstation by the Administrator account, as the third stage of a documented discovery chain.

**Confidence: High** — Calibrated assessment:
1. The specificity of querying "Domain Admins" and "Enterprise Admins" by name is the key differentiator. Unlike `net localgroup` (which IT might run routinely), these targeted queries indicate deliberate privilege mapping.
2. Account context (Administrator on a compromised workstation) provides no benign explanation.
3. This follows AGC-037 (host discovery) and AGC-038 (domain trust discovery) in a documented attack progression.
4. Even the failed domain queries (error 1355) are significant — the ATTEMPT to enumerate domain admin membership is the indicator, not the success.

**Response recommendation:**
1. **The local admin enumeration revealed actionable intelligence** — the attacker now knows `Administrator` and `wadmin` are local admins. Ensure `wadmin` credentials are rotated and monitored for unauthorized use.
2. **The domain group queries failed (broken trust)** — this is actually protective in this case. The attacker could not determine domain admin membership. If the trust were intact, this information would directly enable targeted credential harvesting.
3. **Anticipate the next step** — after identifying local admins, expect credential harvesting attempts against these specific accounts (SAM dump, LSASS access, Kerberoasting if domain trust is restored).
4. **Detection rule:** Alert on `net.exe` command lines containing privileged group names ("Domain Admins", "Enterprise Admins", "Schema Admins", "Account Operators", "Backup Operators") from non-DC hosts. Near-zero false positive rate.

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
