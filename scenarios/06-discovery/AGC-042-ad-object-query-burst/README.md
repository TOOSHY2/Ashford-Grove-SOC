# AGC-042 — AD Object Query Burst

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-042` |
| Category | `06-discovery` — Discovery |
| MITRE Technique | `T1087.002` Account Discovery: Domain Account / `T1018` Remote System Discovery / `T1069.002` Permission Groups Discovery: Domain Groups |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Immediate — PowerShell script-block logging captures Get-AD* and [adsisearcher] invocations; Sysmon EID 1 captures `net.exe user /domain` fallback |
| Time to Triage | 02:00 (check for `-Filter *` pattern across multiple AD object categories; verify account is not a scheduled compliance/reporting job) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ [AGC-041](../AGC-041-network-share-enum/README.md) · next [AGC-043](../../07-lateral-movement/AGC-043-unusual-rdp-logon/README.md) (Lateral Movement category) ▶ |
| One-line Summary | Attempted full AD object dump: 4 `Get-AD*` cmdlets with `-Filter *` (all failed — RSAT not installed), 3 `[adsisearcher]` LDAP queries targeting users/computers/groups (all failed — DC unreachable), and `net user /domain` fallback (error 1355). The `-Filter *` pattern across 4 distinct object categories in rapid succession is the defining indicator — it requests every object of each type, not a scoped query. All failures stem from broken domain trust + missing RSAT, NOT from any detection/blocking. |

## Attacker Perspective

### Tradecraft

**What:** An AD object query burst dumps whole object categories out of Active Directory. The `-Filter *` pattern is the indicator — it asks for every object of a type (all users, all computers, all groups, all OUs) instead of a scoped lookup.

This is the same approach BloodHound/SharpHound take: bulk LDAP queries that graph the whole domain. The output gives the attacker:
- **All domain users** — target list for password spraying, phishing, impersonation
- **All domain computers** — target list for lateral movement, identifying servers vs. workstations
- **All domain groups** — privilege mapping, identifying high-value groups and their members
- **All OUs** — organizational structure, identifying which OUs contain which objects

A full export with `-Filter *` looks nothing like an admin query, which is normally scoped: `Get-ADUser -Identity "john.doe"` or `Get-ADUser -Filter {Department -eq "Finance"}`.

**Why at this lifecycle stage:** This closes out the discovery phase. After host discovery (AGC-037), trust mapping (AGC-038), privileged group enumeration (AGC-039), security tool discovery (AGC-040), and share enumeration (AGC-041), the attacker goes for the widest pull available: every AD object. It is usually the last discovery step before lateral movement.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.
- `AD-DC-01` running (target of LDAP queries — but unreachable from COMPROMISED-HOST-01).

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Result |
|---|---|---|---|---|
| 1 | 2026-09-15 20:52:55 | Get-ADUser -Filter * -Properties * | COMPROMISED-HOST-01 | FAILED: RSAT AD module not installed |
| 2 | 2026-09-15 20:52:55 | Get-ADComputer -Filter * -Properties * | COMPROMISED-HOST-01 | FAILED: RSAT AD module not installed |
| 3 | 2026-09-15 20:52:55 | Get-ADGroup -Filter * -Properties * | COMPROMISED-HOST-01 | FAILED: RSAT AD module not installed |
| 4 | 2026-09-15 20:52:55 | Get-ADOrganizationalUnit -Filter * | COMPROMISED-HOST-01 | FAILED: RSAT AD module not installed |
| 5 | 2026-09-15 20:52:55 | [adsisearcher]"(objectCategory=person)" | COMPROMISED-HOST-01 | FAILED: domain not contactable |
| 6 | 2026-09-15 20:53:07 | [adsisearcher]"(objectCategory=computer)" | COMPROMISED-HOST-01 | FAILED: domain not contactable |
| 7 | 2026-09-15 20:53:07 | [adsisearcher]"(objectCategory=group)" | COMPROMISED-HOST-01 | FAILED: domain not contactable |
| 8 | 2026-09-15 20:53:07 | net user /domain | COMPROMISED-HOST-01 | Error 1355: DC unreachable |

**Key findings:**
- RSAT AD module is not installed on the workstation — `Get-AD*` cmdlets are unavailable
- Domain controller is unreachable (broken trust) — ADSI/LDAP queries and `net user /domain` all fail
- All 8 attempts failed on lab constraints, not on detection or blocking
- On a healthy domain-joined host the same commands would have returned the full AD object set
- The broken trust acted as an accidental defense — it stopped the widest discovery step from completing

**Cleanup:** No persistent artifacts. Commands are read-only. All queries failed before returning data.

## SOC Perspective

### Detection

**Sysmon EID 1 — Process Create (2 events):**

| Timestamp (UTC) | Image | CommandLine | PID | User | IntegrityLevel |
|---|---|---|---|---|---|
| 2026-09-15 20:53:07 | net.exe | `net.exe user /domain` | 4656 | Administrator | High |
| 2026-09-15 20:53:07 | net1.exe | `net1 user /domain` | 2336 | Administrator | High |

LogonGuid: `{eb65e329-b027-6aa9-da85-570000000000}`.

**PowerShell script-block logging (EID 4104):** Script-block logging is where the Get-AD* and [adsisearcher] calls would land. In the lab, script-block logging may not be set to fire at the enhanced level for scripts Windows does not flag as suspicious. In production, all 8 enumeration commands would appear in the script-block log — the richest telemetry for this scenario.

**Detection gap:** Get-AD* cmdlets run in-process and [adsisearcher] is a .NET class, so neither produces a Sysmon EID 1. Only the `net user /domain` fallback reached Sysmon. **PowerShell logging (EID 4104) is the primary detection source** for AD module enumeration — Sysmon alone misses it.

### Investigation

**Step 1 — Identify the `-Filter *` pattern:**
The indicator is `-Filter *` across several AD object categories (users, computers, groups, OUs) back to back. Admin queries are normally scoped:
- `Get-ADUser -Identity "john.doe"` — single user lookup
- `Get-ADUser -Filter {Department -eq "Finance"}` — scoped to a department
- `Get-ADComputer -Filter {OperatingSystem -like "*Server*"}` — scoped to servers

`-Filter *` returns every object of the type. Across 4+ categories that is a full domain export, which has little legitimate use outside scheduled compliance or audit jobs.

**Step 2 — Count distinct object categories queried:**
One broad query (e.g., `Get-ADUser -Filter *` for a user audit) might have an explanation. Four or more categories (users + computers + groups + OUs) in one session is bulk enumeration; no ad-hoc admin task needs all of them.

**Step 3 — Check for scheduled/documented jobs:**
Before calling it malicious, check whether the source account belongs to a known compliance export or audit job. `svc-audit` running on a schedule from a management server could be fine. Here the account is the built-in Administrator (RID-500) on a compromised workstation — not a service account, not a management server, not a scheduled job.

**Step 4 — Correlate with discovery chain:**
This is the sixth and last discovery stage (AGC-037 through AGC-042). Host discovery first, full domain export last — the attacker worked a plan, not a whim.

### Report

**Verdict: True Positive** — The Administrator account on COMPROMISED-HOST-01 tried to dump 4 AD object categories by 3 methods (Get-AD* cmdlets, ADSI/LDAP queries, net.exe).

**Confidence: High** — Calibrated assessment:
1. `-Filter *` across 4+ object categories has no ad-hoc admin explanation outside scheduled compliance jobs.
2. Administrator on a compromised workstation rules out the scheduled-job explanation.
3. The 3 fallbacks (RSAT -> ADSI -> net.exe) show an attacker working around tooling limits. An admin would stop at the first failure.
4. Every attempt failed on lab constraints (missing RSAT + broken trust), not on detection — the attempt carries the signal, and the failures were an accidental defense.
5. Confidence is High despite the failures because the attempt pattern is the indicator.

**Response recommendation:**
1. **The broken domain trust is an accidental defense** — it stopped the widest discovery step. Restore the trust (for example during remediation) and the attacker retries these queries. Isolate the host before repairing the trust.
2. **Enable PowerShell script-block logging** at the enhanced level if it is not already on — it is the primary detection source for AD module enumeration and [adsisearcher] use.
3. **Detection rule:** Alert on PowerShell script-block logs containing `Get-ADUser.*-Filter \*` OR `Get-ADComputer.*-Filter \*` OR `Get-ADGroup.*-Filter \*` OR `[adsisearcher]` from non-management hosts. Near-zero false positives from workstation sources.
4. **LDAP query volume monitoring** (if AD DS audit logging is enabled): Alert on LDAP queries returning >100 objects from a workstation source. That catches the same pattern from tools other than PowerShell.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Discovery (TA0007) | T1087.002 | Account Discovery: Domain Account | PowerShell: `Get-ADUser -Filter * -Properties *` attempted (RSAT unavailable); `[adsisearcher]"(objectCategory=person)"` attempted (DC unreachable); `net user /domain` attempted (error 1355). All failed — attempt is the indicator. | High |
| Discovery (TA0007) | T1018 | Remote System Discovery | PowerShell: `Get-ADComputer -Filter * -Properties *` attempted (RSAT unavailable); `[adsisearcher]"(objectCategory=computer)"` attempted (DC unreachable). Both failed. | High |
| Discovery (TA0007) | T1069.002 | Permission Groups Discovery: Domain Groups | PowerShell: `Get-ADGroup -Filter * -Properties *` attempted (RSAT unavailable); `[adsisearcher]"(objectCategory=group)"` attempted (DC unreachable); `Get-ADOrganizationalUnit -Filter *` attempted (RSAT unavailable). All failed. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### RSAT failure output (representative)

```
FAILED: The term 'Get-ADUser' is not recognized as the name of a cmdlet,
function, script file, or operable program. Check the spelling of the name,
or if a path was included, verify that the path is correct and try again.
```

### ADSI searcher failure output (representative)

```
ADSI FAILED: Exception calling "FindAll" with "0" argument(s):
"The specified domain either does not exist or could not be contacted."
```

### net user /domain failure output

```
The request will be processed at a domain controller for domain ashfordgrove.local.

System error 1355 has occurred.
The specified domain either does not exist or could not be contacted.
```

### Raw Sysmon EID 1 (net user /domain)

```
Process Create:
UtcTime: 2026-09-15 20:53:07.804
ProcessId: 4656
Image: C:\Windows\System32\net.exe
OriginalFileName: net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" user /domain
User: COMPROMISED-01\Administrator
LogonGuid: {eb65e329-b027-6aa9-da85-570000000000}
LogonId: 0x5785DA
IntegrityLevel: High
Hashes: MD5=8A1E71312BD2AAE202652113049CDBD1
```
