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

**What:** AD object query burst is a bulk domain enumeration technique that dumps entire object categories from Active Directory. The `-Filter *` pattern is the critical indicator — it requests EVERY object of a given type (all users, all computers, all groups, all OUs) rather than a scoped query for specific objects.

This technique maps to tools like BloodHound/SharpHound that perform bulk LDAP queries to build a graph of the entire domain. The information gathered enables:
- **All domain users** — target list for password spraying, phishing, impersonation
- **All domain computers** — target list for lateral movement, identifying servers vs. workstations
- **All domain groups** — privilege mapping, identifying high-value groups and their members
- **All OUs** — organizational structure, identifying which OUs contain which objects

The `-Filter *` (full export) pattern is distinct from legitimate administrative queries which are typically scoped: `Get-ADUser -Identity "john.doe"` or `Get-ADUser -Filter {Department -eq "Finance"}`.

**Why at this lifecycle stage:** This is the culmination of the discovery phase. After host-level discovery (AGC-037), domain trust mapping (AGC-038), privileged group enumeration (AGC-039), security tool discovery (AGC-040), and share enumeration (AGC-041), the attacker now attempts the broadest enumeration possible: a complete dump of all AD objects. This is typically the last discovery step before transitioning to lateral movement.

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
- All 8 enumeration attempts failed due to environmental constraints, NOT detection or blocking
- In a healthy domain environment, these same commands would have returned the complete AD object database
- The broken trust relationship is effectively an unintentional defense — it prevented the attacker from completing the broadest discovery step

**Cleanup:** No persistent artifacts. Commands are read-only. All queries failed before returning data.

## SOC Perspective

### Detection

**Sysmon EID 1 — Process Create (2 events):**

| Timestamp (UTC) | Image | CommandLine | PID | User | IntegrityLevel |
|---|---|---|---|---|---|
| 2026-09-15 20:53:07 | net.exe | `net.exe user /domain` | 4656 | Administrator | High |
| 2026-09-15 20:53:07 | net1.exe | `net1 user /domain` | 2336 | Administrator | High |

LogonGuid: `{eb65e329-b027-6aa9-da85-570000000000}`.

**PowerShell script-block logging (EID 4104):** The script execution containing the Get-AD* and [adsisearcher] calls would be captured by PowerShell script-block logging. In this lab, script-block logging for non-suspicious scripts may not be configured to fire at the enhanced level. In production, all 8 enumeration commands would appear in the script-block log, providing the richest detection telemetry for this scenario.

**Detection gap:** Since Get-AD* cmdlets execute in-process (PowerShell cmdlets, not external executables) and [adsisearcher] is a .NET class, neither generates Sysmon EID 1 events. Only the `net user /domain` fallback appeared in Sysmon. This means **PowerShell logging (EID 4104) is the primary detection source** for AD module-based enumeration — Sysmon alone is insufficient.

### Investigation

**Step 1 — Identify the `-Filter *` pattern:**
The defining indicator is the use of `-Filter *` across multiple AD object categories (users, computers, groups, OUs) in rapid succession. Legitimate AD administration queries are typically scoped:
- `Get-ADUser -Identity "john.doe"` — single user lookup
- `Get-ADUser -Filter {Department -eq "Finance"}` — scoped to a department
- `Get-ADComputer -Filter {OperatingSystem -like "*Server*"}` — scoped to servers

The `-Filter *` pattern requests EVERY object of the given type. Running this across 4+ categories is equivalent to a full domain export — a reconnaissance action with very limited legitimate use outside of scheduled compliance/audit jobs.

**Step 2 — Count distinct object categories queried:**
A single broad query (e.g., `Get-ADUser -Filter *` for a user audit) might have a legitimate explanation. Four or more distinct categories (users + computers + groups + OUs) in the same session is bulk enumeration with no plausible ad-hoc administrative use case.

**Step 3 — Check for scheduled/documented jobs:**
Before confirming as malicious, verify whether the source account is associated with a known compliance export or audit job. If the account is `svc-audit` running from a management server on a scheduled basis, this may be legitimate. In this case: the account is the built-in Administrator (RID-500) on a compromised workstation — not a service account, not a management server, not a scheduled job.

**Step 4 — Correlate with discovery chain:**
This is the sixth and final discovery stage (AGC-037 through AGC-042), culminating the attacker's reconnaissance phase. The progression from general host discovery to full domain export confirms a structured attack methodology.

### Report

**Verdict: True Positive** — Attempted full AD object dump across 4 categories using 3 different methods (Get-AD* cmdlets, ADSI/LDAP queries, net.exe), all from a compromised workstation.

**Confidence: High** — Calibrated assessment:
1. The `-Filter *` pattern across 4+ distinct object categories has no plausible ad-hoc administrative explanation outside scheduled compliance jobs.
2. The account context (Administrator on a compromised workstation) excludes the scheduled-job explanation.
3. The 3 fallback methods attempted (RSAT -> ADSI -> net.exe) demonstrate persistence and adaptability, consistent with an attacker working through tooling limitations rather than a legitimate admin who would stop after the first failure.
4. All attempts failed due to environmental constraints (missing RSAT + broken trust), NOT detection — this means the detection value is in the ATTEMPT, and the failures are an unintentional defense.
5. Confidence is High despite all failures because the attempt pattern itself is strongly indicative.

**Response recommendation:**
1. **The broken domain trust is an unintentional defense** — it prevented the broadest discovery step from succeeding. However, if the trust is restored (e.g., through remediation), the attacker would retry these queries. Prioritize host isolation before trust restoration.
2. **Enable PowerShell script-block logging** at the enhanced level if not already configured — this is the primary detection source for AD module-based enumeration and [adsisearcher] usage.
3. **Detection rule:** Alert on PowerShell script-block logs containing `Get-ADUser.*-Filter \*` OR `Get-ADComputer.*-Filter \*` OR `Get-ADGroup.*-Filter \*` OR `[adsisearcher]` from non-management hosts. Near-zero false positive rate for workstation sources.
4. **LDAP query volume monitoring** (if AD DS audit logging is enabled): Alert on LDAP queries returning >100 objects from a workstation source. This catches the same pattern even when tools other than PowerShell are used.

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
