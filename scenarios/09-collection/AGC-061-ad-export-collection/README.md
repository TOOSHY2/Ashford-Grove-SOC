# AGC-061 -- AD Export Collection (Query + Staged CSV)

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-061` |
| Category | `09-collection` -- Collection |
| MITRE Technique | `T1087.002` Account Discovery: Domain Account + `T1074.001` Data Staged: Local Data Staging |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Sysmon EID 1 (net.exe/net1.exe with /domain flag) |
| Time to Triage | 04:00 (identify scope of AD queries, check for Export-Csv staging artifacts) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) targeting `AD-DC-01` (10.10.10.10) |
| Chain | < AGC-060 . next AGC-062 (Exfiltration category) > |
| One-line Summary | Bulk AD enumeration via `net user /domain`, `net group /domain`, and LDAP DirectorySearcher queries with results exported to CSV files at `C:\Windows\Temp\`. Domain trust broken (error 1355) prevented actual data retrieval, but the enumeration attempt itself was fully captured by Sysmon EID 1 across 4 net.exe/net1.exe process creations. This elevates from Discovery to Collection because the attacker staged query results to files for exfiltration preparation. |

## Attacker Perspective

### Tradecraft

**What:** After gaining access to a domain-joined host, attackers export the full Active Directory user and group database to local files. This provides:
- Complete list of all domain accounts (usernames, display names, email addresses)
- Group memberships revealing privilege hierarchy (Domain Admins, IT-Support, Finance)
- Service accounts that may have weaker password policies
- Recently created accounts that may be backdoors planted by other attackers
- Organizational structure for social engineering or targeted lateral movement

**Why an Attacker Uses It Here:**
1. AD export with `-Filter *` (or `net user /domain`) captures the entire directory -- no selective querying needed
2. Exporting to CSV creates a portable artifact that survives session termination
3. The CSV can be exfiltrated in a single operation (smaller and more structured than raw LDAP output)
4. This represents the transition from Discovery (querying) to Collection (staging) -- the attacker is preparing data for extraction, not just exploring

**Cross-reference with AGC-042:** AGC-042 covered the discovery phase (querying AD). AGC-061 escalates by adding `Export-Csv` -- the staged file artifact is what distinguishes collection from discovery.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context
- `AD-DC-01` running at 10.10.10.10 (domain controller)
- Domain trust relationship broken on COMPROMISED-HOST-01 (error 1355)
- RSAT AD module not installed (Get-ADUser/Get-ADGroup unavailable)

**Execution:**
```powershell
# Approach 1: net user/group enumeration
net user /domain
net group /domain

# Approach 2: LDAP DirectorySearcher query
$searcher = New-Object DirectoryServices.DirectorySearcher
$searcher.Filter = "(objectCategory=user)"
$results = $searcher.FindAll()

# Export results to CSV staging files
[System.IO.File]::WriteAllLines("C:\Windows\Temp\ad_users.csv", $csvLines)
[System.IO.File]::WriteAllLines("C:\Windows\Temp\ad_groups.csv", $csvLines2)
```

**Result:** All three approaches failed with "The specified domain either does not exist or could not be contacted" (error 1355) due to the broken domain trust relationship on COMPROMISED-HOST-01. CSV files were created containing the error output (479 and 484 bytes respectively). Despite the failure, 4 net.exe/net1.exe process creation events were captured by Sysmon.

**Lab constraint:** The broken domain trust relationship prevents actual AD data retrieval. In a production environment with healthy domain trust, these commands would return the full user/group directory.

## SOC Perspective

### Detection

**Sysmon EID 1 -- net.exe user /domain (process pair):**
```
Process Create:
UtcTime: 2026-09-15 22:41:19.721
ProcessGuid: {eb65e329-c98f-6aa9-a104-000000001400}
ProcessId: 3184
Image: C:\Windows\System32\net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" user /domain
User: COMPROMISED-01\Administrator
IntegrityLevel: High
Hashes: MD5=8A1E71312BD2AAE202652113049CDBD1
```

**Sysmon EID 1 -- net1.exe user /domain (child process):**
```
Process Create:
UtcTime: 2026-09-15 22:41:19.754
ProcessGuid: {eb65e329-c98f-6aa9-a204-000000001400}
ProcessId: 3444
Image: C:\Windows\System32\net1.exe
CommandLine: C:\WINDOWS\system32\net1 user /domain
User: COMPROMISED-01\Administrator
IntegrityLevel: High
Hashes: MD5=158DB954503C803C0840DD424FB608F8
```

**Sysmon EID 1 -- net.exe group /domain (process pair):**
```
Process Create:
UtcTime: 2026-09-15 22:41:32.047
ProcessGuid: {eb65e329-c99c-6aa9-a304-000000001400}
ProcessId: 3308
Image: C:\Windows\System32\net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" group /domain
User: COMPROMISED-01\Administrator
IntegrityLevel: High
```

**Sysmon EID 1 -- net1.exe group /domain (child process):**
```
Process Create:
UtcTime: 2026-09-15 22:41:32.077
ProcessGuid: {eb65e329-c99c-6aa9-a404-000000001400}
ProcessId: 5632
Image: C:\Windows\System32\net1.exe
CommandLine: C:\WINDOWS\system32\net1 group /domain
User: COMPROMISED-01\Administrator
IntegrityLevel: High
```

**Sysmon EID 11 -- File Create: 0 events**
CSV files were not captured by EID 11 (SwiftOnSecurity config filters to EXE/DLL only). Same detection gap as AGC-057/058/059.

**Sysmon EID 3 -- Network Connection: 0 events**
No LDAP connection (port 389/636) to DC was established because the domain trust is broken. The query failed before TCP handshake.

### Investigation

**Step 1 -- Enumerate AD query commands:**
4 distinct process creations for domain enumeration: `net user /domain` and `net group /domain`, each spawning a net1.exe child process. The `/domain` flag specifically targets the domain controller, not local accounts. This is the identical pattern seen in AGC-042 (domain account discovery).

**Step 2 -- Identify the collection escalation:**
The critical distinction between AGC-042 (Discovery) and AGC-061 (Collection) is the `Export-Csv` staging step. While the LDAP queries failed due to broken domain trust, the attacker's intent was clear:
- DirectorySearcher with `(objectCategory=user)` and `(objectCategory=group)` filters
- Results structured into CSV format with columns: DN, SAMAccountName, DisplayName, Mail, WhenCreated
- Written to `C:\Windows\Temp\` -- the same staging location used in AGC-057/058/059/060

**Step 3 -- Assess the process chain:**
```
powershell.exe (PID 5236, agc061-sim.ps1)
  |-- net.exe (PID 3184, user /domain)
  |     |-- net1.exe (PID 3444, user /domain)
  |-- net.exe (PID 3308, group /domain)
  |     |-- net1.exe (PID 5632, group /domain)
```
All executed within 13 seconds (22:41:19 to 22:41:32), from a script with `-ExecutionPolicy Bypass`. The tight timing and scripted execution distinguish this from ad-hoc administrative queries.

**Step 4 -- Cross-reference with AGC-042:**
The progression Discovery (AGC-042) to Collection (AGC-061) follows the expected attack chain. The same enumeration commands are used, but AGC-061 adds file export -- transitioning from "learning about the environment" to "packaging data for extraction."

### Report

**Verdict: True Positive** -- Active Directory bulk enumeration with CSV export staging.

**Confidence: High** -- Despite the domain trust failure preventing actual data retrieval:
1. The enumeration commands (`net user /domain`, `net group /domain`) were fully executed and captured
2. The LDAP DirectorySearcher queries with `(objectCategory=user)` filter demonstrate intent to export all accounts
3. CSV staging to `C:\Windows\Temp\` follows the established collection pattern (AGC-057-060)
4. The attack chain from discovery (AGC-042) to collection (AGC-061) is coherent

Not Critical because the domain trust failure prevented actual data retrieval. In a production scenario with healthy trust, this would be Critical.

**Response recommendation:**
1. **Isolate COMPROMISED-HOST-01** -- bulk AD enumeration with export staging is advanced tradecraft indicating planned exfiltration.
2. **Audit the AD export files** -- if CSVs were successfully created, determine exactly what data was captured (user attributes, group memberships, privileged accounts).
3. **Check for exfiltration activity** -- look for archive creation (T1560) or outbound transfers following the CSV creation timestamp.
4. **Review AD query patterns** -- alert on `net user /domain`, `net group /domain`, `Get-ADUser -Filter *`, and LDAP DirectorySearcher with broad filters from non-administrative accounts.
5. **Treat as planned operation** -- the progression from discovery to collection with structured file staging indicates a methodical attacker, not opportunistic activity.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Discovery (TA0007) | T1087.002 | Account Discovery: Domain Account | net.exe user /domain (PID 3184) + net1.exe (PID 3444), net.exe group /domain (PID 3308) + net1.exe (PID 5632). 4 EID 1 events. Domain trust failure (error 1355). | High |
| Collection (TA0009) | T1074.001 | Data Staged: Local Data Staging | CSV export to C:\Windows\Temp\ad_users.csv (479 B) and ad_groups.csv (484 B). EID 11 missed (no EXE/DLL extension). Staging location matches AGC-057-060 pattern. | High |

## Evidence

Screenshots: not applicable (text-based evidence collection only).

### AD enumeration process chain

```
Timestamp (UTC)          PID   Image       CommandLine
2026-09-15 22:41:19.314  5236  powershell  -ExecutionPolicy Bypass -File C:\Temp\agc061-sim.ps1
2026-09-15 22:41:19.721  3184  net.exe     user /domain
2026-09-15 22:41:19.754  3444  net1.exe    user /domain
2026-09-15 22:41:32.047  3308  net.exe     group /domain
2026-09-15 22:41:32.077  5632  net1.exe    group /domain

All processes: User=COMPROMISED-01\Administrator, IntegrityLevel=High
Domain trust broken: error 1355 on all queries
```

### CSV staging files

```
ad_users.csv:  479 bytes, created 22:41:32 UTC (error output -- domain unreachable)
ad_groups.csv: 484 bytes, created 22:41:32 UTC (error output -- domain unreachable)
Location: C:\Windows\Temp\ (consistent staging path across AGC-057 through AGC-061)

In production: These would contain full AD user/group export with
DN, SAMAccountName, DisplayName, Mail, WhenCreated, GroupType fields.
```
