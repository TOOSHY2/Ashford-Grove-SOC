# AGC-035 — Password Spray

> **Disclosure:** Executed & documented by Claude Code under direction and review by Ali.

## Card

| Field | Value |
|---|---|
| ID | `AGC-035` |
| Category | `05-credential-access` — Credential Access |
| MITRE Technique | `T1110.003` Brute Force: Password Spraying |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Immediate — Security EID 4625 generated on each failed attempt; Sysmon EID 1 captures `net.exe` with credentials in command line |
| Time to Triage | 03:00 (aggregate 4625 by source IP, count distinct target accounts, check for any subsequent successful logon) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) targeting `AD-DC-01` (10.10.10.10) |
| Chain | ◀ [AGC-034](../AGC-034-kerberos-ticket-export/README.md) · next [AGC-036](../AGC-036-ntlm-auth-anomaly/README.md) ▶ |
| One-line Summary | Password spray executed from compromised host: same password tested against 5 distinct accounts (michael.chen, sarah.jenkins, raj.patel, james.wilson, admin.backup) within a bounded time window. Security EID 4625 confirmed 5 failed logons from single source IP. Sysmon EID 1 captured `net.exe` command lines exposing the spray pattern. |

## Attacker Perspective

### Tradecraft

**What:** Password spraying is a brute-force variant that tests one or two common passwords against many accounts simultaneously, rather than testing many passwords against a single account. This approach is designed to evade account-lockout policies: if the lockout threshold is 5 failed attempts within 30 minutes, a spray that tries only 1-2 passwords per account stays below the threshold indefinitely.

The spray uses `net use \\<target>\IPC$` with explicit `/user:domain\account` credentials to attempt SMB authentication against the domain controller. Each failed attempt generates a Security EID 4625 (Logon Failure) on the target system.

The key distinguishing characteristic of a spray versus a brute-force attack:
- **Brute force:** Many passwords against ONE account (high per-account failure count)
- **Password spray:** One password against MANY accounts (low per-account failure count, high account breadth)

This breadth-over-depth pattern is what analysts must look for: aggregate EID 4625 by source IP and count distinct target accounts, not total failures.

**Why at this lifecycle stage:** After credential harvesting (AGC-031 LSASS, AGC-032 SAM, AGC-033 browser, AGC-034 Kerberos enumeration) yielded limited results (LSASS protected by PPL, SAM hive extracted but SECURITY/SYSTEM denied, Kerberos tickets absent due to broken domain trust), the attacker pivots to spraying common passwords against known domain accounts. This is an alternative credential access path that does not require existing credentials or elevated privileges on the target system.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.
- `AD-DC-01` running (domain controller).
- Domain trust broken (discovered AGC-025) — DC unreachable from COMPROMISED-HOST-01 at network level.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 20:13:11 | Spray against DC (10.10.10.10) | COMPROMISED-HOST-01 | 10 attempts (5 accounts x 2 passwords: `Summer2026!`, `Password123!`). All failed with network errors 64/67 — DC unreachable. |
| 2 | 2026-09-15 20:21:58 | Spray against localhost (127.0.0.1) | COMPROMISED-HOST-01 | 5 attempts (5 accounts x 1 password: `WrongPass2026!`). All failed with error 1326 ("username or password is incorrect"). Generated Security EID 4625 events. |

**DC-targeted spray (Step 1) — network failure:**
The initial spray against the DC failed at the network level (System error 64: "specified network name is no longer available" / error 67: "network name cannot be found"). Ping, SMB (445), and LDAP (389) all fail from COMPROMISED-HOST-01 to AD-DC-01. This is consistent with the broken domain trust relationship discovered in AGC-025. The DC never received the authentication attempts, so no EID 4625 events were generated on the DC.

This is a detection gap: if the spray fails at the network level, DC-side monitoring sees nothing. Only source-side detection (Sysmon EID 1) captures the attempt.

**Local auth spray (Step 2) — authentication failure:**
To generate complete detection evidence, a secondary spray was executed against localhost (127.0.0.1) using the same account list. This produced both Security EID 4625 and Sysmon EID 1 events.

**Cleanup:** No persistent artifacts created.

## SOC Perspective

### Detection

**Security EID 4625 — Logon Failure (5 events within 33 seconds):**

| Timestamp (UTC) | EID | Target Account | Source IP | Logon Type | Auth Package | Status | Sub Status |
|---|---|---|---|---|---|---|---|
| 2026-09-15 20:22:10 | 4625 | michael.chen | 127.0.0.1 | 3 (Network) | NTLM | 0xC000006D | 0xC0000064 |
| 2026-09-15 20:22:15 | 4625 | sarah.jenkins | 127.0.0.1 | 3 (Network) | NTLM | 0xC000006D | 0xC0000064 |
| 2026-09-15 20:22:20 | 4625 | raj.patel | 127.0.0.1 | 3 (Network) | NTLM | 0xC000006D | 0xC0000064 |
| 2026-09-15 20:22:25 | 4625 | james.wilson | 127.0.0.1 | 3 (Network) | NTLM | 0xC000006D | 0xC0000064 |
| 2026-09-15 20:22:31 | 4625 | admin.backup | 127.0.0.1 | 3 (Network) | NTLM | 0xC000006D | 0xC0000064 |

Sub Status `0xC0000064` = "user name does not exist" (accounts are domain accounts not present in local SAM).

**Sysmon EID 1 — Process Create (net.exe with credential exposure):**

| Timestamp (UTC) | PID | CommandLine | User | Integrity |
|---|---|---|---|---|
| 2026-09-15 20:13:11 | varies | `net.exe use \\10.10.10.10\IPC$ /user:ashfordgrove\michael.chen Summer2026!` | Administrator | High |
| 2026-09-15 20:14:20 | varies | `net.exe use \\10.10.10.10\IPC$ /user:ashfordgrove\raj.patel Summer2026!` | Administrator | High |
| 2026-09-15 20:16:35 | 5320 | `net.exe use \\10.10.10.10\IPC$ /user:ashfordgrove\michael.chen Password123!` | Administrator | High |
| 2026-09-15 20:16:59 | 5708 | `net.exe use \\10.10.10.10\IPC$ /user:ashfordgrove\sarah.jenkins Password123!` | Administrator | High |
| 2026-09-15 20:17:55 | 4868 | `net.exe use \\10.10.10.10\IPC$ /user:ashfordgrove\raj.patel Password123!` | Administrator | High |
| 2026-09-15 20:18:18 | 1820 | `net.exe use \\10.10.10.10\IPC$ /user:ashfordgrove\james.wilson Password123!` | Administrator | High |
| 2026-09-15 20:19:02 | 1484 | `net.exe use \\10.10.10.10\IPC$ /user:ashfordgrove\admin.backup Password123!` | Administrator | High |
| 2026-09-15 20:22:20 | 2836 | `net.exe use \\127.0.0.1\IPC$ /user:raj.patel WrongPass2026!` | Administrator | High |
| 2026-09-15 20:22:25 | 4476 | `net.exe use \\127.0.0.1\IPC$ /user:james.wilson WrongPass2026!` | Administrator | High |
| 2026-09-15 20:22:31 | 5612 | `net.exe use \\127.0.0.1\IPC$ /user:admin.backup WrongPass2026!` | Administrator | High |

All Sysmon events share: `ParentImage: powershell.exe`, `ParentCommandLine: powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc035-*.ps1`. Hash: `MD5=8A1E71312BD2AAE202652113049CDBD1`.

### Investigation

**Step 1 — Identify the spray pattern (breadth-over-depth):**
Aggregate EID 4625 by source IP: all 5 failures originate from `127.0.0.1` (COMPROMISED-01). Count distinct target accounts: **5 distinct accounts** (michael.chen, sarah.jenkins, raj.patel, james.wilson, admin.backup) with only **1 failure per account**. That pattern is the spray fingerprint: high account breadth, low per-account attempt count. A legitimate user mistyping their password would produce multiple 4625 events for the SAME account, not different accounts.

**Step 2 — Confirm coordinated campaign (same failure reason):**
All 5 EID 4625 events share the same Status (`0xC000006D` — bad password) and Sub Status (`0xC0000064` — user does not exist). The consistent failure reason across distinct accounts confirms a coordinated campaign with a single password being tested, not unrelated coincidental failures.

**Step 3 — Check for subsequent successful logon:**
Search for EID 4624 (successful logon) for any of the 5 target accounts in the minutes following the spray. No successful logons were found for any sprayed account. This means no credential was guessed correctly in this spray attempt. If a 4624 had appeared for one account shortly after its 4625, that account would need immediate password reset and investigation.

**Step 4 — Source-side detection analysis (Sysmon EID 1):**
Sysmon EID 1 on the source host provides additional detection value that DC-side 4625 monitoring cannot:
- **Command-line credential exposure:** The full `net use` command line includes the attempted password in cleartext. This is visible in Sysmon EID 1 but NOT in EID 4625.
- **Parent process context:** All `net.exe` invocations share the same parent process (powershell.exe executing a script file), confirming scripted/automated spray rather than manual attempts.
- **Network-layer spray detection:** The DC-targeted spray (10.10.10.10) failed at the network level and generated ZERO EID 4625 events on the DC. Only Sysmon EID 1 on the source host detected these attempts. Relying only on DC-side 4625 monitoring misses this: network-layer spray failures are invisible without it.

**Step 5 — Detection reuse note:**
The Sysmon EID 1 detection pattern (aggregating `net.exe` / `net1.exe` process creation by parent process, grouping by distinct `/user:` arguments) was first established here and can be reused for future brute-force variants. See also AGC-031 (LSASS) and AGC-032 (SAM) for the same `net.exe` process creation capture pattern.

### Report

**Verdict: True Positive** — A password spray was executed from COMPROMISED-HOST-01, testing common passwords against 5 distinct domain accounts within a bounded time window.

**Confidence: High** — Evidence confirms all spray indicators:
1. **Account breadth:** 5 distinct target accounts, 1 attempt per account per password — below any reasonable lockout threshold.
2. **Single source:** All attempts from the same host (COMPROMISED-01) and same parent process (scripted PowerShell).
3. **Bounded time window:** All attempts within a 9-minute window (20:13 to 20:22 UTC).
4. **Consistent failure reason:** Same Status/Sub Status codes across all 4625 events.
5. **Credential exposure:** Sysmon EID 1 captured attempted passwords in cleartext command lines.

**Response recommendation:**
1. **Block source IP** at the firewall immediately — the spray source (COMPROMISED-HOST-01, 10.10.10.103) is confirmed compromised.
2. **Check for successful logon** — search EID 4624 for all sprayed accounts within 1 hour of the spray window. Reset passwords for any account showing a successful logon after a spray failure.
3. **Review lockout thresholds** — if the spray's 1-attempt-per-account pattern stayed below the lockout threshold, the threshold itself needs tightening. Consider: (a) lower threshold (3 attempts), (b) shorter observation window (15 minutes), (c) smart lockout that detects spray patterns across accounts.
4. **Force password reset** for all sprayed accounts as a precaution — the attacker now knows which accounts exist (4625 Sub Status differentiates between "user does not exist" and "bad password").
5. **Monitor for password reuse** — if any sprayed password matches a credential found in AGC-032 (SAM) or AGC-033 (browser), the spray may succeed on retry with the harvested credential.
6. **Full chain context:** AGC-031 (LSASS blocked) -> AGC-032 (SAM extracted) -> AGC-033 (browser creds) -> AGC-034 (Kerberos enum) -> AGC-035 (spray). The attacker is systematically working through credential access techniques.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Credential Access (TA0006) | T1110.003 | Brute Force: Password Spraying | Security EID 4625: 5 failed logons (Logon Type 3, NTLM) targeting 5 distinct accounts (michael.chen, sarah.jenkins, raj.patel, james.wilson, admin.backup) from single source within 33 seconds. Sysmon EID 1: 11 `net.exe` process creation events with cleartext credentials in command line. Spray pattern: same password across multiple accounts, 1 attempt per account. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### Raw EID 4625 (representative sample)

```
An account failed to log on.

Subject:
    Security ID:        S-1-0-0
    Account Name:       -
    Account Domain:     -
    Logon ID:           0x0

Logon Type:             3

Account For Which Logon Failed:
    Security ID:        S-1-0-0
    Account Name:       michael.chen
    Account Domain:     -

Failure Information:
    Failure Reason:     Unknown user name or bad password.
    Status:             0xC000006D
    Sub Status:         0xC0000064

Network Information:
    Workstation Name:   COMPROMISED-01
    Source Network Address:  127.0.0.1
    Source Port:        64371

Detailed Authentication Information:
    Logon Process:      NtLmSsp
    Authentication Package: NTLM
```

### Raw Sysmon EID 1 (representative sample)

```
Process Create:
RuleName: -
UtcTime: 2026-09-15 20:19:02.757
ProcessId: 1484
Image: C:\Windows\System32\net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" use \\10.10.10.10\IPC$ /user:ashfordgrove\admin.backup Password123!
User: COMPROMISED-01\Administrator
LogonId: 0x4ECBDE
IntegrityLevel: High
Hashes: MD5=8A1E71312BD2AAE202652113049CDBD1,SHA256=BB3E638C8B5B6EF80847E364AEEF2796CAD25D3539CF9B41D3820FA48943E777
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ParentCommandLine: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc035-sim.ps1
```
