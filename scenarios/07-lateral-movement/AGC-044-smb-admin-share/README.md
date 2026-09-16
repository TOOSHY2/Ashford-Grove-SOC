# AGC-044 -- SMB Admin-Share Access (C$)

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-044` |
| Category | `07-lateral-movement` -- Lateral Movement |
| MITRE Technique | `T1021.002` Remote Services: SMB/Windows Admin Shares |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Immediate -- Sysmon EID 1 captures `net.exe use \\<target>\C$` with target and cleartext credentials in command line |
| Time to Triage | 02:00 (verify access is not from a known deployment tool; check for subsequent file copy or remote execution) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) as source; target: `WIN-CLIENT-02` (10.10.10.102) |
| Chain | < AGC-043 . next AGC-045 > |
| One-line Summary | SMB admin share access attempted against WIN-CLIENT-02: `net use \\10.10.10.102\C$`, `\\ADMIN$`, and `\\IPC$` with `raj.patel` credentials (cleartext in command line). All remote connections failed (network errors). Localhost C$ fallback succeeded -- marker file copied to `\\127.0.0.1\C$\Windows\Temp\`. 5 Sysmon EID 1 events captured, 3 containing cleartext password. Admin share targeting with explicit credentials from a compromised workstation is a high-confidence lateral movement indicator. |

## Attacker Perspective

### Tradecraft

**What:** SMB admin share access uses Windows administrative shares (C$, ADMIN$, IPC$) to remotely access file systems on other hosts. These shares are:
- **C$** -- maps to the C:\ drive root; allows full file system read/write
- **ADMIN$** -- maps to the Windows directory (C:\Windows); often used to stage payloads
- **IPC$** -- inter-process communication; used for null sessions, named pipe access, and as a precursor to remote execution (PsExec, WMI, service creation)

The pattern of accessing admin shares with explicit credentials (`/user:` flag) indicates the attacker is using harvested credentials to authenticate to remote hosts. The `net use` command with cleartext password in the command line is a well-known operational security failure that exposes credentials in Sysmon logs.

**Why at this lifecycle stage:** After RDP failed (AGC-043, port 3389 unreachable), the attacker pivots to SMB-based lateral movement. SMB (port 445) is often more permissive than RDP and provides file-level access that enables payload staging without requiring an interactive session.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.
- `WIN-CLIENT-02` running (target host).
- `raj.patel` credentials harvested from prior credential access scenarios (AGC-031 through AGC-036).

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Result |
|---|---|---|---|---|
| 1 | 2026-09-15 21:03:11 | net use \\\\10.10.10.102\C$ /user:raj.patel | COMPROMISED-HOST-01 | Error 67: network name not found |
| 2 | 2026-09-15 21:03:53 | net use \\\\10.10.10.102\ADMIN$ /user:raj.patel | COMPROMISED-HOST-01 | Error 3743: server not configured for remote admin |
| 3 | 2026-09-15 21:04:14 | net use \\\\10.10.10.102\IPC$ /user:raj.patel | COMPROMISED-HOST-01 | Error 64: network name no longer available |
| 4 | 2026-09-15 21:04:56 | net use \\\\127.0.0.1\C$ | COMPROMISED-HOST-01 | SUCCESS -- connected to localhost admin share |
| 5 | 2026-09-15 21:04:56 | Copy marker.txt to \\\\127.0.0.1\C$\Windows\Temp\ | COMPROMISED-HOST-01 | SUCCESS -- 57 bytes written |

**Key findings:**
- All 3 remote admin share access attempts to WIN-CLIENT-02 failed with different network errors (67, 3743, 64)
- Error 3743 ("server not configured for remote administration") on ADMIN$ suggests remote admin shares may be restricted on WIN-CLIENT-02
- Localhost C$ access succeeded, demonstrating the admin share access and file staging technique
- `raj.patel`'s password appeared in cleartext in all 3 remote `net use` command lines

**Cleanup:** Marker file deleted, net use connection disconnected.

## SOC Perspective

### Detection

**Sysmon EID 1 -- Process Create (5 events across 105 seconds):**

| Timestamp (UTC) | Image | CommandLine | PID | Cleartext Creds |
|---|---|---|---|---|
| 2026-09-15 21:03:11 | net.exe | `net.exe use \\10.10.10.102\C$ /user:raj.patel [REDACTED]` | 2428 | YES |
| 2026-09-15 21:03:53 | net.exe | `net.exe use \\10.10.10.102\ADMIN$ /user:raj.patel [REDACTED]` | 1640 | YES |
| 2026-09-15 21:04:14 | net.exe | `net.exe use \\10.10.10.102\IPC$ /user:raj.patel [REDACTED]` | 4352 | YES |
| 2026-09-15 21:04:56 | net.exe | `net.exe use \\127.0.0.1\C$` | 4928 | No |
| 2026-09-15 21:04:56 | net.exe | `net.exe use \\127.0.0.1\C$ /delete` | 4288 | No |

All share `LogonGuid: {eb65e329-b28e-6aa9-e913-590000000000}`.

**Critical finding:** Three Sysmon EID 1 events contain `raj.patel`'s cleartext password in the command line. This is both a detection goldmine (unambiguous credential use evidence) and a credential exposure (the password is now in the Sysmon event log).

**Security EID 4624 (destination):** No Type 3 logon events generated -- all remote connections failed before authentication completed.

### Investigation

**Step 1 -- Identify admin share targeting pattern:**
The defining indicator is `net use \\<IP>\C$` (or `ADMIN$` or `IPC$`). Admin shares (ending in `$`) are hidden by default and require local administrator privileges on the target. Accessing them with explicit `/user:` credentials from a workstation is a well-known lateral movement pattern.

Compare the signal strength:
- `net use \\server\SharedFolder` -- routine file share access (low signal)
- `net use \\IP\C$` -- admin share access by IP (high signal)
- `net use \\IP\C$ /user:<account> <password>` -- admin share with explicit credentials (critical signal)

**Step 2 -- Exclude deployment tools:**
Before classifying as malicious, check whether the source host is a known software deployment server (SCCM, PDQ Deploy, etc.) or if the account is a designated deployment service account. In this case: the source is a standard workstation and the executing account is the built-in Administrator -- not a deployment tool or service account.

**Step 3 -- Credential analysis:**
The `net use` commands use `raj.patel`'s credentials, which were not available to the attacker at the start of the engagement. Their use here confirms successful credential harvesting from prior stages (AGC-031 through AGC-036). This cross-references the credential access findings.

**Step 4 -- Multi-share targeting:**
The attacker tried C$, ADMIN$, and IPC$ in sequence. This shotgun approach (trying multiple admin shares) is more consistent with automated lateral movement tooling than manual access, where a user would typically try one share and stop.

**Step 5 -- Detection reuse:**
Reuses the same `net.exe` process creation detection as AGC-039/041. Enhanced rule: alert on `net.exe use` command lines containing `\C$`, `\ADMIN$`, or `\IPC$` with `/user:` parameter. This is an extremely high-confidence detection with near-zero false positives from workstation sources.

### Report

**Verdict: True Positive** -- Admin share lateral movement was attempted from a compromised workstation to another workstation using harvested credentials.

**Confidence: High** -- Calibrated assessment:
1. Admin share access (C$, ADMIN$, IPC$) from a workstation with explicit `/user:` credentials is not generated by any routine IT workflow on standard workstations.
2. The harvested credential (`raj.patel`) matches the IT-Support account identified in the credential access phase -- confirming cross-stage attack progression.
3. The multi-share targeting pattern (C$ -> ADMIN$ -> IPC$) is characteristic of automated lateral movement.
4. Cleartext password in command line confirms credential possession and provides an unambiguous forensic indicator.
5. Even though all remote connections failed, the attempt pattern is sufficient for True Positive classification.

**Response recommendation:**
1. **Immediate: rotate raj.patel's credentials** -- confirmed compromised (AGC-043 + AGC-044 both expose the password).
2. **Restrict admin share access:** Disable or restrict remote access to C$ and ADMIN$ via registry or GPO (`LocalAccountTokenFilterPolicy`). This prevents workstation-to-workstation admin share pivoting.
3. **Detection rule:** Alert on `net.exe use` command lines containing `\C$`, `\ADMIN$`, or `\IPC$` with `/user:` from workstation sources. Immediate escalation.
4. **Credential exposure monitoring:** Alert on any `net.exe` command line containing `/user:` -- cleartext credential use in net.exe is always a high-severity finding.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Lateral Movement (TA0008) | T1021.002 | Remote Services: SMB/Windows Admin Shares | Sysmon EID 1: `net.exe use \\10.10.10.102\C$`, `\\ADMIN$`, `\\IPC$` with `/user:raj.patel` and cleartext password. Three admin share types targeted in sequence. All remote failed (network errors 67/3743/64). Localhost C$ fallback succeeded with file staging. | High |

## Evidence

Screenshots: not applicable (text-based evidence collection only).

### Admin share connection results

```
Remote C$ (10.10.10.102):   Error 67 - network name not found
Remote ADMIN$ (10.10.10.102): Error 3743 - server not configured for remote admin
Remote IPC$ (10.10.10.102):  Error 64 - network name no longer available
Localhost C$ (127.0.0.1):    SUCCESS - file copied (57 bytes)
```

### Raw Sysmon EID 1 (net use \\10.10.10.102\C$)

```
Process Create:
UtcTime: 2026-09-15 21:03:11.101
ProcessId: 2428
Image: C:\Windows\System32\net.exe
OriginalFileName: net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" use \\10.10.10.102\C$ /user:raj.patel [REDACTED]
User: COMPROMISED-01\Administrator
LogonGuid: {eb65e329-b28e-6aa9-e913-590000000000}
LogonId: 0x5913E9
IntegrityLevel: High
Hashes: MD5=8A1E71312BD2AAE202652113049CDBD1
```

### Raw Sysmon EID 1 (net use \\10.10.10.102\ADMIN$)

```
Process Create:
UtcTime: 2026-09-15 21:03:53.252
ProcessId: 1640
Image: C:\Windows\System32\net.exe
OriginalFileName: net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" use \\10.10.10.102\ADMIN$ /user:raj.patel [REDACTED]
User: COMPROMISED-01\Administrator
LogonGuid: {eb65e329-b28e-6aa9-e913-590000000000}
LogonId: 0x5913E9
IntegrityLevel: High
Hashes: MD5=8A1E71312BD2AAE202652113049CDBD1
```

### Raw Sysmon EID 1 (net use \\10.10.10.102\IPC$)

```
Process Create:
UtcTime: 2026-09-15 21:04:14.386
ProcessId: 4352
Image: C:\Windows\System32\net.exe
OriginalFileName: net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" use \\10.10.10.102\IPC$ /user:raj.patel [REDACTED]
User: COMPROMISED-01\Administrator
LogonGuid: {eb65e329-b28e-6aa9-e913-590000000000}
LogonId: 0x5913E9
IntegrityLevel: High
Hashes: MD5=8A1E71312BD2AAE202652113049CDBD1
```
