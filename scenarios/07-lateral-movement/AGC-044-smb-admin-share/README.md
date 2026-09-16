# AGC-044 — SMB Admin-Share Access (C$)

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-044` |
| Category | `07-lateral-movement` — Lateral Movement |
| MITRE Technique | `T1021.002` Remote Services: SMB/Windows Admin Shares |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Immediate — Sysmon EID 1 captures `net.exe use \\<target>\C$` with target and cleartext credentials in command line |
| Time to Triage | 02:00 (verify access is not from a known deployment tool; check for subsequent file copy or remote execution) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) as source; target: `WIN-CLIENT-02` (10.10.10.102) |
| Chain | ◀ [AGC-043](../AGC-043-unusual-rdp-logon/README.md) · next [AGC-045](../AGC-045-winrm-movement/README.md) ▶ |
| One-line Summary | SMB admin share access attempted against WIN-CLIENT-02: `net use \\10.10.10.102\C$`, `\\ADMIN$`, and `\\IPC$` with `raj.patel` credentials (cleartext in command line). All remote connections failed (network errors). Localhost C$ fallback succeeded — marker file copied to `\\127.0.0.1\C$\Windows\Temp\`. 5 Sysmon EID 1 events captured, 3 containing cleartext password. Admin share targeting with explicit credentials from a compromised workstation is a high-confidence lateral movement indicator. |

## Attacker Perspective

### Tradecraft

**What:** The attacker used the Windows administrative shares (C$, ADMIN$, IPC$) to reach the file system of another host over SMB. The three shares differ:
- **C$** — maps to the C:\ drive root; full file system read/write
- **ADMIN$** — maps to the Windows directory (C:\Windows); a common payload staging spot
- **IPC$** — inter-process communication; used for null sessions, named pipe access, and as the precursor to remote execution (PsExec, WMI, service creation)

Passing explicit credentials with the `/user:` flag means the attacker is authenticating to remote hosts with harvested credentials. Putting the cleartext password on the `net use` command line is an operational security mistake, because Sysmon records the whole command line.

**Why at this lifecycle stage:** RDP failed in AGC-043 (port 3389 unreachable), so the attacker tried SMB instead. SMB (port 445) is often more permissive than RDP, and file-level access lets the attacker stage a payload without an interactive session.

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
| 4 | 2026-09-15 21:04:56 | net use \\\\127.0.0.1\C$ | COMPROMISED-HOST-01 | SUCCESS — connected to localhost admin share |
| 5 | 2026-09-15 21:04:56 | Copy marker.txt to \\\\127.0.0.1\C$\Windows\Temp\ | COMPROMISED-HOST-01 | SUCCESS — 57 bytes written |

**Key findings:**
- All 3 remote admin share attempts against WIN-CLIENT-02 failed, each with a different network error (67, 3743, 64)
- Error 3743 ("server not configured for remote administration") on ADMIN$ suggests WIN-CLIENT-02 restricts remote admin shares
- The localhost C$ fallback worked, so the share-access and file-staging steps still produced telemetry
- `raj.patel`'s password appeared in cleartext in all 3 remote `net use` command lines

**Cleanup:** Marker file deleted, net use connection disconnected.

## SOC Perspective

### Detection

**Sysmon EID 1 — Process Create (5 events across 105 seconds):**

| Timestamp (UTC) | Image | CommandLine | PID | Cleartext Creds |
|---|---|---|---|---|
| 2026-09-15 21:03:11 | net.exe | `net.exe use \\10.10.10.102\C$ /user:raj.patel [REDACTED]` | 2428 | YES |
| 2026-09-15 21:03:53 | net.exe | `net.exe use \\10.10.10.102\ADMIN$ /user:raj.patel [REDACTED]` | 1640 | YES |
| 2026-09-15 21:04:14 | net.exe | `net.exe use \\10.10.10.102\IPC$ /user:raj.patel [REDACTED]` | 4352 | YES |
| 2026-09-15 21:04:56 | net.exe | `net.exe use \\127.0.0.1\C$` | 4928 | No |
| 2026-09-15 21:04:56 | net.exe | `net.exe use \\127.0.0.1\C$ /delete` | 4288 | No |

All share `LogonGuid: {eb65e329-b28e-6aa9-e913-590000000000}`.

**Critical finding:** Three Sysmon EID 1 events carry `raj.patel`'s cleartext password in the command line. That is unambiguous evidence of credential use, and it is also a credential exposure — the password is now in the Sysmon event log.

**Security EID 4624 (destination):** No Type 3 logon events — every remote connection failed before authentication completed.

### Investigation

**Step 1 — Identify admin share targeting pattern:**
The defining indicator is `net use \\<IP>\C$` (or `ADMIN$` or `IPC$`). Admin shares (ending in `$`) are hidden by default and need local administrator rights on the target. Reaching for them with explicit `/user:` credentials from a workstation is a lateral movement pattern, not a file-sharing one.

Compare the signal strength:
- `net use \\server\SharedFolder` — routine file share access (low signal)
- `net use \\IP\C$` — admin share access by IP (high signal)
- `net use \\IP\C$ /user:<account> <password>` — admin share with explicit credentials (critical signal)

**Step 2 — Exclude deployment tools:**
Before calling this malicious, check whether the source host is a software deployment server (SCCM, PDQ Deploy, etc.) or the account is a deployment service account. Here the source is a standard workstation and the executing account is the built-in Administrator — neither a deployment tool nor a service account.

**Step 3 — Credential analysis:**
The `net use` commands carry `raj.patel`'s credentials, which the attacker did not have at the start of the engagement. Using them here confirms the credential harvesting in AGC-031 through AGC-036 paid off.

**Step 4 — Multi-share targeting:**
The attacker tried C$, ADMIN$, and IPC$ in sequence. Cycling through all three looks like tooling rather than a person, who would usually try one share and stop.

**Step 5 — Detection reuse:**
The same `net.exe` process creation detection from AGC-039/041 covers this. Enhanced rule: alert on `net.exe use` command lines containing `\C$`, `\ADMIN$`, or `\IPC$` with a `/user:` parameter. From workstation sources this should produce near-zero false positives.

### Report

**Verdict: True Positive** — Admin share lateral movement was attempted from a compromised workstation to another workstation using harvested credentials.

**Confidence: High** — Calibrated assessment:
1. No routine IT workflow on a standard workstation runs admin share access (C$, ADMIN$, IPC$) with explicit `/user:` credentials.
2. The harvested credential (`raj.patel`) is the IT-Support account identified in the credential access phase, which ties this stage to that one.
3. Cycling C$ -> ADMIN$ -> IPC$ in sequence is how tooling behaves, not a person.
4. The cleartext password in the command line proves the attacker holds the credential and leaves an unambiguous forensic marker.
5. Every remote connection failed, but the attempt pattern alone supports a true positive.

**Response recommendation:**
1. **Immediate: rotate raj.patel's credentials** — confirmed compromised (AGC-043 + AGC-044 both expose the password).
2. **Restrict admin share access:** Disable or restrict remote access to C$ and ADMIN$ via registry or GPO (`LocalAccountTokenFilterPolicy`) to block workstation-to-workstation admin share pivoting.
3. **Detection rule:** Alert on `net.exe use` command lines containing `\C$`, `\ADMIN$`, or `\IPC$` with `/user:` from workstation sources. Escalate immediately.
4. **Credential exposure monitoring:** Alert on any `net.exe` command line containing `/user:` — a cleartext credential in net.exe is high severity every time.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Lateral Movement (TA0008) | T1021.002 | Remote Services: SMB/Windows Admin Shares | Sysmon EID 1: `net.exe use \\10.10.10.102\C$`, `\\ADMIN$`, `\\IPC$` with `/user:raj.patel` and cleartext password. Three admin share types targeted in sequence. All remote failed (network errors 67/3743/64). Localhost C$ fallback succeeded with file staging. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

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
