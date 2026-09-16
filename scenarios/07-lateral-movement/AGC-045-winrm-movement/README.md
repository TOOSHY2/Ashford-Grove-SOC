# AGC-045 — WinRM Lateral Movement

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-045` |
| Category | `07-lateral-movement` — Lateral Movement |
| MITRE Technique | `T1021.006` Remote Services: Windows Remote Management |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Immediate — Sysmon EID 1 captures `wsmprovhost.exe -Embedding` (WinRM host process); Security EID 4624 Type 3 captures the network logon; WinRM Operational log captures shell creation with ResourceUri |
| Time to Triage | 03:00 (cross-reference EID 4104 script-block content on destination; verify source host is a designated management workstation) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) as source; target: `WIN-CLIENT-02` (10.10.10.102) |
| Chain | ◀ [AGC-044](../AGC-044-smb-admin-share/README.md) · next [AGC-046](../AGC-046-remote-wmi-execution/README.md) ▶ |
| One-line Summary | WinRM lateral movement via `Invoke-Command` attempted against WIN-CLIENT-02 (failed — TCP 5985 unreachable). Localhost fallback succeeded after `Enable-PSRemoting`: `wsmprovhost.exe` spawned, marker file written (63 bytes) via remote PowerShell session. 3 Sysmon EID 1 events (wsmprovhost.exe, svchost.exe WinRM service, powershell.exe). 4 Security EID 4624 Type 3 logons from 127.0.0.1 via NTLM V2. 50 WinRM Operational events including shell creation with `Microsoft.PowerShell` ResourceUri. |

## Attacker Perspective

### Tradecraft

**What:** Windows Remote Management (WinRM) is a Microsoft implementation of WS-Management protocol that enables remote PowerShell execution via `Invoke-Command`, `Enter-PSSession`, or direct `winrm` commands. WinRM operates over HTTP (port 5985) or HTTPS (port 5443) and is the backbone of PowerShell Remoting.

Key characteristics:
- **Invoke-Command** executes arbitrary script blocks on remote hosts — the most powerful remote execution mechanism built into Windows
- The remote process runs as `wsmprovhost.exe` (WS-Management Provider Host) on the destination
- WinRM uses WS-Management shell creation with a `ResourceUri` of `http://schemas.microsoft.com/powershell/Microsoft.PowerShell`
- Authentication is via NTLM or Kerberos, generating Type 3 (Network) logon events

**Why at this lifecycle stage:** After SMB admin share access (AGC-044) provided file-level remote access, WinRM provides something more powerful: remote code execution. WinRM is the preferred lateral movement protocol for attackers who have already obtained valid credentials because:
1. It is a legitimate Windows management protocol (blends with IT operations)
2. It provides full PowerShell execution context on the remote host
3. It can be harder to detect than PsExec or scheduled task creation
4. Script-block logging (EID 4104) on the destination captures what was executed — but only if enabled

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.
- `WIN-CLIENT-02` running (target host).
- `raj.patel` credentials harvested from prior credential access scenarios.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Result |
|---|---|---|---|---|
| 1 | 2026-09-15 21:11:40 | TCP test to 10.10.10.102:5985 | COMPROMISED-HOST-01 | CLOSED/TIMEOUT — WinRM port not reachable |
| 2 | 2026-09-15 21:11:45 | Invoke-Command to 10.10.10.102 with raj.patel cred | COMPROMISED-HOST-01 | Failed — TrustedHosts + network unreachable |
| 3 | 2026-09-15 21:11:45 | Invoke-Command to 127.0.0.1 (localhost) | COMPROMISED-HOST-01 | Failed — WinRM not configured |
| 4 | 2026-09-15 21:11:58 | Enable-PSRemoting -Force | COMPROMISED-HOST-01 | Succeeded — WinRM service started |
| 5 | 2026-09-15 21:12:05 | Invoke-Command to 127.0.0.1 (retry) | COMPROMISED-HOST-01 | Succeeded — marker file written (63 bytes) |
| 6 | 2026-09-15 21:12:06 | Cleanup | COMPROMISED-HOST-01 | Marker file removed |

**Key findings:**
- Remote WinRM to WIN-CLIENT-02 failed for two reasons: TCP 5985 unreachable (network isolation) and TrustedHosts restriction (IP-based authentication requires explicit TrustedHosts configuration)
- Enable-PSRemoting on localhost started the WinRM service (svchost.exe -k NetworkService -p -s WinRM) and configured the WinRM listener
- Localhost WinRM succeeded on retry: `wsmprovhost.exe -Embedding` spawned as the remote session host process
- The entire WinRM session lifecycle was captured: service start, shell creation, command execution, shell close, session close

## SOC Perspective

### Detection

**Sysmon EID 1 — Process Create (3 events):**

| Timestamp (UTC) | Image | CommandLine | PID | User |
|---|---|---|---|---|
| 2026-09-15 21:11:39 | powershell.exe | `powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc045-sim.ps1` | 3144 | Administrator |
| 2026-09-15 21:11:58 | svchost.exe | `svchost.exe -k NetworkService -p -s WinRM` | 3256 | NT AUTHORITY\NETWORK SERVICE |
| 2026-09-15 21:12:05 | wsmprovhost.exe | `C:\WINDOWS\system32\wsmprovhost.exe -Embedding` | 5680 | Administrator |

**Critical indicator — wsmprovhost.exe:** The WS-Management Provider Host process is the definitive WinRM remote session indicator. This process:
- Only spawns when a WinRM remote session is established
- Runs under the authenticated user's context (Administrator in this case)
- Has `-Embedding` flag indicating COM activation (automated, not interactive)
- Its parent process is `svchost.exe` hosting the WinRM service

**Security EID 4624 — Type 3 Network Logon (4 events):**

| Timestamp (UTC) | Account | Source | Logon Process | Auth Package |
|---|---|---|---|---|
| 2026-09-15 21:12:05 | COMPROMISED-01\Administrator | 127.0.0.1:64507 | NtLmSsp | NTLM V2 |
| 2026-09-15 21:12:05 | COMPROMISED-01\Administrator | 127.0.0.1:64508 | NtLmSsp | NTLM V2 |
| 2026-09-15 21:12:05 | COMPROMISED-01\Administrator | 127.0.0.1:64509 | NtLmSsp | NTLM V2 |
| 2026-09-15 21:12:06 | COMPROMISED-01\Administrator | 127.0.0.1:64509 | NtLmSsp | NTLM V2 |

Multiple Type 3 logons from the same source within 1 second, all NTLM V2, all elevated tokens. The multiple logon events reflect WinRM's session initialization (authentication, shell creation, command execution, enumeration).

**WinRM Operational Log (50 events in ~1 second):**

Key events in sequence:
1. `EID 2` — Initializing WSMan API
2. `EID 29` — Initialization completed
3. `EID 6` — Creating WSMan Session to `127.0.0.1/wsman?PSVersion=5.1.26100.9444`
4. `EID 31` — Session created successfully
5. `EID 145/132` — Multiple Plugin enumeration/get operations
6. `EID 91` — **Creating WSMan shell** with ResourceUri `http://schemas.microsoft.com/powershell/Microsoft.PowerShell` (COMPROMISED-01\Administrator clientIP: 127.0.0.1)
7. `EID 11` — Shell created with ShellId `4CB2EDD9-51AE-4011-BBEC-817DD34DBCF8`
8. `EID 13` — Running WSMan commands (CommandIds: `07C5DEA2...`, `1FE831BE...`)
9. `EID 15/16` — Closing commands and shell
10. `EID 8/33` — Closing session
11. `EID 4/30` — Deinitializing WSMan API

**EID 91 is the highest-value WinRM indicator:** It captures the shell creation with the authenticated user, client IP, and ResourceUri in a single event.

### Investigation

**Step 1 — Identify WinRM remote execution:**
The primary indicator is `wsmprovhost.exe -Embedding` in Sysmon EID 1. This process ONLY exists during active WinRM remote sessions. Cross-reference with WinRM EID 91 (shell creation) to get the source IP and authenticated account.

**Step 2 — Determine source host role:**
Is the source host a designated management workstation or jump host? WinRM from IT automation servers (Ansible, SCCM, Azure Arc) is expected. WinRM from a standard user workstation (COMPROMISED-HOST-01) is anomalous — this host has no documented management role.

**Step 3 — Examine script-block content (EID 4104):**
PowerShell script-block logging (EID 4104) on the destination captures the exact commands executed via the remote session. In this case, 0 EID 4104 events were captured — this is a detection gap. Script-block logging should be enabled via GPO on all managed endpoints. When enabled, EID 4104 would reveal the exact script block: file creation of a marker at `C:\Windows\Temp\agc045.txt`.

**Step 4 — Enable-PSRemoting as preparation:**
The attacker ran `Enable-PSRemoting -Force` to configure WinRM on the compromised host before executing the remote session. This is itself an indicator — enabling PSRemoting on a standard workstation where it was previously disabled is a configuration change that should be detected. The svchost.exe WinRM service start event (EID 1) captures this.

**Step 5 — Detection reuse:**
This builds on the lateral movement detection chain from AGC-043 (RDP) and AGC-044 (SMB). The pattern is: failed remote protocol -> try next protocol. RDP (3389 blocked) -> SMB (445 errors) -> WinRM (5985). This protocol rotation is itself a behavioral indicator of automated lateral movement.

### Report

**Verdict: True Positive** — WinRM lateral movement was attempted from a compromised workstation, with localhost execution demonstrating the technique after remote target was unreachable.

**Confidence: High** — Calibrated assessment:
1. `wsmprovhost.exe -Embedding` only spawns during WinRM remote sessions — zero false positive rate for this process.
2. WinRM Operational EID 91 captures shell creation with authenticated user and source IP — unambiguous remote execution evidence.
3. The source host (COMPROMISED-HOST-01) is a standard workstation with no documented management role — WinRM from this host is anomalous.
4. Enable-PSRemoting was run to configure WinRM — an attacker preparation step that changes system configuration.
5. 4 Type 3 logon events within 1 second from the same source reflect the WinRM session lifecycle.

**Response recommendation:**
1. **Restrict WinRM access:** Configure Windows Firewall to allow WinRM (TCP 5985/5443) only from designated management subnets or jump hosts. Block workstation-to-workstation WinRM.
2. **Enable script-block logging:** Deploy GPO to enable PowerShell Script Block Logging (EID 4104) on all endpoints. This is the single most valuable detection source for WinRM attacks — it captures what was actually executed remotely.
3. **Detection rule:** Alert on `wsmprovhost.exe` process creation from non-management source IPs. Cross-reference with WinRM EID 91 for shell creation context.
4. **Monitor Enable-PSRemoting:** Alert on WinRM service start (svchost.exe -k NetworkService -p -s WinRM) on hosts where WinRM is not expected.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Lateral Movement (TA0008) | T1021.006 | Remote Services: Windows Remote Management | Sysmon EID 1: `wsmprovhost.exe -Embedding` (PID 5680). Security EID 4624 Type 3 from 127.0.0.1 via NTLM V2 (4 events). WinRM Operational EID 91: shell creation with ResourceUri `Microsoft.PowerShell`, clientIP 127.0.0.1. Remote target 10.10.10.102 unreachable (TCP 5985 timeout). Localhost execution succeeded after Enable-PSRemoting. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### WinRM execution results

```
Remote target (10.10.10.102):  TCP 5985 CLOSED/TIMEOUT + TrustedHosts error
Localhost (127.0.0.1):         Initially failed, then Enable-PSRemoting, then SUCCEEDED
Marker file:                   C:\Windows\Temp\agc045.txt (63 bytes), cleaned up
```

### Raw Sysmon EID 1 (wsmprovhost.exe — WinRM host process)

```
Process Create:
UtcTime: 2026-09-15 21:12:05.678
ProcessId: 5680
Image: C:\Windows\System32\wsmprovhost.exe
Description: Host process for WinRM plug-ins
OriginalFileName: wsmprovhost.exe
CommandLine: C:\WINDOWS\system32\wsmprovhost.exe -Embedding
User: COMPROMISED-01\Administrator
LogonGuid: {eb65e329-b4a5-6aa9-b7f7-5c0000000000}
LogonId: 0x5CF7B7
IntegrityLevel: High
Hashes: MD5=0C4FB78B24CC0E8BE2CC75661199DE07
```

### Raw Sysmon EID 1 (WinRM service start)

```
Process Create:
UtcTime: 2026-09-15 21:11:58.005
ProcessId: 3256
Image: C:\Windows\System32\svchost.exe
OriginalFileName: svchost.exe
CommandLine: C:\WINDOWS\System32\svchost.exe -k NetworkService -p -s WinRM
User: NT AUTHORITY\NETWORK SERVICE
LogonGuid: {eb65e329-8b7c-6aa9-e403-000000000000}
LogonId: 0x3E4
IntegrityLevel: System
Hashes: MD5=07FE1BE55D1049C7B48E270C466502D4
```

### Raw Security EID 4624 (WinRM Type 3 logon)

```
An account was successfully logged on.
Logon Type:           3
Account Name:         Administrator
Account Domain:       COMPROMISED-01
Logon ID:             0x5CF7B7
Source Network Address: 127.0.0.1
Source Port:          64507
Logon Process:        NtLmSsp
Authentication Package: NTLM
Package Name:         NTLM V2
Elevated Token:       Yes
```

### WinRM Operational EID 91 (shell creation)

```
Creating WSMan shell on server with ResourceUri:
  http://schemas.microsoft.com/powershell/Microsoft.PowerShell
  (COMPROMISED-01\Administrator clientIP: 127.0.0.1)
ShellId: 4CB2EDD9-51AE-4011-BBEC-817DD34DBCF8
```
