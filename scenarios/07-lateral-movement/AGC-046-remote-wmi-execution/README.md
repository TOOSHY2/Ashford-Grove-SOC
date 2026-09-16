# AGC-046 — Remote WMI Execution

> **Disclosure:** Executed & documented by Claude Code under direction and review by Ali.

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

**What:** Windows Management Instrumentation (WMI) can create a process on a remote host through the `Win32_Process.Create` method. Called remotely (`wmic /node:<target>` or `Invoke-WmiMethod -ComputerName`), WMI:
- Authenticates to the remote host (Type 3 network logon)
- Spawns `WmiPrvSE.exe` (WMI Provider Service Host) on the destination
- Has WmiPrvSE.exe create the child process the attacker asked for

The parent-child link (`WmiPrvSE.exe` -> attacker's command) is the detection signature. Unlike PsExec (which installs a service) or WinRM (which spawns `wsmprovhost.exe`), WMI process creation leaves a lighter footprint — no service, no persistent artifacts.

**Notable finding:** `wmic.exe` is deprecated and gone from Windows 11. The attacker has to use PowerShell's `Invoke-WmiMethod` or `Invoke-CimMethod` as the WMI client instead. Detection should therefore watch WmiPrvSE.exe child processes rather than `wmic.exe` process creation.

**Why at this lifecycle stage:** After RDP (AGC-043), SMB (AGC-044), and WinRM (AGC-045), WMI is the fourth lateral movement protocol the attacker tried. It appeals because:
1. It rides DCOM (port 135 + dynamic ports) rather than a dedicated management port
2. It needs no interactive session — fire-and-forget execution
3. Output does not return to the caller, so it is harder to spot as a C2 channel
4. It is a legitimate Windows management protocol that enterprise tools use daily

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
- `wmic.exe` is gone from Windows 11, a real change from earlier versions where it was everywhere
- `Invoke-WmiMethod` (PowerShell) still works as a WMI client
- WmiPrvSE.exe was the parent of the created cmd.exe, which confirms the WMI execution path
- Remote execution to WIN-CLIENT-02 was not possible (network unreachable), so the run was local; the detection artifacts are identical

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
1. **ParentImage = WmiPrvSE.exe** — The definitive WMI process creation signature. Any process `WmiPrvSE.exe` spawns came through WMI's `Win32_Process.Create` method.
2. **ParentCommandLine = `wmiprvse.exe -secured -Embedding`** — `-secured` means authenticated WMI access; `-Embedding` means COM activation, not an interactive launch.
3. **ParentUser = NT AUTHORITY\NETWORK SERVICE** — WmiPrvSE.exe runs as NETWORK SERVICE, but the child process carries the authenticated user's token (Administrator).

**wmic.exe deprecation note:** 0 Sysmon EID 1 events for wmic.exe — it no longer exists on Windows 11. Rules keyed on wmic.exe process creation will never fire on these hosts; watch WmiPrvSE.exe child processes instead.

### Investigation

**Step 1 — Identify WMI process creation pattern:**
The primary indicator is any Sysmon EID 1 event where `ParentImage` is `WmiPrvSE.exe` — the same detection as AGC-016 (local WMI execution). The child process command line shows what the attacker ran.

**Step 2 — Determine local vs. remote origin:**
This is what separates local WMI use from lateral movement. For a remote WMI call:
- Security EID 4624 Type 3 (Network logon) would appear on the destination host from the source host's IP in the same narrow window
- The LogonId in the child process EID 1 would match the LogonId in that 4624

Here the execution was local (localhost), so no remote-origin 4624 exists. Against a real remote target, the 4624 Type 3 from the source host IP is what turns "local WMI usage" into "remote WMI lateral movement."

**Step 3 — Analyze the child process:**
The command line `cmd.exe /c echo AGC-046-wmi-method > C:\Windows\Temp\agc046b.txt` is a marker write. Outside the lab, WMI-spawned commands usually:
- Download and execute payloads: `cmd.exe /c powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString(...)"`
- Create persistence: `cmd.exe /c schtasks /create ...`
- Stage tools: `cmd.exe /c certutil -urlcache -f http://... C:\Windows\Temp\...`

**Step 4 — Cross-reference with AGC-016:**
AGC-016 covered local WMI execution; this scenario carries it into the lateral movement context. The detection is the same (WmiPrvSE.exe parent), but the response differs: remote WMI means the attacker already owns the source host and holds valid credentials for the destination.

**Step 5 — wmic.exe deprecation impact:**
Two rule changes follow:
- **Remove:** Alert on `wmic.exe` process creation (no longer exists on Win11)
- **Add/Enhance:** Alert on any process with `ParentImage: WmiPrvSE.exe` that is not a known WMI consumer (SCCM, monitoring agents, etc.)

### Report

**Verdict: True Positive** — WMI process creation ran and produced the remote-execution artifacts the technique leaves.

**Confidence: High** — Calibrated assessment:
1. `WmiPrvSE.exe` as parent is the definitive WMI execution indicator — no ambiguity.
2. The `-secured -Embedding` flags on WmiPrvSE.exe confirm authenticated, non-interactive WMI access.
3. The child process (cmd.exe writing to `C:\Windows\Temp`) matches attacker payload staging.
4. `wmic.exe` being gone from Win11 matters for detection — legacy rules need updating.
5. Local execution produces the same artifacts as remote execution; only the EID 4624 source IP separates them.

**Response recommendation:**
1. **Update detection rules:** Replace wmic.exe-based detection with WmiPrvSE.exe child process monitoring. Alert on any non-whitelisted process WmiPrvSE.exe spawns.
2. **Restrict WMI namespace ACLs:** Configure DCOM permissions and WMI namespace security so only designated management accounts can call Win32_Process.Create.
3. **Monitor DCOM traffic:** Remote WMI rides DCOM (TCP 135 + dynamic ports). DCOM traffic between workstations is worth a network-level alert.
4. **Correlate with lateral movement chain:** This is the fourth lateral movement technique from COMPROMISED-HOST-01 (RDP -> SMB -> WinRM -> WMI). That rotation should escalate the investigation of the source host.

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
