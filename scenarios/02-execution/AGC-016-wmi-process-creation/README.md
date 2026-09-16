# AGC-016 — WMI-Based Local Process Creation

> **Disclosure:** Executed & documented by Claude Code under direction and review by Ali.

## Card

| Field | Value |
|---|---|
| ID | `AGC-016` |
| Category | `02-execution` — Execution |
| MITRE Technique | `T1047` Windows Management Instrumentation |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Immediate — Sysmon EID 1 captures child process with ParentImage = WmiPrvSE.exe |
| Time to Triage | 02:00 (from alert to WMI-Activity correlation and child-process assessment) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ [AGC-015](../AGC-015-signed-binary-proxy/README.md) · next [AGC-017](../AGC-017-task-triggered-execution/README.md) ▶ |
| One-line Summary | WMI `Win32_Process.Create` used to spawn `cmd.exe` through `WmiPrvSE.exe`, a process-creation method that bypasses standard parent-child relationships. |

## Attacker Perspective

### Tradecraft

**What:** The attacker uses Windows Management Instrumentation (WMI) to create processes via the `Win32_Process.Create` method. When invoked, the WMI Provider Host (`WmiPrvSE.exe`) spawns the requested process. That breaks the normal parent-child chain: the recorded parent is `WmiPrvSE.exe`, not the attacker's shell or C2 agent, so attribution gets harder.

WMI process creation is valuable to attackers because:
1. **Indirect execution** — the spawned process appears as a child of `WmiPrvSE.exe`, not the attacker's tool.
2. **Remote capability** — the same technique works over the network (DCOM/WinRM), enabling lateral movement (see AGC-046).
3. **Legitimate tool overlap** — enterprise management tools (SCCM, SCOM, custom monitoring) use WMI extensively, creating FP noise.
4. **No additional binaries** — WMI is built into every Windows installation since Windows 2000.

**Why at this lifecycle stage:** After initial compromise, the attacker runs payloads through WMI so they are harder to trace back to the infection vector. The `WmiPrvSE.exe` parent hides where the command came from.

**Key triage differentiator:** `WmiPrvSE.exe` spawning `cmd.exe` or `powershell.exe` is the primary detection signal. Cross-reference against known legitimate WMI consumers (SCCM agent, monitoring tools) before escalating.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Sysmon active.
- Note: `wmic.exe` removed in Windows 11 24H2. Used PowerShell `Invoke-WmiMethod` instead, which invokes the same underlying `Win32_Process.Create` WMI method and produces identical Sysmon/WMI artifacts.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 18:50:55 | WMI process creation | COMPROMISED-HOST-01 | `Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList "cmd.exe /c echo AGC016-marker > C:\Windows\Temp\agc016.txt"` — ReturnValue: 0, spawned PID 3456 |
| 2 | 2026-09-15 18:50:55 | cmd.exe executes | COMPROMISED-HOST-01 | cmd.exe (PID 3456) writes marker file. ParentProcess: WmiPrvSE.exe (PID 5472) |
| 3 | 2026-09-15 18:51:00 | Verification | COMPROMISED-HOST-01 | Marker file `C:\Windows\Temp\agc016.txt` confirmed with content "AGC016-marker" |

**Cleanup:** Marker file removed after evidence collection.

## SOC Perspective

### Detection

**Sysmon telemetry (COMPROMISED-HOST-01):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 18:50:55 | 1 | Process Create | **Image:** `C:\Windows\System32\cmd.exe` (PID 3456). **CommandLine:** `cmd.exe /c echo AGC016-marker > C:\Windows\Temp\agc016.txt`. **ParentProcessId:** 5472. **ParentImage:** `C:\Windows\System32\wbem\WmiPrvSE.exe`. **User:** `COMPROMISED-01\Administrator`. **IntegrityLevel:** High. **Hashes:** MD5=CE396564392FAFAAD5C07A5E2DADE4E6, SHA256=97AC98B1A92C286054CCE55239CFCCDFC23A5517BD07FE693072C9CA96C7DABB |

**WMI-Activity operational log:**

| Timestamp | EID | Detail |
|---|---|---|
| 2026-09-15 18:50:55 | 5857 | CIMWin32 provider started with result code 0x0. **HostProcess = wmiprvse.exe; ProcessID = 5472**; ProviderPath = `%systemroot%\system32\wbem\cimwin32.dll` |

**Key detection signal:** Sysmon EID 1 where `ParentImage` ends with `WmiPrvSE.exe` and the child process is a command interpreter (`cmd.exe`, `powershell.exe`) or a suspicious binary. Correlate with WMI-Activity EID 5857 to confirm the CIMWin32 provider (which hosts `Win32_Process`) loaded in the same `WmiPrvSE.exe` instance.

### Investigation

**Step 1 — Identify WMI-spawned processes:**
At 18:50:55 UTC, Sysmon EID 1 recorded `cmd.exe` (PID 3456) with `ParentImage = C:\Windows\System32\wbem\WmiPrvSE.exe` (PID 5472). A `WmiPrvSE.exe` parent means a WMI method call created the process, not a user session or a shell.

**Step 2 — Correlate with WMI-Activity log:**
WMI-Activity EID 5857 at the same timestamp shows the CIMWin32 provider loading in `WmiPrvSE.exe` PID 5472. `cimwin32.dll` hosts the `Win32_Process` class, confirming `Win32_Process.Create` as the method called. Two sources (Sysmon and WMI-Activity) agree on the same PID and the same second.

**Step 3 — Assess the child process behavior:**
The spawned `cmd.exe` wrote a file to `C:\Windows\Temp`. Here the payload is benign. In a real attack a WMI-spawned process would typically:
- Download and execute second-stage payloads
- Execute reconnaissance commands (whoami, ipconfig, net group)
- Establish persistence or lateral movement

**Step 4 — Check against legitimate WMI consumers:**
The lab runs no enterprise management tools (SCCM, SCOM, or custom WMI scripts). No known management workflow issued this WMI call, so it is anomalous.

### Report

**Verdict: True Positive** — WMI `Win32_Process.Create` used to spawn `cmd.exe` through `WmiPrvSE.exe`, confirmed by both Sysmon EID 1 (parent-child relationship) and WMI-Activity EID 5857 (provider load).

**Confidence: High** — Two sources (Sysmon and the WMI-Activity log) plus the absence of WMI management tools in the lab make this a strong finding:
- `WmiPrvSE.exe` spawning `cmd.exe` is uncommon in normal desktop use.
- The CIMWin32 provider load confirms a real `Win32_Process` operation.
- No management tool (SCCM, monitoring agent) runs in the lab that could explain the call.

**Response recommendation:**
1. **Investigate the WMI invocation source** — determine what process or user initiated the `Invoke-WmiMethod` / `wmic` call. Check the PowerShell script block log or process audit log.
2. **Check for remote WMI** — if the WMI call came over the network (DCOM), this becomes lateral movement (T1047 + TA0008). Check for source IP in WMI-Activity EID 5860/5861.
3. **Review all WmiPrvSE.exe children** — search for other processes spawned by the same `WmiPrvSE.exe` instance (PID 5472) to identify additional payload execution.
4. **Detection rule:** Alert on Sysmon EID 1 where `ParentImage LIKE '%\WmiPrvSE.exe'` AND (`Image LIKE '%\cmd.exe'` OR `Image LIKE '%\powershell.exe'` OR `Image NOT IN (known-legitimate-wmi-children)`).
5. **Hardening:** Restrict WMI namespace permissions via `wmimgmt.msc`. Add Windows Firewall rules to block remote WMI (DCOM TCP 135 + dynamic ports) from non-management subnets.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Execution (TA0002) | T1047 | Windows Management Instrumentation | `Win32_Process.Create` invoked via PowerShell `Invoke-WmiMethod`. WmiPrvSE.exe (PID 5472) spawned cmd.exe (PID 3456). WMI-Activity EID 5857 confirms CIMWin32 provider load. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
