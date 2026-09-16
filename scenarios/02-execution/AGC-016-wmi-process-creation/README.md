# AGC-016 — WMI-Based Local Process Creation

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

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

**What:** The attacker uses Windows Management Instrumentation (WMI) to create processes via the `Win32_Process.Create` method. When invoked, the WMI Provider Host (`WmiPrvSE.exe`) spawns the requested process. This breaks the normal parent-child process chain because the actual parent is `WmiPrvSE.exe` rather than the attacker's shell or C2 agent, making attribution harder.

WMI process creation is valuable to attackers because:
1. **Indirect execution** — the spawned process appears as a child of `WmiPrvSE.exe`, not the attacker's tool.
2. **Remote capability** — the same technique works over the network (DCOM/WinRM), enabling lateral movement (see AGC-046).
3. **Legitimate tool overlap** — enterprise management tools (SCCM, SCOM, custom monitoring) use WMI extensively, creating FP noise.
4. **No additional binaries** — WMI is built into every Windows installation since Windows 2000.

**Why at this lifecycle stage:** After initial compromise, the attacker uses WMI to execute payloads in a way that is harder to trace back to the original infection vector. The `WmiPrvSE.exe` parent obscures the true origin of the command.

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
At 18:50:55 UTC, Sysmon EID 1 recorded `cmd.exe` (PID 3456) with `ParentImage = C:\Windows\System32\wbem\WmiPrvSE.exe` (PID 5472). The `WmiPrvSE.exe` parent is the definitive indicator that this process was created via a WMI method call, not through normal user interaction or shell execution.

**Step 2 — Correlate with WMI-Activity log:**
WMI-Activity EID 5857 at the same timestamp confirms that the CIMWin32 provider loaded in `WmiPrvSE.exe` PID 5472. The `cimwin32.dll` provider hosts the `Win32_Process` class, confirming that `Win32_Process.Create` was the method invoked. This two-source correlation (Sysmon + WMI-Activity) strengthens the finding.

**Step 3 — Assess the child process behavior:**
The spawned `cmd.exe` wrote a file to `C:\Windows\Temp`. In this simulation, the payload is benign. In a real attack, WMI-spawned processes typically:
- Download and execute second-stage payloads
- Execute reconnaissance commands (whoami, ipconfig, net group)
- Establish persistence or lateral movement

**Step 4 — Check against legitimate WMI consumers:**
No enterprise management tools (SCCM, SCOM, or custom WMI scripts) are deployed in this lab environment. The WMI process creation was not initiated by any known legitimate management workflow, confirming this as anomalous.

### Report

**Verdict: True Positive** — WMI `Win32_Process.Create` used to spawn `cmd.exe` through `WmiPrvSE.exe`, confirmed by both Sysmon EID 1 (parent-child relationship) and WMI-Activity EID 5857 (provider load).

**Confidence: High** — The dual-source evidence (Sysmon + WMI-Activity log) and the absence of legitimate WMI management tools in the environment make this a strong indicator:
- `WmiPrvSE.exe` spawning `cmd.exe` is uncommon in normal desktop usage.
- The CIMWin32 provider load confirms an actual `Win32_Process` operation.
- Cross-referencing with known management tools (SCCM, monitoring agents) eliminates legitimate use in this environment.

**Response recommendation:**
1. **Investigate the WMI invocation source** — determine what process or user initiated the `Invoke-WmiMethod` / `wmic` call. Check the PowerShell script block log or process audit log.
2. **Check for remote WMI** — if the WMI call came over the network (DCOM), this becomes lateral movement (T1047 + TA0008). Check for source IP in WMI-Activity EID 5860/5861.
3. **Review all WmiPrvSE.exe children** — search for other processes spawned by the same `WmiPrvSE.exe` instance (PID 5472) to identify additional payload execution.
4. **Detection rule:** Alert on Sysmon EID 1 where `ParentImage LIKE '%\WmiPrvSE.exe'` AND (`Image LIKE '%\cmd.exe'` OR `Image LIKE '%\powershell.exe'` OR `Image NOT IN (known-legitimate-wmi-children)`).
5. **Hardening:** Restrict WMI namespace permissions via `wmimgmt.msc`. Consider Windows Firewall rules to block remote WMI (DCOM TCP 135 + dynamic ports) for non-management subnets.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Execution (TA0002) | T1047 | Windows Management Instrumentation | `Win32_Process.Create` invoked via PowerShell `Invoke-WmiMethod`. WmiPrvSE.exe (PID 5472) spawned cmd.exe (PID 3456). WMI-Activity EID 5857 confirms CIMWin32 provider load. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
