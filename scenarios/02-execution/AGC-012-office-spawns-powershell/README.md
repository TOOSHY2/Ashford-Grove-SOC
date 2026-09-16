# AGC-012 — Office Application Spawns PowerShell

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-012` |
| Category | `02-execution` — Execution |
| MITRE Technique | `T1059.001` Command and Scripting Interpreter: PowerShell / `T1204.002` User Execution: Malicious File |
| Verdict | True Positive |
| Confidence | Critical |
| Time to Detect | Immediate — Sysmon EID 1 captures parent-child chain |
| Time to Triage | 01:00 (from event to full command-line analysis) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ [AGC-011](../AGC-011-browser-spawns-script/README.md) · next [AGC-013](../AGC-013-encoded-powershell/README.md) ▶ |
| One-line Summary | Office application (WINWORD.EXE) spawns powershell.exe child — macro-driven code execution pattern with zero legitimate justification. |

## Attacker Perspective

### Tradecraft

**What:** A Microsoft Office application (Word, Excel, PowerPoint) spawns a script interpreter (PowerShell, cmd.exe, wscript.exe) as a child process. This is the classic macro-driven execution chain: user opens a malicious document, a VBA macro runs automatically (or after "Enable Content"), and the macro launches PowerShell to download and execute a second-stage payload.

**Why at this lifecycle stage:** This technique bridges Initial Access (T1566.001 — spearphishing attachment) and Execution (T1059.001 — PowerShell). The macro provides the code execution context; PowerShell provides the download-and-execute capability. The parent-child relationship (Office -> PowerShell) is one of the cleanest detection signals in the entire MITRE catalog because:
1. **No legitimate use case.** Office applications do not need to spawn PowerShell in any standard business workflow. There is no enterprise-grade reason for winword.exe to create a powershell.exe child.
2. **Captures the transition.** This is the exact moment the attacker gains code execution on the endpoint — before this, the attack is just a document; after this, it's arbitrary code execution.
3. **Complementary to AGC-007.** AGC-007 documented the macro lure delivery; AGC-012 documents the execution-side detection of the same pattern.

**Lab limitation:** Microsoft Office is not installed on COMPROMISED-HOST-01. The simulation uses a renamed-binary technique (cmd.exe copied as WINWORD.EXE) to produce the exact Sysmon parent-child artifacts that detection rules match. This is a standard red team approach for testing detection rules without requiring Office installation. Sysmon records both `Image` (path-based, shows WINWORD.EXE) and `OriginalFileName` (PE header, shows Cmd.Exe) — the mismatch is an additional detection signal (T1036.005 Masquerading: Match Legitimate Name or Location).

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Sysmon running.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 18:35:06 | Create simulated Office binary | COMPROMISED-HOST-01 | `copy C:\Windows\System32\cmd.exe C:\Temp\WINWORD.EXE` — renamed binary for detection testing |
| 2 | 2026-09-15 18:35:06 | Office -> PowerShell chain | COMPROMISED-HOST-01 | `C:\Temp\WINWORD.EXE /c powershell.exe -Command "Write-Output 'AGC-012-office-spawn-test' ..."` |
| 3 | 2026-09-15 18:35:06 | PowerShell writes marker | COMPROMISED-HOST-01 | `powershell.exe` (PID 3184) writes `C:\Windows\Temp\agc012.txt` |
| 4 | 2026-09-15 18:35:08 | Marker confirmed | COMPROMISED-HOST-01 | Content: `AGC-012-office-spawn-test` |

**Cleanup:** WINWORD.EXE and marker file deleted after evidence collection.

## SOC Perspective

### Detection

**Sysmon telemetry (COMPROMISED-HOST-01):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 18:35:06 | 1 | Process Create | **WINWORD.EXE** (PID 1116) — `Image: C:\Temp\WINWORD.EXE`, `OriginalFileName: Cmd.Exe`, `CommandLine: "C:\Temp\WINWORD.EXE" /c powershell.exe -Command "..."` — simulated Office process |
| 2026-09-15 18:35:06 | 1 | Process Create | **powershell.exe** (PID 3184) — `Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `CommandLine: powershell.exe -Command "Write-Output 'AGC-012-office-spawn-test' \| Out-File C:\Windows\Temp\agc012.txt"` — child of WINWORD.EXE |

**Key detection signals:**
1. **Parent-child pattern:** `ParentImage` = Office application, `Image` = script interpreter. This is the primary detection rule.
2. **OriginalFileName mismatch:** `Image` path says WINWORD.EXE but `OriginalFileName` says Cmd.Exe — indicates binary masquerading (T1036.005). In a real attack with genuine Office, these would match.
3. **Command-line content:** The PowerShell command line reveals the payload action (file write to a staging directory).

### Investigation

**Step 1 — Confirm the parent-child chain:**
WINWORD.EXE (PID 1116) at 18:35:06 UTC spawned powershell.exe (PID 3184). The Sysmon EID 1 events are timestamped within the same second, confirming the direct parent-child relationship.

**Step 2 — Analyze the child's command line:**
`powershell.exe -Command "Write-Output 'AGC-012-office-spawn-test' | Out-File C:\Windows\Temp\agc012.txt -Encoding utf8"`

In this simulation, the payload is a benign marker write. In a real attack, the PowerShell command line would typically contain:
- `Invoke-WebRequest` / `Net.WebClient` — downloading second-stage payload
- `-EncodedCommand` / `-e` — Base64-encoded payload to evade command-line logging
- `IEX` (Invoke-Expression) — executing downloaded code in memory

**Step 3 — Cross-reference with AGC-007:**
AGC-007 documented a macro lure document (`Signed-Contract-2026.docm`) that wrote a marker file. AGC-012 documents the detection perspective of the same pattern — the Sysmon EID 1 event that fires when the macro spawns a script interpreter. In a real incident, the SOC analyst would:
1. Find the EID 1 event (AGC-012 pattern).
2. Correlate with the EID 11 event for the source document (AGC-007 pattern).
3. Retrieve and quarantine the malicious document.

**Step 4 — OriginalFileName detection bonus:**
Sysmon records `OriginalFileName: Cmd.Exe` in the PE header for the WINWORD.EXE process. This mismatch (Image path vs OriginalFileName) is an independent detection signal for binary masquerading. Detection engineers should alert on `Image` path containing a known application name where `OriginalFileName` does not match.

### Report

**Verdict: True Positive** — Confirmed Office-application-spawns-PowerShell execution chain.

**Confidence: Critical** — This parent-child combination has effectively zero legitimate justification in a corporate Windows environment. The detection signal is unambiguous:
1. WINWORD.EXE spawned powershell.exe — Sysmon EID 1 confirms PIDs and timing
2. PowerShell executed a payload command (file write to staging directory)
3. No enterprise workflow requires Office to spawn PowerShell
4. Complementary detection to AGC-007 macro delivery

**Response recommendation:**
1. **Isolate the host immediately** — Office-spawns-PowerShell is an active breach indicator.
2. **Quarantine the source document** — retrieve the .docm/.xlsm that triggered the macro from the user's recent files / email attachments.
3. **Extract the PowerShell command line** — the full command reveals the attacker's payload (download URL, C2 address, persistence mechanism).
4. **Block the payload destination** — if the command downloads from a URL, block it at the firewall/proxy.
5. **Hunt for scope** — search all endpoints for the same parent-child pattern in the same time window (campaign-wide execution).
6. **Detection rule:** Alert on Sysmon EID 1 where `ParentImage IN (winword.exe, excel.exe, powerpnt.exe, outlook.exe)` AND `Image IN (powershell.exe, cmd.exe, wscript.exe, cscript.exe, mshta.exe)`.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Execution (TA0002) | T1059.001 | Command and Scripting Interpreter: PowerShell | powershell.exe (PID 3184) spawned as child of WINWORD.EXE (PID 1116). Command: `Write-Output 'AGC-012-office-spawn-test' \| Out-File C:\Windows\Temp\agc012.txt`. Marker file confirmed. | Critical |
| Execution (TA0002) | T1204.002 | User Execution: Malicious File | Triggering mechanism: user opens a macro-enabled document; the macro executes PowerShell. Simulated via renamed-binary technique (Office not installed on lab VM). | Critical |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
