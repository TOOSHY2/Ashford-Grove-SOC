# AGC-007 — Macro Lure Document

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-007` |
| Category | `01-phishing` — Phishing & Initial Access |
| MITRE Technique | `T1566.001` Phishing: Spearphishing Attachment (macro) |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | N/A — no automated Wazuh alert for macro-delivered file writes; Sysmon EID 11 captures the file creation events |
| Time to Triage | 03:00 (from .docm delivery to marker-file confirmation) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ AGC-006 · next AGC-008 ▶ |
| One-line Summary | Macro-enabled Word document (.docm) delivered as phishing attachment executes VBA code on "Enable Content," writing a marker file to the system temp directory. |

## Attacker Perspective

### Tradecraft

**What:** A `.docm` (macro-enabled Word document) is delivered as an email attachment with a social-engineering pretext ("signed contract," "invoice"). When the victim opens the document and clicks "Enable Content" (bypassing the default macro security prompt), the embedded VBA `AutoOpen()` macro executes. In this safe-lab scenario, the macro writes a marker file to `C:\Windows\Temp\macro_marker.txt`. In a real attack, this stage would chain to `cmd.exe` or `powershell.exe` to download and execute a second-stage payload.

**Why at this lifecycle stage:** Macro-enabled documents remain one of the most common initial access vectors despite years of mitigation efforts. The technique works because: (1) users trust document formats (.doc, .docm, .xlsx) more than executables, (2) the "Enable Content" prompt creates a false sense of security — users believe they are enabling editing, not running code, (3) VBA macros execute in the context of the Office process, inheriting its network access and local file permissions.

**Where in this lab's tooling:**
- **Endpoint (Sysmon):** **EID 11 (File Create)** is the primary detection — captures both the `.docm` file arriving in Downloads and the macro writing to `C:\Windows\Temp\`. **EID 1 (Process Create)** would capture any child processes spawned by the macro (e.g., `cmd.exe`, `powershell.exe`) — in this scenario, the macro is intentionally limited to a file write, so no child process is spawned.
- **Wazuh:** No rule specifically correlates Office process file writes to system temp directories. Standard logon events only.
- **Key gap:** An Office application writing to `C:\Windows\Temp\` (or any system directory outside the user's Documents folder) is anomalous and should be alerted on.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Wazuh agent Active, Sysmon running.
- Scenario is endpoint-local only — no external attacker infrastructure needed.

**Safe macro payload (what `AutoOpen()` would contain):**
```vba
Sub AutoOpen()
    Open "C:\Windows\Temp\macro_marker.txt" For Output As #1
    Print #1, "AGC-007 macro executed at " & Now()
    Close #1
End Sub
```
This is intentionally limited to a marker-file write for lab safety. A real-world macro would typically chain to `cmd.exe /c powershell -enc ...` or download a second-stage payload.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 17:44:49 | Deliver .docm to Downloads | COMPROMISED-HOST-01 | `Signed-Contract-2026.docm` written to `C:\Users\michael.chen\Downloads\` |
| 2 | 2026-09-15 17:44:49 | Simulate macro execution | COMPROMISED-HOST-01 | Marker file written to `C:\Windows\Temp\macro_marker.txt` |
| 3 | 2026-09-15 17:44:49 | Verify marker | COMPROMISED-HOST-01 | File confirmed: "AGC-007 macro executed at 2026-09-15 17:44:49 UTC" |

**Cleanup:** `.docm` and marker file left as evidence artifacts.

## SOC Perspective

### Detection

**Automated alerts:** No macro-specific alert. Wazuh logged standard logon/privilege events:
- 17:44:43 — Rule 60118 (L3): Windows Workstation Logon Success
- 17:44:43 — Rule 67028 (L3): Special privileges assigned to new logon
- 17:44:47 — Rule 60118 (L3): Windows Workstation Logon Success

**Sysmon telemetry (COMPROMISED-HOST-01):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 17:44:49 | 11 | File Create | **RuleName: Downloads** — `powershell.exe` wrote `C:\Users\michael.chen\Downloads\Signed-Contract-2026.docm` |
| 2026-09-15 17:44:49 | 1 | Process Create | `powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc007-sim.ps1`, parent: `VBoxService.exe` |

**Key detection signal:** Sysmon EID 11 capturing a `.docm` file write to the user's Downloads folder is a moderate indicator on its own (users do receive legitimate macro documents). The **high-fidelity signal** is EID 11 showing an Office process (`winword.exe`, `excel.exe`) writing a file to a system temp directory (`C:\Windows\Temp\`) rather than the user's Documents folder — this is characteristic of macro payload behavior. In this simulation, `powershell.exe` performed both writes; in a real attack, the Downloads write would come from the email client/browser and the temp write from `winword.exe`.

### Investigation

**Step 1 — .docm delivery to Downloads:**
Sysmon EID 11 recorded `Signed-Contract-2026.docm` written to `C:\Users\michael.chen\Downloads\` at 17:44:49 UTC with `RuleName: Downloads`. The filename uses a social-engineering pretext ("Signed-Contract") designed to create urgency and trust.

**Step 2 — Macro execution evidence (marker file):**
The macro wrote `C:\Windows\Temp\macro_marker.txt` at 17:44:49 UTC. An Office application writing to `C:\Windows\Temp\` is anomalous — normal document operations save to the user's Documents, Desktop, or AppData directories. System temp writes indicate the macro is performing actions beyond normal document editing.

**Step 3 — Scope assessment (intentional safe stop):**
In a real attack, the `AutoOpen()` macro would chain to a second-stage execution: spawning `cmd.exe` or `powershell.exe` as a child process of `winword.exe`, downloading a remote payload, or establishing C2. **This scenario intentionally stops at the marker-file write for lab safety.** The investigation would normally continue by examining Sysmon EID 1 for child processes of `winword.exe` and EID 3 for outbound network connections from the Office process.

**Step 4 — Cross-reference with prior scenarios:**
This is the same campaign's eighth variation — the attacker has now used: spoofed display names (AGC-001), lookalike domains (AGC-002), credential-harvesting links (AGC-003), QR codes (AGC-004), URL shorteners (AGC-005), HTML attachments (AGC-006), and now macro-enabled documents (AGC-007). Each scenario tests a different delivery vector for the same ultimate goal: gaining initial access to the victim's endpoint.

### Report

**Verdict: True Positive** — Confirmed phishing delivery via macro-enabled document attachment.

**Confidence: High** — The evidence chain is clear:
1. `.docm` file delivered to user's Downloads folder (Sysmon EID 11, RuleName: Downloads)
2. Macro execution writes to system temp directory (`C:\Windows\Temp\macro_marker.txt`)
3. Office writing to system temp (not user Documents) is anomalous and characteristic of malicious macros
4. Social-engineering filename ("Signed-Contract-2026") designed to compel the victim to enable macros

**Response recommendation:**
1. **Quarantine the .docm** and search for copies across other users' mailboxes.
2. **GPO enforcement:** Deploy "Disable all macros without notification" via Group Policy for users who do not need VBA. For users who do, restrict to digitally signed macros only.
3. **Detection engineering:** Create a Wazuh rule correlating Sysmon EID 11 where `Image` contains `winword.exe` or `excel.exe` and `TargetFilename` matches `C:\Windows\Temp\*` or `C:\Users\*\AppData\Local\Temp\*`.
4. **ASR rules:** Enable Windows Defender Attack Surface Reduction rule "Block Office applications from creating child processes" where supported.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Initial Access (TA0001) | T1566.001 | Phishing: Spearphishing Attachment | `.docm` attachment `Signed-Contract-2026.docm` delivered to Downloads; macro writes marker to `C:\Windows\Temp\macro_marker.txt`; Sysmon EID 11 file creates (RuleName: Downloads + system temp write) | High |

## Evidence

Screenshots: to be added manually by the analyst.
