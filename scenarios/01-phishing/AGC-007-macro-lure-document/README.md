# AGC-007 — Macro Lure Document

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

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
| Chain | ◀ [AGC-006](../AGC-006-html-attachment-redirect/README.md) · next [AGC-008](../AGC-008-password-reset-lure/README.md) ▶ |
| One-line Summary | Macro-enabled Word document (.docm) delivered as phishing attachment executes VBA code on "Enable Content," writing a marker file to the system temp directory. |

## Attacker Perspective

### Tradecraft

**What:** A macro-enabled Word document (`.docm`) arrives as an attachment under a pretext ("signed contract," "invoice"). The victim opens it, clicks "Enable Content" past the macro warning, and the embedded VBA `AutoOpen()` runs. In the lab the macro only writes a marker to `C:\Windows\Temp\macro_marker.txt`; a real one would chain to `cmd.exe` or `powershell.exe` to fetch and run a second stage.

**Why at this lifecycle stage:** Macro documents still work as initial access because: (1) users trust document formats (.doc, .docm, .xlsx) more than executables, (2) "Enable Content" reads as enabling editing, not running code, and (3) VBA runs inside the Office process and inherits its network access and file permissions.

**Where in this lab's tooling:**
- **Endpoint (Sysmon):** **Sysmon EID 11 (File Create)** is the primary detection: it captures the `.docm` arriving in Downloads and the macro's write to `C:\Windows\Temp\`. **EID 1 (Process Create)** would capture any child the macro spawned (`cmd.exe`, `powershell.exe`); this macro stops at a file write, so there is none.
- **Wazuh:** No rule ties an Office process to a write in a system temp directory. Standard logon events only.
- **Key gap:** An Office application writing to `C:\Windows\Temp\`, or any system directory outside the user's profile, is abnormal and deserves an alert.

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
Limited to a marker-file write for lab safety. A real macro would chain to `cmd.exe /c powershell -enc ...` or pull a second-stage payload.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 17:44:49 | Deliver .docm to Downloads | COMPROMISED-HOST-01 | `Signed-Contract-2026.docm` written to `C:\Users\michael.chen\Downloads\` |
| 2 | 2026-09-15 17:44:49 | Simulate macro execution | COMPROMISED-HOST-01 | Marker file written to `C:\Windows\Temp\macro_marker.txt` |
| 3 | 2026-09-15 17:44:49 | Verify marker | COMPROMISED-HOST-01 | File confirmed: "AGC-007 macro executed at 2026-09-15 17:44:49 UTC" |

**Cleanup:** `.docm` and marker file left as evidence artifacts.

## SOC Perspective

### Detection

**Automated alerts:** No macro-specific alert fired. Wazuh logged only the standard logon and privilege events:
- 17:44:43 — Wazuh rule 60118 (L3): Windows Workstation Logon Success
- 17:44:43 — Wazuh rule 67028 (L3): Special privileges assigned to new logon
- 17:44:47 — Wazuh rule 60118 (L3): Windows Workstation Logon Success

**Sysmon telemetry (COMPROMISED-HOST-01):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 17:44:49 | 11 | File Create | **RuleName: Downloads** — `powershell.exe` wrote `C:\Users\michael.chen\Downloads\Signed-Contract-2026.docm` |
| 2026-09-15 17:44:49 | 1 | Process Create | `powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc007-sim.ps1`, parent: `VBoxService.exe` |

**Key detection signal:** Sysmon EID 11 showing a `.docm` write to Downloads is a moderate indicator by itself — users do receive legitimate macro documents. The **high-fidelity signal** is EID 11 showing an Office process (`winword.exe`, `excel.exe`) writing to `C:\Windows\Temp\` instead of the user's Documents folder; that is what a macro payload does. In this simulation `powershell.exe` performed both writes; in a real attack the Downloads write would come from the mail client or browser and the temp write from `winword.exe`.

### Investigation

**Step 1 — .docm delivery to Downloads:**
Sysmon EID 11 captured `Signed-Contract-2026.docm` written to `C:\Users\michael.chen\Downloads\` at 17:44:49 UTC with `RuleName: Downloads`. The filename ("Signed-Contract") is the pretext — it promises something the user expects and wants to open.

**Step 2 — Macro execution evidence (marker file):**
The macro wrote `C:\Windows\Temp\macro_marker.txt` at 17:44:49 UTC. Normal document work saves to Documents, Desktop, or AppData; an Office application writing to `C:\Windows\Temp\` is doing something other than editing.

**Step 3 — Scope assessment (intentional safe stop):**
A real `AutoOpen()` would go on to spawn `cmd.exe` or `powershell.exe` under `winword.exe`, download a payload, or set up C2. **This scenario stops at the marker-file write for lab safety.** The next investigative step would be Sysmon EID 1 for children of `winword.exe` and EID 3 for outbound connections from the Office process.

**Step 4 — Cross-reference with prior scenarios:**
This is the same campaign's eighth variation — the attacker has now used spoofed display names (AGC-001), lookalike domains (AGC-002), credential-harvesting links (AGC-003), QR codes (AGC-004), URL shorteners (AGC-005), HTML attachments (AGC-006), and macro documents (AGC-007). Each one is a different delivery vector for the same goal: a foothold on the victim's endpoint.

### Report

**Verdict: True Positive** — Confirmed phishing delivery via macro-enabled document attachment.

**Confidence: High** — Four points carry the verdict:
1. `.docm` file delivered to user's Downloads folder (Sysmon EID 11, RuleName: Downloads)
2. Macro execution writes to system temp directory (`C:\Windows\Temp\macro_marker.txt`)
3. Office writing to system temp rather than user Documents is what a malicious macro does, not what a document edit does
4. Filename ("Signed-Contract-2026") chosen to push the victim into enabling macros

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

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
