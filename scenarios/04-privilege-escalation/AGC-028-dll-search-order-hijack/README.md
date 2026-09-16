# AGC-028 — DLL Search-Order Hijacking

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-028` |
| Category | `04-privilege-escalation` — Privilege Escalation |
| MITRE Technique | `T1574.001` Hijack Execution Flow: DLL Search Order Hijacking |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Partial — Sysmon EID 11 flags DLL file creation at hijack location; **EID 7 (Image Loaded) is DISABLED** in this environment, creating a detection gap for runtime DLL loading |
| Time to Triage | 03:00 (requires cross-referencing file creation location against legitimate DLL paths and application baseline) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ [AGC-027](../AGC-027-service-misconfig/README.md) · next [AGC-029](../AGC-029-suspicious-sudo-linux/README.md) ▶ |
| One-line Summary | DLL placed at application directory to hijack `version.dll` search order. Sysmon EID 11 (RuleName: DLL) captured file placement. **Critical detection gap:** Sysmon EID 7 (Image Loaded) is disabled in SwiftOnSecurity config, meaning runtime DLL loading paths are invisible. |

## Attacker Perspective

### Tradecraft

**What:** The attacker places a malicious DLL in a directory that appears earlier in the Windows DLL search order than the legitimate DLL location. When an application loads a DLL by name without specifying the full path, Windows searches directories in this order:
1. **The directory the application was loaded from** (highest priority — the hijack point)
2. The system directory (`C:\Windows\System32`)
3. The 16-bit system directory
4. The Windows directory
5. The current working directory
6. Directories in the PATH environment variable

By placing a DLL with the same name as a legitimate system DLL in the application's own directory, the attacker's DLL is loaded first, running in the context of the host application.

This provides:
1. **Code execution in a trusted process** — the malicious code runs inside a legitimate application, making it harder to distinguish from normal behavior.
2. **Privilege inheritance** — if the host application runs with elevated privileges (admin, SYSTEM), the DLL inherits those privileges.
3. **Persistence** — the hijack DLL is loaded every time the application starts, surviving reboots.
4. **Defense evasion** — the DLL name matches a legitimate system DLL, and the loading happens inside a trusted process, evading application whitelisting and basic EDR signatures.

**Why at this lifecycle stage:** After gaining initial access and the ability to write files, the attacker uses DLL hijacking to escalate privileges (if the target app runs elevated) and establish persistence without modifying system files or registry.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 19:37:43 | Create app directory | COMPROMISED-HOST-01 | Created `C:\Program Files\VulnApp\` |
| 2 | 2026-09-15 19:37:43 | Place hijack DLL | COMPROMISED-HOST-01 | Copied `version.dll` (55,192 bytes) from System32 to `C:\Program Files\VulnApp\version.dll` |
| 3 | 2026-09-15 19:37:43 | Deploy vulnerable app | COMPROMISED-HOST-01 | Copied `notepad.exe` as `VulnApp.exe` (loads `version.dll` by name without full path) |
| 4 | 2026-09-15 19:37:45 | Execute | COMPROMISED-HOST-01 | Launched `VulnApp.exe` (PID 1764) — loads `version.dll` from its own directory first (hijack path) instead of System32 |
| 5 | 2026-09-15 19:38:16 | Cleanup | COMPROMISED-HOST-01 | Entire VulnApp directory removed |

**Cleanup:** VulnApp directory and all contents removed.

## SOC Perspective

### Detection

**CRITICAL DETECTION GAP: Sysmon EID 7 (Image Loaded) is DISABLED.**

The SwiftOnSecurity Sysmon config does NOT enable EID 7 (Image Loaded) logging. This event is the primary detection source for DLL hijacking — it records which process loaded which DLL from which path. Without it, the actual DLL loading is invisible to Sysmon.

Zero EID 7 events were found in the last 100 Sysmon entries, confirming the event is filtered out entirely. This is common in SwiftOnSecurity configs because EID 7 generates extremely high volume (every DLL load by every process), but its absence creates a blind spot for this technique class.

**Available detection (partial):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 19:37:43 | 11 (Sysmon) | File Create | **RuleName:** `DLL`. **TargetFilename:** `C:\Program Files\VulnApp\version.dll`. **Image:** `powershell.exe` (PID 5428). **User:** `COMPROMISED-01\Administrator`. DLL file created in application directory. |
| 2026-09-15 19:37:43 | 11 (Sysmon) | File Create | **RuleName:** `EXE`. **TargetFilename:** `C:\Program Files\VulnApp\VulnApp.exe`. **Image:** `powershell.exe` (PID 5428). Executable created in same directory as hijack DLL. |
| 2026-09-15 19:37:45 | 1 (Sysmon) | Process Create | **Image:** `C:\Program Files\VulnApp\VulnApp.exe` (PID 1764). **OriginalFileName:** `NOTEPAD.EXE`. **User:** `COMPROMISED-01\Administrator`. **IntegrityLevel:** High. |

**What detection can and cannot tell us:**
- EID 11 confirms a DLL was placed at the hijack location (RuleName: DLL specifically flags .dll file creates).
- EID 1 confirms VulnApp.exe executed from the same directory.
- **Missing:** No evidence that VulnApp.exe actually LOADED the hijack DLL vs the legitimate System32 one. EID 7 would provide this, but it is disabled.

### Investigation

**Step 1 — Identify suspicious DLL placement:**
Sysmon EID 11 (RuleName: DLL) flagged `version.dll` being created at `C:\Program Files\VulnApp\`. This DLL name matches a legitimate Windows system DLL (`C:\Windows\System32\version.dll`). A system DLL name appearing in an application directory is a DLL hijacking indicator.

**Step 2 — Confirm EID 7 status (critical for investigation):**
Sysmon EID 7 (Image Loaded) is DISABLED in this environment. This means:
- We cannot confirm which path VulnApp.exe loaded `version.dll` from.
- We cannot compare the loaded DLL's hash against the legitimate System32 version.
- The detection gap transforms our finding from "confirmed hijack" to "high-confidence indicators of hijack setup" — the actual load event is unobserved.

**Step 3 — Cross-reference file creation with application baseline:**
The EID 11 events show both `VulnApp.exe` and `version.dll` were created at 19:37:43 UTC by `powershell.exe` (PID 5428) running as Administrator. The simultaneous creation of an executable and a system-named DLL in the same directory is highly suspicious.

**Step 4 — OriginalFileName analysis:**
Sysmon EID 1 for VulnApp.exe shows OriginalFileName: `NOTEPAD.EXE`. This means the executable on disk has been renamed from its original name. Renaming system binaries and placing them alongside hijack DLLs is a common attack pattern.

**Step 5 — DLL search order analysis:**
For `VulnApp.exe` located at `C:\Program Files\VulnApp\`:
1. `C:\Program Files\VulnApp\version.dll` — HIJACK LOCATION (found first)
2. `C:\Windows\System32\version.dll` — legitimate (never reached)

### Report

**Verdict: True Positive** — A DLL search-order hijack was set up by placing `version.dll` in the application directory. Sysmon EID 11 confirmed the DLL file creation at the hijack location, and EID 1 confirmed the host application executed from the same directory.

**Confidence: High** — Despite EID 7 being disabled:
- Sysmon EID 11 (RuleName: DLL) confirmed `version.dll` created at `C:\Program Files\VulnApp\` by PowerShell running as Administrator.
- The DLL name matches a known Windows system DLL (`C:\Windows\System32\version.dll`).
- VulnApp.exe (OriginalFileName: NOTEPAD.EXE) executed from the same directory.
- The DLL search order guarantees the local copy is loaded before the System32 copy.
- EID 7 absence prevents confirming the actual load event, but the setup evidence is conclusive.

**Critical finding — EID 7 detection gap:**
Sysmon EID 7 (Image Loaded) is disabled in the SwiftOnSecurity configuration. This creates a blind spot for ALL DLL-based attacks:
- DLL search-order hijacking (this scenario)
- DLL side-loading (T1574.002)
- DLL injection (T1055.001)
- Phantom DLL hijacking

**Response recommendation:**
1. **Delete the hijack DLL** and any associated files from the application directory.
2. **Enable Sysmon EID 7** with targeted filtering for high-value applications. Full EID 7 logging is volume-prohibitive, but selective monitoring is feasible:
   ```xml
   <ImageLoad onmatch="include">
     <ImageLoaded condition="end with">version.dll</ImageLoaded>
     <ImageLoaded condition="end with">winhttp.dll</ImageLoaded>
   </ImageLoad>
   ```
3. **Application hardening:** Use fully-qualified DLL paths in application code, or set `SetDllDirectory("")` to remove the current directory from the search path.
4. **Fleet-wide audit:** Scan application directories for DLL files that share names with System32 DLLs.
5. **Investigate the OriginalFileName mismatch:** VulnApp.exe is actually NOTEPAD.EXE — investigate why a renamed system binary was placed in Program Files.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Privilege Escalation (TA0004) | T1574.001 | Hijack Execution Flow: DLL Search Order Hijacking | Sysmon EID 11 (RuleName: DLL): `version.dll` placed at `C:\Program Files\VulnApp\` (hijack location precedes System32 in search order). EID 1: host app VulnApp.exe (OriginalFileName: NOTEPAD.EXE) ran from same directory. **EID 7 disabled** — load event unobserved but setup is conclusive. | High |
| Persistence (TA0003) | T1574.001 | Hijack Execution Flow: DLL Search Order Hijacking | Same evidence. DLL hijack persists across application restarts — the hijack DLL loads every time the host application starts. | High |
| Defense Evasion (TA0005) | T1574.001 | Hijack Execution Flow: DLL Search Order Hijacking | Same evidence. Malicious code executes within a trusted application process, evading process-based detection and application whitelisting. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
