# AGC-028 — DLL Search-Order Hijacking

> **Disclosure:** Executed & documented by Claude Code under direction and review by Ali.

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

**What:** The attacker drops a malicious DLL in a directory that sits earlier in the Windows DLL search order than the legitimate DLL. When an application loads a DLL by name with no full path, Windows searches directories in this order:
1. **The directory the application was loaded from** (highest priority — the hijack point)
2. The system directory (`C:\Windows\System32`)
3. The 16-bit system directory
4. The Windows directory
5. The current working directory
6. Directories in the PATH environment variable

Give the DLL the same name as a legitimate system DLL and place it in the application's own directory, and it loads first, running inside the host application.

This provides:
1. **Code execution in a trusted process** — the malicious code runs inside a legitimate application, harder to separate from normal behavior.
2. **Privilege inheritance** — when the host application runs elevated (admin, SYSTEM), the DLL inherits those privileges.
3. **Persistence** — the hijack DLL loads on every application start, surviving reboots.
4. **Defense evasion** — the DLL name matches a real system DLL and loads inside a trusted process, slipping past application allowlisting and basic EDR signatures.

**Why at this lifecycle stage:** With initial access and the ability to write files, the attacker uses DLL hijacking to escalate — if the target app runs elevated — and to persist, without touching system files or the registry.

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

The SwiftOnSecurity Sysmon config does NOT enable EID 7 (Image Loaded) logging. That event is the primary detection source for DLL hijacking: it records which process loaded which DLL from which path. Without it, the DLL load itself is invisible to Sysmon.

The last 100 Sysmon entries hold zero EID 7 events, so the event is filtered out entirely. SwiftOnSecurity configs commonly drop EID 7 because it logs every DLL load by every process, but its absence leaves this technique class in a detection gap.

**Available detection (partial):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 19:37:43 | 11 (Sysmon) | File Create | **RuleName:** `DLL`. **TargetFilename:** `C:\Program Files\VulnApp\version.dll`. **Image:** `powershell.exe` (PID 5428). **User:** `COMPROMISED-01\Administrator`. DLL file created in application directory. |
| 2026-09-15 19:37:43 | 11 (Sysmon) | File Create | **RuleName:** `EXE`. **TargetFilename:** `C:\Program Files\VulnApp\VulnApp.exe`. **Image:** `powershell.exe` (PID 5428). Executable created in same directory as hijack DLL. |
| 2026-09-15 19:37:45 | 1 (Sysmon) | Process Create | **Image:** `C:\Program Files\VulnApp\VulnApp.exe` (PID 1764). **OriginalFileName:** `NOTEPAD.EXE`. **User:** `COMPROMISED-01\Administrator`. **IntegrityLevel:** High. |

**What detection can and cannot tell us:**
- EID 11 confirms a DLL landed at the hijack location (RuleName: DLL flags .dll file creates).
- EID 1 confirms VulnApp.exe ran from the same directory.
- **Missing:** nothing shows whether VulnApp.exe loaded the hijack DLL or the legitimate System32 one. EID 7 would, but it is disabled.

### Investigation

**Step 1 — Identify suspicious DLL placement:**
Sysmon EID 11 (RuleName: DLL) flagged `version.dll` created at `C:\Program Files\VulnApp\`. That name matches a legitimate Windows system DLL, `C:\Windows\System32\version.dll`. A system DLL name showing up in an application directory is a DLL-hijacking indicator.

**Step 2 — Confirm EID 7 status (critical for investigation):**
Sysmon EID 7 (Image Loaded) is DISABLED in the lab. So:
- The path VulnApp.exe loaded `version.dll` from cannot be confirmed.
- The loaded DLL's hash cannot be compared against the System32 version.
- The finding drops from "confirmed hijack" to "high-confidence hijack setup"; the load event went unobserved.

**Step 3 — Cross-reference file creation with application baseline:**
The EID 11 events show `VulnApp.exe` and `version.dll` both created at 19:37:43 UTC by `powershell.exe` (PID 5428) as Administrator. An executable and a system-named DLL appearing together in one directory is a strong lead.

**Step 4 — OriginalFileName analysis:**
Sysmon EID 1 for VulnApp.exe reports OriginalFileName `NOTEPAD.EXE`, so the on-disk binary was renamed. Renaming a system binary and pairing it with a hijack DLL is a known attack pattern.

**Step 5 — DLL search order analysis:**
For `VulnApp.exe` located at `C:\Program Files\VulnApp\`:
1. `C:\Program Files\VulnApp\version.dll` — HIJACK LOCATION (found first)
2. `C:\Windows\System32\version.dll` — legitimate (never reached)

### Report

**Verdict: True Positive** — The attacker set up a DLL search-order hijack by placing `version.dll` in the application directory. Sysmon EID 11 confirmed the DLL creation at the hijack location, and EID 1 confirmed the host application ran from the same directory.

**Confidence: High** — Despite EID 7 being disabled:
- Sysmon EID 11 (RuleName: DLL) confirmed `version.dll` created at `C:\Program Files\VulnApp\` by PowerShell running as Administrator.
- The DLL name matches a known Windows system DLL (`C:\Windows\System32\version.dll`).
- VulnApp.exe (OriginalFileName: NOTEPAD.EXE) executed from the same directory.
- The DLL search order guarantees the local copy is loaded before the System32 copy.
- EID 7 absence prevents confirming the actual load event, but the setup evidence is conclusive.

**Critical finding — EID 7 detection gap:**
Sysmon EID 7 (Image Loaded) is disabled in the SwiftOnSecurity configuration, a detection gap that spans ALL DLL-based attacks:
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
3. **Application hardening:** Use fully-qualified DLL paths in code, or call `SetDllDirectory("")` to drop the current directory from the search path.
4. **Fleet-wide audit:** Scan application directories for DLL files that share a name with a System32 DLL.
5. **Investigate the OriginalFileName mismatch:** VulnApp.exe is really NOTEPAD.EXE — find out why a renamed system binary landed in Program Files.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Privilege Escalation (TA0004) | T1574.001 | Hijack Execution Flow: DLL Search Order Hijacking | Sysmon EID 11 (RuleName: DLL): `version.dll` placed at `C:\Program Files\VulnApp\` (hijack location precedes System32 in search order). EID 1: host app VulnApp.exe (OriginalFileName: NOTEPAD.EXE) ran from same directory. **EID 7 disabled** — load event unobserved but setup is conclusive. | High |
| Persistence (TA0003) | T1574.001 | Hijack Execution Flow: DLL Search Order Hijacking | Same evidence. DLL hijack persists across application restarts — the hijack DLL loads every time the host application starts. | High |
| Defense Evasion (TA0005) | T1574.001 | Hijack Execution Flow: DLL Search Order Hijacking | Same evidence. Malicious code executes within a trusted application process, evading process-based detection and application whitelisting. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
