# AGC-011 — Browser Spawns a Script Interpreter

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-011` |
| Category | `02-execution` — Execution |
| MITRE Technique | `T1218.005` System Binary Proxy Execution: Mshta / `T1059.003` Command and Scripting Interpreter: Windows Command Shell |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Immediate — Sysmon EID 1 captures the parent-child chain in real time |
| Time to Triage | 01:30 (from event to parent-child confirmation) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ [AGC-010](../../01-phishing/AGC-010-user-reported-triage/README.md) (Phishing category) · next [AGC-012](../AGC-012-office-spawns-powershell/README.md) ▶ |
| One-line Summary | Browser-class process (mshta.exe) spawns cmd.exe child — classic drive-by or exploit-chain detection pattern. |

## Attacker Perspective

### Tradecraft

**What:** A browser-class process spawns a script interpreter (cmd.exe, powershell.exe, wscript.exe) as a child process. In a real attack, this happens when a drive-by exploit or malicious page triggers code execution through the browser, which then launches a command shell to download payloads, establish persistence, or perform reconnaissance.

**Why at this lifecycle stage:** This is the transition from Initial Access to Execution. The attacker has delivered a malicious page (via phishing link, watering hole, or malvertising), and the browser is now executing attacker-controlled code. The parent-child relationship (browser -> script interpreter) is one of the highest-signal detection patterns in endpoint telemetry because:
1. **Browsers rarely spawn script interpreters legitimately.** Enterprise browsers do not normally launch cmd.exe or powershell.exe as child processes.
2. **Few false positives.** Some browser extensions or enterprise management tools may trigger this pattern, but they are easily enumerated and excluded.
3. **Early in the kill chain.** Catching this pattern stops the attack before the payload downloads or persistence is established.

**Lab simulation:** Since the lab cannot execute a real browser exploit, the simulation uses `mshta.exe` (Microsoft HTML Application Host) — a browser-class LOLBin that legitimately hosts HTML/VBScript content and spawns child processes. mshta.exe is classified under T1218.005 (System Binary Proxy Execution) precisely because it exhibits the same browser-spawns-script pattern attackers exploit. An HTA file containing VBScript invokes `cmd.exe` to write a marker file.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Sysmon running.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 18:28:29 | Create HTA payload | COMPROMISED-HOST-01 | PowerShell writes `agc011.hta` containing VBScript to `C:\Temp\` — simulates a drive-by download |
| 2 | 2026-09-15 18:28:29 | Launch mshta.exe | COMPROMISED-HOST-01 | `mshta.exe C:\Temp\agc011.hta` — browser-class process executes the HTA payload |
| 3 | 2026-09-15 18:28:30 | cmd.exe spawned | COMPROMISED-HOST-01 | `cmd.exe /c echo AGC-011-browser-spawn-test > C:\Windows\Temp\agc011.txt` — script interpreter spawned as child of mshta.exe |
| 4 | 2026-09-15 18:28:30 | Marker file confirmed | COMPROMISED-HOST-01 | `C:\Windows\Temp\agc011.txt` created with expected content |

**Additional execution (vbscript: protocol variant):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 5 | 2026-09-15 18:30:41 | vbscript: protocol | COMPROMISED-HOST-01 | `mshta.exe vbscript:Execute("CreateObject(""Wscript.Shell"").Run ""cmd /c ..."")` — inline VBScript execution variant |

**Cleanup:** HTA file and marker file deleted after evidence collection.

## SOC Perspective

### Detection

**Sysmon telemetry (COMPROMISED-HOST-01):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 18:28:29 | 1 | Process Create | **mshta.exe** (PID 5188) — `"C:\WINDOWS\system32\mshta.exe" C:\Temp\agc011.hta` — Microsoft (R) HTML Application host (browser-class LOLBin) |
| 2026-09-15 18:28:30 | 1 | Process Create | **cmd.exe** (PID 1460) — `"C:\Windows\System32\cmd.exe" /c echo AGC-011-browser-spawn-test > C:\Windows\Temp\agc011.txt` — child of mshta.exe |
| 2026-09-15 18:28:29 | 11 | File Create | `C:\Temp\agc011.hta` — the HTA payload written to disk |
| 2026-09-15 18:30:41 | 1 | Process Create | **mshta.exe** (PID 2932) — `vbscript:Execute(...)` variant — inline script execution without file on disk |

**Key detection signal:** Sysmon EID 1 where `ParentImage` is a browser-class process (`mshta.exe`, `chrome.exe`, `msedge.exe`, `firefox.exe`) and `Image` is a script interpreter (`cmd.exe`, `powershell.exe`, `wscript.exe`, `cscript.exe`).

### Investigation

**Step 1 — Identify the parent-child chain:**
At 18:28:29 UTC, `mshta.exe` (PID 5188) was launched with argument `C:\Temp\agc011.hta`. One second later, `cmd.exe` (PID 1460) was spawned with a command line that writes to `C:\Windows\Temp\`. The timing and command structure confirm mshta.exe spawned cmd.exe via the HTA's embedded VBScript `WScript.Shell.Run`.

**Step 2 — Evaluate the child process action:**
The spawned `cmd.exe` wrote a file to `C:\Windows\Temp\` — a world-writable staging directory commonly used by malware. In a real attack, this stage would typically involve:
- Downloading a second-stage payload (`certutil -urlcache`, `bitsadmin`, `Invoke-WebRequest`)
- Establishing persistence (registry Run key, scheduled task)
- Performing host reconnaissance (`whoami`, `ipconfig`, `net user`)

**Step 3 — Rule out legitimate use:**
mshta.exe executing HTA files with VBScript that spawns cmd.exe is not a legitimate enterprise workflow. The mshta.exe binary is a known LOLBin (Living Off the Land Binary) — it has no legitimate business function in most environments and should be monitored or blocked.

**Step 4 — Scope assessment:**
The vbscript: protocol variant (PID 2932 at 18:30:41) demonstrates a fileless execution path — mshta.exe can execute script directly from a protocol handler without writing an HTA file to disk. This is more evasive because there is no file artifact to scan.

### Report

**Verdict: True Positive** — Confirmed browser-class process spawning script interpreter.

**Confidence: High** — The evidence chain is unambiguous:
1. mshta.exe (browser-class LOLBin) spawned cmd.exe (script interpreter) — Sysmon EID 1 confirms the parent-child relationship
2. The child process wrote to `C:\Windows\Temp\` — a staging pattern
3. No legitimate justification for this process chain in this environment
4. Both file-based (HTA) and fileless (vbscript: protocol) variants demonstrated

**Response recommendation:**
1. **Isolate the host** — the endpoint has executed attacker-controlled code via a browser-class process.
2. **Investigate what the child process did** — file writes, network connections, registry changes, further child processes.
3. **Block mshta.exe** — via AppLocker or Windows Defender Application Control (WDAC) if not required in the environment.
4. **Hunt for similar patterns** — search all endpoints for Sysmon EID 1 events where ParentImage matches browser/mshta executables and Image is a script interpreter.
5. **Detection rule:** Alert on EID 1 where `ParentImage IN (mshta.exe, chrome.exe, msedge.exe, firefox.exe, iexplore.exe)` AND `Image IN (cmd.exe, powershell.exe, wscript.exe, cscript.exe)`.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Defense Evasion (TA0005) | T1218.005 | System Binary Proxy Execution: Mshta | mshta.exe (PID 5188) executed HTA with embedded VBScript; also demonstrated vbscript: protocol handler variant (PID 2932). Both are LOLBin abuse patterns. | High |
| Execution (TA0002) | T1059.003 | Command and Scripting Interpreter: Windows Command Shell | cmd.exe (PID 1460) spawned as child of mshta.exe, executed `echo AGC-011-browser-spawn-test > C:\Windows\Temp\agc011.txt` — script interpreter execution via browser-class parent. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
