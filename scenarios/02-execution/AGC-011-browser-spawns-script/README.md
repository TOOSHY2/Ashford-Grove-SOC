# AGC-011 — Browser Spawns a Script Interpreter

> **Disclosure:** Executed & documented by Claude Code under direction and review by Ali.

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

**What:** A browser-class process spawns a script interpreter (cmd.exe, powershell.exe, wscript.exe) as a child process. In a real attack a drive-by exploit or malicious page gets code execution inside the browser, and the browser then launches a command shell to download payloads, establish persistence, or run reconnaissance.

**Why at this lifecycle stage:** This is the transition from Initial Access to Execution. The attacker has delivered a malicious page (phishing link, watering hole, or malvertising), and the browser is now running attacker-controlled code. The parent-child pair (browser -> script interpreter) is one of the highest-signal patterns in endpoint telemetry because:
1. **Browsers rarely spawn script interpreters legitimately.** Enterprise browsers do not normally launch cmd.exe or powershell.exe as child processes.
2. **Few false positives.** Some browser extensions and management agents produce this chain, but they are few enough to enumerate and exclude.
3. **Early in the kill chain.** Catching the chain here stops the attack before the payload downloads or persistence lands.

**Lab simulation:** The lab cannot run a real browser exploit, so the simulation uses `mshta.exe` (Microsoft HTML Application Host), a browser-class LOLBin that hosts HTML/VBScript and spawns child processes. ATT&CK files mshta.exe under T1218.005 (System Binary Proxy Execution) because it produces the same browser-spawns-script chain. Here an HTA file containing VBScript calls `cmd.exe` to write a marker file.

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
At 18:28:29 UTC Sysmon logged `mshta.exe` (PID 5188) starting with argument `C:\Temp\agc011.hta`. One second later it logged `cmd.exe` (PID 1460) with a command line that writes to `C:\Windows\Temp\`. The one-second gap and the command line match the HTA's embedded VBScript `WScript.Shell.Run` call, so mshta.exe is the parent.

**Step 2 — Evaluate the child process action:**
The child `cmd.exe` wrote a file to `C:\Windows\Temp\`, a world-writable directory malware often uses for staging. In a real attack the same child would typically be:
- Downloading a second-stage payload (`certutil -urlcache`, `bitsadmin`, `Invoke-WebRequest`)
- Establishing persistence (registry Run key, scheduled task)
- Performing host reconnaissance (`whoami`, `ipconfig`, `net user`)

**Step 3 — Rule out legitimate use:**
An HTA whose VBScript spawns cmd.exe is not a legitimate enterprise workflow. mshta.exe is a known LOLBin (Living Off the Land Binary) with no business use in most environments, so it belongs on a monitor-or-block list.

**Step 4 — Scope assessment:**
The vbscript: protocol variant (PID 2932 at 18:30:41) shows the fileless path: mshta.exe runs the script straight from the protocol handler, and no HTA file touches disk. That leaves nothing for a file scanner to catch; the Sysmon EID 1 command line is the only record.

### Report

**Verdict: True Positive** — Sysmon EID 1 ties cmd.exe (PID 1460) to mshta.exe (PID 5188) as its parent.

**Confidence: High** — The evidence chain is unambiguous:
1. mshta.exe (browser-class LOLBin) spawned cmd.exe (script interpreter) — Sysmon EID 1 records the parent-child link
2. The child process wrote to `C:\Windows\Temp\` — a staging pattern
3. Nothing in the lab legitimately produces this process chain
4. Both the file-based (HTA) and fileless (vbscript: protocol) variants ran and were captured

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
