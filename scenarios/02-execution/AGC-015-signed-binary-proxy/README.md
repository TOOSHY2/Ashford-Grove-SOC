# AGC-015 — Signed Binary Proxy Execution (rundll32)

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-015` |
| Category | `02-execution` — Execution |
| MITRE Technique | `T1218.011` Signed Binary Proxy Execution: Rundll32 |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Immediate — Sysmon EID 1 captures rundll32.exe process creation with full CommandLine |
| Time to Triage | 01:30 (from alert to CommandLine content analysis confirming abuse pattern) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ AGC-014 · next AGC-016 ▶ |
| One-line Summary | rundll32.exe invoked with `javascript:` protocol handler to proxy-execute code through a Microsoft-signed binary, bypassing application whitelisting. |

## Attacker Perspective

### Tradecraft

**What:** The attacker uses `rundll32.exe` — a legitimate, Microsoft-signed system binary — to execute arbitrary code via the `javascript:` protocol handler. The command `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication "` loads `mshtml.dll` (the Trident HTML rendering engine) and evaluates the JavaScript payload that follows. Because the executing process is a trusted, signed Windows binary, this technique bypasses:

1. **Application whitelisting** — rundll32.exe is universally allowed in enterprise environments.
2. **Signature-based detection** — the binary itself is legitimately signed by Microsoft.
3. **Basic process-name monitoring** — rundll32.exe appears in normal system operations (Control Panel applets, printer drivers, shell extensions).

**Why at this lifecycle stage:** After initial access and establishing a foothold, the attacker needs to execute payloads without triggering security controls. Rundll32 proxy execution is a "living off the land" (LOLBin) technique — the attacker uses a pre-installed system tool rather than dropping a custom executable (which would face signature checks as shown in AGC-014).

**Key triage differentiator:** The **CommandLine content** is the primary detection signal, not the binary itself. Legitimate rundll32 calls reference specific DLL exports (`rundll32.exe shell32.dll,Control_RunDLL`). The `javascript:` protocol handler pattern is virtually never legitimate and should be treated as high-confidence malicious.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Sysmon active.
- Batch file written to `C:\Temp\agc015-run.cmd` containing the rundll32 javascript: command.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 18:45:31 | Write batch wrapper | COMPROMISED-HOST-01 | Created `C:\Temp\agc015-run.cmd` containing `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();close()` |
| 2 | 2026-09-15 18:45:31 | Execute via cmd.exe | COMPROMISED-HOST-01 | `cmd.exe /c C:\Temp\agc015-run.cmd` — spawns rundll32 with javascript: argument |
| 3 | 2026-09-15 18:45:31 | rundll32 PID 4932 starts | COMPROMISED-HOST-01 | Process confirmed running via Get-Process. Loads mshtml.dll, executes JavaScript payload (`document.write();close()`). |
| 4 | 2026-09-15 18:45:46 | Cleanup | COMPROMISED-HOST-01 | Killed residual rundll32 process, removed batch file |

**Cleanup:** Batch file and any marker files removed after evidence collection.

## SOC Perspective

### Detection

**Sysmon telemetry (COMPROMISED-HOST-01):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 18:45:31 | 1 | Process Create | **Image:** `C:\Windows\System32\rundll32.exe` (PID 4932). **CommandLine:** `rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";document.write();close()`. **User:** `COMPROMISED-01\Administrator`. **IntegrityLevel:** High. **Hashes:** MD5=0AE8896B13D785C56A75A5DAC3809036, SHA256=F3E73F8A59B991FA8CDB91D4B37E11110C33A9EABDB25AF8AC8AB5CCF9E3BBF5 |
| 2026-09-15 18:45:31 | 1 | Process Create | **Image:** `C:\Windows\System32\cmd.exe` (PID 3080). **CommandLine:** `"C:\WINDOWS\system32\cmd.exe" /c C:\Temp\agc015-run.cmd`. Parent process that launched rundll32. |

**Key detection signal:** Sysmon EID 1 where `Image` ends with `rundll32.exe` and `CommandLine` contains any of:
- `javascript:` — the protocol handler trigger
- `mshtml` — direct DLL reference for HTML engine
- `RunHTMLApplication` — the specific export used for JavaScript execution

**Detection note:** SwiftOnSecurity's Sysmon configuration does log rundll32 EID 1 events, but the event may appear with a slight delay in event log indexing. Initial queries within 5 seconds of execution may miss the event. Broader time-window queries reliably capture it. This is relevant for real-time detection pipeline tuning.

### Investigation

**Step 1 — Identify the anomalous CommandLine:**
At 18:45:31 UTC, Sysmon EID 1 recorded `rundll32.exe` (PID 4932) with CommandLine containing `javascript:"\..\mshtml,RunHTMLApplication "`. This is a well-documented LOLBin abuse pattern (LOLBAS Project: rundll32). The `javascript:` protocol causes rundll32 to load `mshtml.dll` and evaluate arbitrary JavaScript code — in this case, `document.write();close()`.

**Step 2 — Establish a baseline for legitimate rundll32 usage:**
Normal rundll32.exe invocations in this environment include:
- `rundll32.exe shell32.dll,Control_RunDLL` (Control Panel)
- `rundll32.exe printui.dll,PrintUIEntry` (printer operations)
- `rundll32.exe user32.dll,UpdatePerUserSystemParameters` (display settings)

All legitimate calls reference a **specific DLL path and export name**. The `javascript:` protocol handler pattern does not match any known legitimate use case.

**Step 3 — Assess impact:**
The payload in this simulation was benign (`document.write();close()`). In a real attack, the JavaScript payload would typically:
1. Download and execute a second-stage payload
2. Establish a reverse shell
3. Execute encoded PowerShell (chaining with T1059.001 as seen in AGC-013)
4. Write files to disk for persistence

The process ran at High integrity under the Administrator account, meaning the payload had full system access.

### Report

**Verdict: True Positive** — rundll32.exe was invoked with the `javascript:`/`mshtml` proxy execution pattern, a technique with no legitimate use case.

**Confidence: High** — The detection is content-based (CommandLine analysis), not heuristic. The `javascript:` protocol handler in a rundll32 CommandLine is a definitive indicator of abuse:
- Zero false-positive rate when matching `javascript:` + `mshtml` + `RunHTMLApplication` in rundll32 CommandLine.
- The binary itself (hash, signature, path) is completely legitimate — only the invocation pattern is anomalous.
- File-reputation checks are useless here; the binary IS a trusted Microsoft component. Only behavioral/content-based detection works.

**Response recommendation:**
1. **Immediate isolation** — this pattern has no legitimate use. Isolate the host.
2. **Investigate the parent process chain** — who launched cmd.exe/rundll32? Was it a browser (drive-by), Office macro, or scheduled task?
3. **Check for child processes and network connections** — the JavaScript payload may have spawned additional processes or made outbound connections.
4. **Detection rule:** Alert on Sysmon EID 1 where `Image LIKE '%\rundll32.exe'` AND (`CommandLine LIKE '%javascript:%'` OR `CommandLine LIKE '%vbscript:%'` OR `CommandLine LIKE '%mshtml%RunHTMLApplication%'`). This has a near-zero FP rate.
5. **Application whitelisting hardening:** Consider blocking rundll32.exe from loading mshtml.dll via Windows Defender Application Control (WDAC) or AppLocker DLL rules. This blocks the proxy execution vector without breaking legitimate rundll32 usage.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Defense Evasion (TA0005) | T1218.011 | Signed Binary Proxy Execution: Rundll32 | rundll32.exe (PID 4932) invoked with `javascript:"\..\mshtml,RunHTMLApplication "` CommandLine. Microsoft-signed binary abused as execution proxy. Sysmon EID 1 captured full CommandLine. | High |

## Evidence

Screenshots: not applicable (text-based evidence collection only).
