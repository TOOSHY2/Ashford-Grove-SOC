# AGC-014 — Executable Launched From a Temp Directory

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-014` |
| Category | `02-execution` — Execution |
| MITRE Technique | `T1204.002` User Execution: Malicious File (location heuristic) |
| Verdict | True Positive |
| Confidence | Medium |
| Time to Detect | Immediate — Sysmon EID 11 (File Create, RuleName: EXE) captures placement; EID 1 captures execution |
| Time to Triage | 02:00 (from alert to signature verification and behavior assessment) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ AGC-013 · next AGC-015 ▶ |
| One-line Summary | Executable file placed and launched from user's `AppData\Local\Temp` directory — common malware staging location. |

## Attacker Perspective

### Tradecraft

**What:** An executable is dropped to a temporary directory (`%TEMP%`, `%LOCALAPPDATA%\Temp`, `C:\Windows\Temp`, Downloads) and executed directly from that path. Malware droppers, exploit payloads, and second-stage downloads commonly stage to Temp because:
1. **Write access guaranteed** — any user can write to their own `%TEMP%` without elevation.
2. **Expected noise** — installers, updaters, and self-extracting archives legitimately use Temp, so a broad detection rule generates false positives without additional context.
3. **Cleanup by OS** — Temp directories are periodically purged, which aids evidence destruction.

**Why at this lifecycle stage:** After initial access (phishing, exploit), the attacker downloads or drops a payload. The payload must land somewhere writable before it can execute. Temp directories are the default staging location because they require no special permissions and are less likely to be monitored than `C:\Program Files` or `C:\Windows\System32`.

**Key triage differentiator:** The signature status of the executable is the primary factor separating malicious from benign:
- **Unsigned or unknown publisher** from Temp = high suspicion.
- **Microsoft-signed / known vendor** from Temp = likely installer or updater artifact (but still worth confirming).

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Sysmon running.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 18:39:02 | Place executable in Temp | COMPROMISED-HOST-01 | Copied `whoami.exe` (98304 bytes) to `C:\Users\michael.chen\AppData\Local\Temp\agc014_test.exe` |
| 2 | 2026-09-15 18:39:02 | Execute from Temp path | COMPROMISED-HOST-01 | `agc014_test.exe` executed; output: `compromised-01\administrator` |
| 3 | 2026-09-15 18:39:02 | Signature check | COMPROMISED-HOST-01 | Valid signature — CN=Microsoft Windows, O=Microsoft Corporation |

**Cleanup:** Executable deleted after evidence collection.

## SOC Perspective

### Detection

**Sysmon telemetry (COMPROMISED-HOST-01):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 18:39:02 | 11 | File Create | **RuleName: EXE** — `TargetFilename: C:\Users\michael.chen\AppData\Local\Temp\agc014_test.exe`, `Image: powershell.exe` (dropper process). The `RuleName: EXE` tag indicates Sysmon's SwiftOnSecurity config specifically flagged this as an executable file creation event. |

**Key detection signal:** Sysmon EID 11 with `RuleName: EXE` where `TargetFilename` matches a Temp directory pattern (`\AppData\Local\Temp\`, `\Windows\Temp\`, `\Downloads\`). This catches the staging phase — the executable landing on disk — before it runs.

**Detection note:** Sysmon EID 1 (Process Create) for the execution may be filtered by the Sysmon configuration when the OriginalFileName matches a known system binary (in this case, `whoami.exe`). In a real attack, the dropped executable would have an unknown OriginalFileName, making EID 1 detection more reliable.

### Investigation

**Step 1 — Confirm executable placement:**
At 18:39:02 UTC, Sysmon EID 11 recorded an executable file write to `C:\Users\michael.chen\AppData\Local\Temp\agc014_test.exe`. The `RuleName: EXE` tag confirms the Sysmon configuration identified this as a potentially suspicious executable placement.

**Step 2 — Check the signature (critical triage step):**
The executable has a **valid Microsoft Windows signature** (CN=Microsoft Windows, O=Microsoft Corporation). This is a strong indicator that the file is a legitimate Windows binary — not malware. In this simulation, the file is a renamed copy of `whoami.exe`.

**In a real attack:** The dropped executable would be:
- **Unsigned** — most custom malware does not carry valid code-signing certificates.
- **Signed by an unknown publisher** — some sophisticated malware uses stolen or purchased certificates.
- **Self-signed** — a trivially-generated certificate.

The signature status is the **primary differentiator** between a True Positive (malicious) and a False Positive (installer artifact). An unsigned executable in Temp from a non-interactive context is high-confidence malicious.

**Step 3 — Investigate parent process and follow-on behavior:**
The dropper process was `powershell.exe` (PID 2436) — in this simulation, the lab automation harness. In a real investigation, the analyst would check:
1. **Who dropped the file?** — Was the parent a browser (drive-by), Office app (macro), or another suspicious process?
2. **What did the executable do after launch?** — Network connections (EID 3), file writes (EID 11), child processes (EID 1).
3. **Does the hash appear in threat intelligence?** — VirusTotal, internal IOC feeds.

### Report

**Verdict: True Positive** — Executable placed and launched from a user Temp directory, matching the malware staging pattern.

**Confidence: Medium** — This is a broad heuristic with a real false-positive rate:
- Legitimate software installers, updaters, and self-extracting archives routinely place executables in Temp.
- The signature check (Valid, Microsoft Windows) would normally lower suspicion.
- Medium confidence reflects the heuristic's value as a **correlation signal** rather than a standalone alert: combine with parent-process analysis, signature status, and follow-on behavior to reach a final determination.

**Response recommendation:**
1. **Check the signature first** — a valid, trusted-vendor signature dramatically reduces the risk.
2. **If unsigned:** Isolate the host, collect the binary for analysis, investigate parent and child processes.
3. **If signed by a known vendor:** Verify the action is expected (is a software update running?). Close as FP if confirmed legitimate.
4. **Detection rule:** Alert on Sysmon EID 11 where `RuleName = EXE` AND `TargetFilename LIKE '%\AppData\Local\Temp\%'` or `%\Windows\Temp\%`. Enrich with Authenticode signature check. Escalate unsigned executables automatically.
5. **Correlation rule:** Escalate if this EID 11 alert is followed within 60 seconds by an EID 1 (Process Create) from the same path, and the process makes an outbound network connection (EID 3).

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Execution (TA0002) | T1204.002 | User Execution: Malicious File | `agc014_test.exe` placed in `C:\Users\michael.chen\AppData\Local\Temp\` and executed. Sysmon EID 11 (RuleName: EXE) captured placement. Valid Microsoft signature (simulation uses renamed whoami.exe). | Medium |

## Evidence

Screenshots: to be added manually by the analyst.
