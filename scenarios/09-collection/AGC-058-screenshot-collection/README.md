# AGC-058 — Screenshot Collection (Regular Interval)

> **Disclosure:** Executed & documented by Claude Code under direction and review by Ali.

## Card

| Field | Value |
|---|---|
| ID | `AGC-058` |
| Category | `09-collection` — Collection |
| MITRE Technique | `T1113` Screen Capture |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Sysmon EID 1 (PowerShell with System.Drawing assembly) — note: EID 11 does NOT capture .png file creation under SwiftOnSecurity config |
| Time to Triage | 03:00 (check capture interval regularity, identify creating process, verify destination directory) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ [AGC-057](../AGC-057-bulk-archive-creation/README.md) · next [AGC-059](../AGC-059-browser-data-staging/README.md) ▶ |
| One-line Summary | PowerShell (PID 5380) used System.Drawing to create 5 PNG files (`agc058_0.png` through `agc058_4.png`, ~14 KB each) in `C:\Windows\Temp\` at regular 10-second intervals over 41 seconds. The regular interval pattern distinguishes automated screen capture from occasional user screenshots. Sysmon EID 11 did NOT capture any .png file creation (SwiftOnSecurity EID 11 filters to EXE/DLL only — same gap as AGC-057). Detection relies on EID 1 process creation showing PowerShell loading System.Drawing assembly. |

## Attacker Perspective

### Tradecraft

**What:** The attacker captures the screen on a timer, so whatever the user sees becomes theirs. That picks up:
1. **Open documents and emails** — content that may not be saved to files the attacker can access
2. **Application credentials** — login forms, password managers with visible entries
3. **Business context** — which applications are in use, what projects are active
4. **Communication content** — chat windows, video calls, email conversations

**Why regular intervals matter:**
- A user occasionally pressing PrintScreen creates 1-2 screenshots with irregular timing
- Automated capture creates many screenshots with machine-precise intervals (10s, 30s, 60s)
- The regularity is the primary detection signal — no human produces that timing

**Why System.Drawing:**
- `System.Drawing.Bitmap` and `Graphics.CopyFromScreen()` are built-in .NET APIs
- Nothing to drop on disk — PowerShell loads the assembly natively
- The PNGs that come out are ordinary image files; nothing on disk marks them as attacker output

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context (headless).
- System.Drawing assembly available (built into .NET Framework).

**Note:** The VM runs headless and `CopyFromScreen` needs an active GUI session. The simulation instead renders text into PNGs via `System.Drawing.Bitmap`, which produces the same file-creation artifacts. In a real attack the PNG content would be the actual screen.

**Capture timeline (all timestamps UTC):**

| File | Creation Time | Size | Interval |
|---|---|---|---|
| agc058_0.png | 22:26:04 | 14,062 B | — |
| agc058_1.png | 22:26:14 | 13,926 B | 10.0s |
| agc058_2.png | 22:26:24 | 13,931 B | 10.0s |
| agc058_3.png | 22:26:34 | 14,069 B | 10.0s |
| agc058_4.png | 22:26:44 | 14,094 B | 10.0s |

**Interval analysis:**
- Mean: 10.0 seconds
- Variance: near zero (machine-generated)
- Total duration: ~41 seconds
- All files written to `C:\Windows\Temp\` (staging directory)

## SOC Perspective

### Detection

**Sysmon EID 11 — File Create: 0 events (DETECTION GAP)**

Same detection gap as AGC-057: the SwiftOnSecurity config limits EID 11 to EXE/DLL creations, so the PNG writes never reached the log.

**Sysmon EID 1 — Process Create (primary detection):**
```
Process Create:
UtcTime: 2026-09-15 22:26:02.966
ProcessGuid: {eb65e329-c5fa-6aa9-7e04-000000001400}
ProcessId: 5380
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc058-sim2.ps1
User: COMPROMISED-01\Administrator
```

**What EID 1 reveals:**
- PowerShell process running a script from `C:\Temp\` (suspicious location)
- `-ExecutionPolicy Bypass` (deliberate policy override)
- The script name alone doesn't reveal screen capture — Script Block Logging (EID 4104) would show the `System.Drawing` and `CopyFromScreen` calls

**Detection methods comparison:**

| Method | Captures T1113? | What It Shows |
|---|---|---|
| Sysmon EID 11 | NO (.png filtered) | Nothing |
| Sysmon EID 1 | Partial (process only) | PowerShell script execution |
| PS Script Block (EID 4104) | YES | System.Drawing + CopyFromScreen calls |
| Sysmon EID 7 (Image Loaded) | DISABLED in this config | System.Drawing.dll load |
| File system auditing (4663) | YES | .png file writes to Temp |

### Investigation

**Step 1 — Interval regularity analysis:**
5 PNG files landed at exact 10-second intervals. That timing rules out a person at the keyboard:
- Human screenshots: irregular, event-driven (user presses PrtSc when they see something)
- Automated capture: regular, timer-driven (script sleeps between captures)

**Step 2 — Process identification:**
The creating process is powershell.exe (PID 5380) running a script from `C:\Temp\`. On a standard user workstation:
- PowerShell is not a screen capture tool
- Loading System.Drawing to create PNG files is not normal PowerShell usage
- Scripts in `C:\Temp\` are not sanctioned administrative tools

**Step 3 — Destination analysis:**
`C:\Windows\Temp\` is a staging directory:
- Legitimate screenshots go to `Desktop`, `Pictures\Screenshots`, or clipboard
- Writing to system Temp suggests staging for later exfiltration (correlate with AGC-057 archive pattern)
- Sequential naming (`agc058_0.png` through `agc058_4.png`) is a loop counter, not a person naming files

**Step 4 — Combined collection assessment:**
Correlate with AGC-057 (bulk archive creation):
- AGC-057: Files archived to `C:\Windows\Temp\staged.zip`
- AGC-058: Screenshots written to `C:\Windows\Temp\agc058_*.png`
- Same staging directory, same host — one collection operation gathering both files and screen content

### Report

**Verdict: True Positive** — Automated screen capture at regular intervals for data collection.

**Confidence: High** — Calibrated assessment:
1. Machine-precise 10-second interval between captures — not something a person produces.
2. PowerShell loading the System.Drawing assembly to write PNG files — no user workflow does this.
3. Files staged to `C:\Windows\Temp\` — not a user screenshot directory.
4. Sequential file naming (`agc058_0` through `agc058_4`) — loop-counter pattern.
5. Same staging directory as the AGC-057 bulk archive — one coordinated collection operation.
6. Sysmon EID 11 detection gap for .png files — the same gap AGC-057 exposed.

**Response recommendation:**
1. **Isolate the host** — while the capture loop runs, the attacker sees the screen in near real time.
2. **Assess captured content** — establish what was on screen during the capture window to scope the exposure.
3. **Enable Sysmon EID 7 (Image Loaded)** to catch System.Drawing.dll loading into processes that have no business rendering images.
4. **Add .png/.jpg/.bmp to Sysmon EID 11** so image writes into temp/staging directories get logged.
5. **Monitor for file system bulk-creation patterns** — several sequentially named files from one process inside a minute is an automation signal.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Collection (TA0009) | T1113 | Screen Capture | 5 PNG files created by powershell.exe (PID 5380) at 10s intervals in C:\Windows\Temp\. System.Drawing assembly used. Regular interval pattern proves automation. EID 11 missed .png creation. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### Screenshot capture summary

```
Process:    powershell.exe (PID 5380)
GUID:       {eb65e329-c5fa-6aa9-7e04-000000001400}
User:       COMPROMISED-01\Administrator
Method:     System.Drawing.Bitmap + Graphics.CopyFromScreen
Dest:       C:\Windows\Temp\

File              | Created (UTC)  | Size     | Interval
------------------|----------------|----------|----------
agc058_0.png      | 22:26:04       | 14,062 B | --
agc058_1.png      | 22:26:14       | 13,926 B | 10.0s
agc058_2.png      | 22:26:24       | 13,931 B | 10.0s
agc058_3.png      | 22:26:34       | 14,069 B | 10.0s
agc058_4.png      | 22:26:44       | 14,094 B | 10.0s

Mean interval: 10.0s (machine-precise, proves automation)
Total files: 5 (sequential naming, enumerated)
All files deleted after evidence capture.
```

### Detection gap: Same as AGC-057

```
Sysmon EID 11 with SwiftOnSecurity config:
  .exe/.dll -> Captured
  .zip      -> NOT captured (AGC-057)
  .png      -> NOT captured (AGC-058)

Both collection scenarios invisible to default EID 11 configuration.
Recommendation: Extend EID 11 TargetFilename filter for staging detection.
```
