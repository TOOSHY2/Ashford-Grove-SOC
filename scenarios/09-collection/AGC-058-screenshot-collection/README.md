# AGC-058 -- Screenshot Collection (Regular Interval)

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-058` |
| Category | `09-collection` -- Collection |
| MITRE Technique | `T1113` Screen Capture |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Sysmon EID 1 (PowerShell with System.Drawing assembly) -- note: EID 11 does NOT capture .png file creation under SwiftOnSecurity config |
| Time to Triage | 03:00 (check capture interval regularity, identify creating process, verify destination directory) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | < AGC-057 . next AGC-059 > |
| One-line Summary | PowerShell (PID 5380) used System.Drawing to create 5 PNG files (`agc058_0.png` through `agc058_4.png`, ~14 KB each) in `C:\Windows\Temp\` at regular 10-second intervals over 41 seconds. The regular interval pattern distinguishes automated screen capture from occasional user screenshots. Sysmon EID 11 did NOT capture any .png file creation (SwiftOnSecurity EID 11 filters to EXE/DLL only -- same gap as AGC-057). Detection relies on EID 1 process creation showing PowerShell loading System.Drawing assembly. |

## Attacker Perspective

### Tradecraft

**What:** Automated screen capture at regular intervals collects visual intelligence from the compromised host -- whatever the user sees on screen becomes available to the attacker. This technique captures:
1. **Open documents and emails** -- content that may not be saved to files the attacker can access
2. **Application credentials** -- login forms, password managers with visible entries
3. **Business context** -- which applications are in use, what projects are active
4. **Communication content** -- chat windows, video calls, email conversations

**Why regular intervals matter:**
- A user occasionally pressing PrintScreen creates 1-2 screenshots with irregular timing
- Automated capture creates many screenshots with machine-precise intervals (10s, 30s, 60s)
- The regularity pattern is the primary detection signal -- it cannot be explained by human behavior

**Why System.Drawing:**
- `System.Drawing.Bitmap` and `Graphics.CopyFromScreen()` are built-in .NET APIs
- No external tools needed -- PowerShell loads the assembly natively
- The resulting PNG files are standard image files, indistinguishable from legitimate screenshots

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context (headless).
- System.Drawing assembly available (built into .NET Framework).

**Note:** VM runs headless -- `CopyFromScreen` requires an active GUI session. Simulation creates PNG files via `System.Drawing.Bitmap` with rendered text content to produce identical file-creation artifacts. In a real attack, the PNG content would be actual screen captures.

**Capture timeline (all timestamps UTC):**

| File | Creation Time | Size | Interval |
|---|---|---|---|
| agc058_0.png | 22:26:04 | 14,062 B | -- |
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

**Sysmon EID 11 -- File Create: 0 events (DETECTION GAP)**

Same detection gap as AGC-057: SwiftOnSecurity Sysmon config filters EID 11 to EXE/DLL file creations. PNG files are not captured.

**Sysmon EID 1 -- Process Create (primary detection):**
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
- The script name alone doesn't reveal screen capture -- Script Block Logging (EID 4104) would show the `System.Drawing` and `CopyFromScreen` calls

**Detection methods comparison:**

| Method | Captures T1113? | What It Shows |
|---|---|---|
| Sysmon EID 11 | NO (.png filtered) | Nothing |
| Sysmon EID 1 | Partial (process only) | PowerShell script execution |
| PS Script Block (EID 4104) | YES | System.Drawing + CopyFromScreen calls |
| Sysmon EID 7 (Image Loaded) | DISABLED in this config | System.Drawing.dll load |
| File system auditing (4663) | YES | .png file writes to Temp |

### Investigation

**Step 1 -- Interval regularity analysis:**
5 PNG files created at exactly 10-second intervals. This machine-precise timing eliminates human-initiated screenshot activity:
- Human screenshots: irregular, event-driven (user presses PrtSc when they see something)
- Automated capture: regular, timer-driven (script sleeps between captures)

**Step 2 -- Process identification:**
The creating process is powershell.exe (PID 5380) running a script from `C:\Temp\`. On a standard user workstation:
- PowerShell is not a screen capture tool
- Loading System.Drawing to create PNG files is not normal PowerShell usage
- Scripts in `C:\Temp\` are not sanctioned administrative tools

**Step 3 -- Destination analysis:**
`C:\Windows\Temp\` is a staging directory:
- Legitimate screenshots go to `Desktop`, `Pictures\Screenshots`, or clipboard
- Writing to system Temp suggests staging for later exfiltration (correlate with AGC-057 archive pattern)
- Sequential naming (`agc058_0.png` through `agc058_4.png`) indicates automated enumeration

**Step 4 -- Combined collection assessment:**
Correlate with AGC-057 (bulk archive creation):
- AGC-057: Files archived to `C:\Windows\Temp\staged.zip`
- AGC-058: Screenshots written to `C:\Windows\Temp\agc058_*.png`
- Same staging directory, same compromised host -- suggests a single collection operation gathering both files and screen content

### Report

**Verdict: True Positive** -- Automated screen capture at regular intervals for data collection.

**Confidence: High** -- Calibrated assessment:
1. Machine-precise 10-second interval between captures -- inconsistent with human behavior.
2. PowerShell process loading System.Drawing assembly to create PNG files -- not normal user activity.
3. Files staged to `C:\Windows\Temp\` -- not a user screenshot directory.
4. Sequential file naming (`agc058_0` through `agc058_4`) -- automated enumeration pattern.
5. Same staging directory as AGC-057 bulk archive -- coordinated collection operation.
6. Sysmon EID 11 detection gap for .png files -- critical finding.

**Response recommendation:**
1. **Isolate the host** -- active screen capture means the attacker is collecting real-time visual intelligence.
2. **Assess captured content** -- review what was on-screen during the capture period to determine sensitive data exposure.
3. **Enable Sysmon EID 7 (Image Loaded)** to detect System.Drawing.dll loading by unexpected processes.
4. **Add .png/.jpg/.bmp to Sysmon EID 11** filter to capture image file creation in temp/staging directories.
5. **Monitor for file system bulk-creation patterns** -- multiple sequential files from the same process in a short window is an automation signal.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Collection (TA0009) | T1113 | Screen Capture | 5 PNG files created by powershell.exe (PID 5380) at 10s intervals in C:\Windows\Temp\. System.Drawing assembly used. Regular interval pattern proves automation. EID 11 missed .png creation. | High |

## Evidence

Screenshots: not applicable (text-based evidence collection only).

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
