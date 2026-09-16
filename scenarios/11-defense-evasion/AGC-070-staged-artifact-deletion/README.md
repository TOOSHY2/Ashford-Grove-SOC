# AGC-070 — Staged-Artifact Deletion (Cleanup)

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-070` |
| Category | `11-defense-evasion` — Defense Evasion |
| MITRE Technique | `T1070.004` Indicator Removal: File Deletion |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Sysmon EID 1 (cmd.exe with `del /f /q staged.zip` in command line) |
| Time to Triage | 05:00 (correlate deleted file with prior staging/exfiltration events) |
| Affected Systems | `COMPROMISED-HOST-01` (10.10.10.103) |
| Chain | ◀ [AGC-069](../AGC-069-wazuh-agent-tamper/README.md) · next [AGC-071](../AGC-071-obfuscated-command-line/README.md) ▶ |
| One-line Summary | Deletion of staged archive (`staged.zip`, 858 bytes) and staging directory from `C:\Windows\Temp\` — cleanup of artifacts left behind by the collection (AGC-057) and exfiltration (AGC-062/066) phases. The deletion itself was captured via Sysmon EID 1 (cmd.exe process with `del /f /q` command line). Sysmon EID 23 (FileDelete) and EID 26 (FileDeleteDetected) were NOT enabled in the SwiftOnSecurity configuration, representing a detection gap: the deletion process is visible but the specific file deletion event is not directly logged. This is the final phase of the attacker's collection-to-cleanup lifecycle. |

## Attacker Perspective

### Tradecraft

**What:** After exfiltrating collected data, the attacker deletes the staged archives and temporary files to remove evidence of the collection and staging phases. This cleanup prevents forensic investigators from finding the intermediate artifacts that would reveal what data was collected and exfiltrated.

**Why an Attacker Uses It Here:**
- `staged.zip` is direct evidence of data collection (AGC-057/066 patterns)
- The staging directory contains the individual files that were archived
- Deleting these artifacts after successful exfiltration removes the "what was taken" evidence
- Combined with log clearing (AGC-067) and SIEM tampering (AGC-069), this completes the evidence destruction chain
- `del /f /q` forces deletion without confirmation, suitable for scripted cleanup

**Lifecycle completion:**
```
AGC-057: Collect and archive     --> staged.zip created
AGC-062: Exfiltrate via HTTPS    --> staged.zip uploaded to C2
AGC-066: Archive + upload combo  --> unified collection-exfil
AGC-070: Delete staged.zip       --> cleanup (this scenario)
```

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context
- Staged archive recreated (simulating AGC-057/066 remnant): 4 finance documents compressed to staged.zip (858 bytes)

**Execution:**
```cmd
del /f /q C:\Windows\Temp\staged.zip
```

**Result:** File deleted. Staging directory also removed via `Remove-Item -Recurse -Force`. Both confirmed absent post-deletion.

## SOC Perspective

### Detection

**Sysmon EID 1 — cmd.exe deletion command:**
```
Process Create:
UtcTime: 2026-09-15 23:21:17.056
ProcessGuid: {eb65e329-d2ed-6aa9-1505-000000001400}
ProcessId: 6052
Image: C:\Windows\System32\cmd.exe
CommandLine: "C:\WINDOWS\system32\cmd.exe" /c "del /f /q C:\Windows\Temp\staged.zip"
User: COMPROMISED-01\Administrator
IntegrityLevel: High
LogonId: 0x7B14ED
```

**Sysmon EID 23 (FileDelete): 0 events**
File deletion logging (EID 23) is NOT enabled in the SwiftOnSecurity Sysmon configuration. This is a significant detection gap — the deletion action is only visible through the cmd.exe process creation, not through a dedicated file deletion event.

**Sysmon EID 26 (FileDeleteDetected): 0 events**
Also not enabled in the current Sysmon configuration.

**Sysmon EID 1 — PowerShell orchestration:**
```
Process Create:
UtcTime: 2026-09-15 23:21:12.388
ProcessGuid: {eb65e329-d2e8-6aa9-1405-000000001400}
ProcessId: 2352
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc070-sim.ps1
User: COMPROMISED-01\Administrator
```

### Investigation

**Step 1 — Correlate deleted file with prior staging:**
The deleted file (`C:\Windows\Temp\staged.zip`) matches the artifact naming and location from:
- **AGC-057**: Compress-Archive created staged archives in `C:\Windows\Temp\`
- **AGC-066**: Unified archive-exfil operation used `C:\Windows\Temp\agc066_staged.zip`
The deletion targets the remnant of these operations, confirming the attacker is cleaning up after a completed exfiltration campaign.

**Step 2 — Detection gap assessment:**
Without Sysmon EID 23/26, the investigation must rely on:
- **EID 1 command-line analysis:** `del /f /q` with a specific file path in `C:\Windows\Temp\`
- **Absence correlation:** File was known to exist (created by AGC-057/066 operations, captured by EID 11 where applicable) but is now absent on the filesystem
- **Timeline proximity:** Deletion occurred shortly after defense evasion activities (AGC-067/068/069)

**Step 3 — Collection-to-cleanup lifecycle:**
```
Collection:     AGC-057 (archive), AGC-058 (screenshots), AGC-059 (browser data)
Staging:        AGC-061 (AD export), AGC-064 (USB staging), AGC-065 (SMB staging)
Exfiltration:   AGC-062 (HTTPS), AGC-063 (DNS), AGC-066 (archive+upload)
Evasion:        AGC-067 (log clear), AGC-068 (AV disable), AGC-069 (SIEM tamper)
Cleanup:        AGC-070 (artifact deletion) <-- this scenario
```
The artifact deletion is the final phase, confirming the attacker has completed their mission and is now systematically removing evidence.

**Step 4 — Sysmon configuration recommendation:**
Enable EID 23 (FileDelete) and/or EID 26 (FileDeleteDetected) in the Sysmon configuration to capture file deletion events directly. Without these, file deletion detection depends entirely on command-line analysis of process creation events, which can miss deletion performed through Windows Explorer or API calls without a visible process.

### Report

**Verdict: True Positive** — Deliberate deletion of exfiltration staging artifacts.

**Confidence: High** (not Critical because the deletion itself is a secondary indicator — the primary damage was the exfiltration):
1. Deleted file matches known staging artifact from prior collection scenarios
2. Deletion performed from confirmed compromised host with active C2
3. Follows the established defense evasion sequence (AGC-067/068/069)
4. cmd.exe with `del /f /q` is an explicit forced deletion command
5. Administrator context on the compromised host

**Response recommendation:**
1. **Focus forensic effort on the exfiltration**, not the cleanup — the damage was done when the data left the network (AGC-062/063/066), not when the staging files were deleted
2. **Enable Sysmon EID 23/26** in the configuration to capture future file deletion events directly, closing the detection gap
3. **Check for additional remnant files** in `C:\Windows\Temp\` and other staging directories — the attacker may have missed some artifacts
4. **Review Sysmon EID 11 history** for file creation events in `C:\Windows\Temp\` — these may reveal files that were staged and subsequently deleted without EID 23 logging
5. **Correlate the cleanup timeline** with the exfiltration timeline to establish the complete attack lifecycle

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Defense Evasion (TA0005) | T1070.004 | Indicator Removal: File Deletion | `del /f /q C:\Windows\Temp\staged.zip` deleted staging archive. Sysmon EID 1 captured cmd.exe (PID 6052). EID 23/26 NOT enabled (detection gap). File confirmed absent. Part of collection-to-cleanup lifecycle. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### Artifact lifecycle (creation to deletion)

```
CREATION (AGC-057/066 pattern):
  File:      C:\Windows\Temp\staged.zip (858 bytes)
  Contents:  4 finance documents (Q3 Revenue, Client Portfolio, Payroll, Wire Transfers)
  Created:   2026-09-15 23:21:13 UTC

EXFILTRATION (AGC-062/066 pattern):
  Data uploaded to 10.10.40.10 via HTTPS/HTTP
  Staging artifacts remain on disk after successful exfiltration

DELETION (this scenario):
  Time:      2026-09-15 23:21:17 UTC
  Command:   del /f /q C:\Windows\Temp\staged.zip
  Process:   cmd.exe (PID 6052), Administrator
  Result:    File confirmed absent

Time from creation to deletion: ~4 seconds (simulated lifecycle)
```

### Detection gap: EID 23/26 not enabled

```
Sysmon EID 23 (FileDelete):         NOT ENABLED in SwiftOnSecurity config
Sysmon EID 26 (FileDeleteDetected): NOT ENABLED in SwiftOnSecurity config

Available detection:
  EID 1:  cmd.exe with "del /f /q" in CommandLine (captured)
  EID 11: File creation event for the original staging (captured for EXE/DLL only)

Recommendation: Enable EID 23 with TargetFilename filter for:
  - C:\Windows\Temp\*.zip
  - C:\Windows\Temp\staged*
  - Known staging directories
```
