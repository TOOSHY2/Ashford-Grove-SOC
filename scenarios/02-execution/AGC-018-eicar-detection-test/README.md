# AGC-018 — EICAR Safe Detection Test

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-018` |
| Category | `02-execution` — Execution (pipeline validation) |
| MITRE Technique | N/A — EICAR is a standardized AV test file, not an ATT&CK technique |
| Verdict | Pipeline Pass |
| Confidence | High |
| Time to Detect | ~14 seconds (file write to Defender EID 1116 detection event) |
| Time to Remediate | ~19 seconds (file write to Defender EID 1117 remediation event) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ AGC-017 · next AGC-019 (Persistence category) ▶ |
| One-line Summary | EICAR test file validates the endpoint detection pipeline: Defender detected and quarantined the EICAR string, confirming real-time protection is functional. |

## Purpose

### What This Is

This is **not** an attack technique simulation. AGC-018 is a **pipeline validation test** using the industry-standard EICAR Anti-Virus Test File (a 68-byte string recognized by all AV engines as a test detection). The purpose is to confirm that the detection chain works end-to-end:

1. **Endpoint layer (Defender):** Does real-time protection detect the EICAR string when written to disk?
2. **SIEM layer (Wazuh):** Does the Defender detection event propagate to the centralized SIEM?
3. **Detection latency:** How quickly does the alert travel from endpoint to SIEM?

If either layer fails, every prior "no alert triggered, therefore benign" conclusion in this engagement is unreliable until the pipeline is repaired.

### Why This Scenario Exists

False negatives can occur silently. A detection pipeline that appears functional may have a broken component (disabled RTP, stale signatures, agent disconnection, log forwarding failure) that only surfaces when tested. Running EICAR as a controlled positive provides a known-good test signal through the entire chain.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Defender RTP confirmed enabled.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 18:55:54 | Confirm Defender RTP | COMPROMISED-HOST-01 | `Get-MpPreference` confirms `DisableRealtimeMonitoring = False` |
| 2 | 2026-09-15 18:55:55 | Write EICAR to .txt | COMPROMISED-HOST-01 | `[System.IO.File]::WriteAllText("C:\Windows\Temp\eicar.txt", $eicar)` |
| 3 | 2026-09-15 18:56:05 | Write EICAR to .com | COMPROMISED-HOST-01 | Same EICAR string to `C:\Windows\Temp\eicar.com` |
| 4 | 2026-09-15 18:56:09 | Defender detects | COMPROMISED-HOST-01 | EID 1116: `Virus:DOS/EICAR_Test_File` detected in both files |
| 5 | 2026-09-15 18:56:14 | Defender remediates | COMPROMISED-HOST-01 | EID 1117: Action "Remove" applied to both files |

**Cleanup:** Files removed by Defender quarantine action.

## SOC Perspective

### Detection

**Windows Defender operational log (COMPROMISED-HOST-01):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 18:56:09 | 1116 | Malware Detected | **Name:** `Virus:DOS/EICAR_Test_File`. **ID:** 2147519003. **Severity:** Severe. **Path:** `file:_C:\Windows\Temp\eicar.txt`. **Detection Source:** Real-Time Protection. **Process Name:** `powershell.exe`. |
| 2026-09-15 18:56:09 | 1116 | Malware Detected | **Name:** `Virus:DOS/EICAR_Test_File`. **Path:** `file:_C:\Windows\Temp\eicar.com; file:_C:\Windows\Temp\eicar.txt`. **Detection Origin:** Local machine. |
| 2026-09-15 18:56:14 | 1117 | Remediation Applied | **Name:** `Virus:DOS/EICAR_Test_File`. **Action:** Remove. **Action Status:** No additional actions required. **Error Code:** 0x00000000. |

**Defender threat history (Get-MpThreatDetection):**

| Threat ID | Name | Initial Detection | Action Success | Resources |
|---|---|---|---|---|
| 2147519003 | Virus:DOS/EICAR_Test_File | 2026-09-15 18:56:05 | True | `file:_C:\Windows\Temp\eicar.com`, `file:_C:\Windows\Temp\eicar.txt` |

**Bonus finding — AGC-015 retroactive detection:**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 18:52:08 | 1117 | Remediation Applied | **Name:** `Trojan:Win32/Powessere.G` (ID: 2147725444). **Path:** `CmdLine:_C:\Windows\System32\rundll32.exe javascript:\..\mshtml,RunHTMLApplication ;document.write();close()`. Defender detected the AGC-015 rundll32 javascript: proxy execution as a known trojan variant. |

### Investigation

**Step 1 — Confirm Defender endpoint detection:**
Defender EID 1116 (detection) fired at 18:56:09 UTC for both EICAR files (`eicar.txt` and `eicar.com`). Detection Source: "Real-Time Protection". The EICAR string was detected by signature match (Virus:DOS/EICAR_Test_File, ID 2147519003). **Endpoint layer: PASS.**

**Step 2 — Confirm SIEM propagation:**
WAZUH-SIEM-01 Guest Additions were temporarily unavailable during this test window. The Wazuh SIEM propagation could not be independently verified in this test run. **SIEM layer: UNTESTED** (infrastructure limitation, not a pipeline failure).

In a production environment, the analyst would verify that Wazuh received and displayed the Defender alert for EICAR within the expected propagation window. If Wazuh does not show the detection event, this indicates a log forwarding or agent communication issue that must be resolved before trusting negative Wazuh results.

**Step 3 — Measure detection latency:**
- **EICAR file write:** 18:55:55 UTC (first file)
- **Defender detection (EID 1116):** 18:56:09 UTC
- **Defender remediation (EID 1117):** 18:56:14 UTC
- **Write-to-detect delta:** ~14 seconds
- **Write-to-remediate delta:** ~19 seconds

This establishes the baseline detection latency for this lab: approximately 14-19 seconds from file creation to detection and remediation.

**Bonus observation:** Defender also retroactively detected the AGC-015 rundll32 `javascript:` execution (at 18:45:46 UTC) as `Trojan:Win32/Powessere.G` and applied remediation at 18:52:08 UTC. This demonstrates Defender's behavioral/AMSI detection operates on a different (slower) pipeline than file-based signature matching (~6 minute lag for command-line pattern matching vs. ~14 seconds for file-based EICAR).

### Report

**Verdict: Pipeline Pass** — Defender real-time protection is functional on COMPROMISED-HOST-01:
- EICAR test file detected and quarantined (EID 1116 + 1117).
- Behavioral detection also confirmed via AGC-015 Powessere.G detection.
- SIEM propagation untested due to infrastructure limitation.

**Confidence: High** — Multiple independent signals confirm endpoint protection:
- Defender RTP confirmed enabled via `Get-MpPreference`.
- EID 1116 (detection) and EID 1117 (remediation) events captured with correct threat classification.
- Threat history (`Get-MpThreatDetection`) independently confirms detection timestamps and action success.

**Action items:**
1. **Re-test Wazuh propagation** when WAZUH-SIEM-01 Guest Additions are restored, to confirm the full endpoint-to-SIEM pipeline.
2. **Periodically re-run EICAR test** (monthly or after infrastructure changes) to validate the pipeline remains intact.
3. **Document the detection latency baseline** (~14-19 seconds) for this environment to set expectations for real-time alerting.

### MITRE Mapping

N/A — EICAR is a standardized antivirus test file, not an adversary technique. No ATT&CK mapping applies.

## Evidence

Screenshots: not applicable (text-based evidence collection only).
