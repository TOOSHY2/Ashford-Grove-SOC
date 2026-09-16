# AGC-068 — Windows Defender Real-Time Protection Disabled

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-068` |
| Category | `11-defense-evasion` — Defense Evasion |
| MITRE Technique | `T1562.001` Impair Defenses: Disable or Modify Tools |
| Verdict | True Positive |
| Confidence | Critical |
| Time to Detect | Sysmon EID 1 (Set-MpPreference command in PowerShell process) |
| Time to Triage | 03:00 (verify Defender state, check for tamper protection, assess attacker context) |
| Affected Systems | `COMPROMISED-HOST-01` (10.10.10.103) |
| Chain | ◀ [AGC-067](../AGC-067-event-log-clearing/README.md) · next [AGC-069](../AGC-069-wazuh-agent-tamper/README.md) ▶ |
| One-line Summary | Attempted disabling of Windows Defender Real-Time Protection via `Set-MpPreference -DisableRealtimeMonitoring $true`. The PowerShell command reported success, but Windows 11 Tamper Protection overrode the change — RealTimeProtectionEnabled remained True after execution. No EID 5001 (Defender disabled event) was generated because the protection state did not actually change. The attempt itself was captured by Sysmon EID 1, demonstrating that even a failed defense evasion attempt is detectable. Tamper Protection functioned as designed, preventing the attacker from disabling endpoint protection despite having Administrator privileges. |

## Attacker Perspective

### Tradecraft

**What:** Turn off Windows Defender Real-Time Protection so later tooling, payload staging, and malware drops go unscanned. `Set-MpPreference -DisableRealtimeMonitoring $true` is the PowerShell call that switches off the real-time engine.

**Why an Attacker Uses It Here:**
- Real-time protection would detect and quarantine known-bad tools and payloads
- Disabling it opens a window to run tooling without Defender quarantining it
- On older Windows versions (pre-tamper protection), this command succeeds with local admin
- On a tamper-protected Windows 11 host like this one, the attempt still records intent even when it fails

**Tamper Protection (Windows 11):** Tamper Protection blocks changes to Defender's security settings even from processes running as Administrator. Here the attacker had full admin on COMPROMISED-HOST-01 and still could not switch real-time protection off through the standard API.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context
- Defender Real-Time Protection verified active (RealTimeProtectionEnabled: True)

**Execution:**
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

**Result:** Command returned without error, but Tamper Protection blocked the state change. A post-execution check showed RealTimeProtectionEnabled still True. No EID 5001 was written because protection never went off.

**Cleanup:** Defender re-enabled via `Set-MpPreference -DisableRealtimeMonitoring $false` (confirmed RealTimeProtectionEnabled: True).

## SOC Perspective

### Detection

**Sysmon EID 1 — PowerShell process executing disable command:**
```
Process Create:
UtcTime: 2026-09-15 23:14:58.340
ProcessGuid: {eb65e329-d172-6aa9-e504-000000001400}
ProcessId: 4224
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc068-sim.ps1
CurrentDirectory: C:\WINDOWS\system32\
User: COMPROMISED-01\Administrator
IntegrityLevel: High
```

**Windows Defender Operational Log — EID 5001: 0 events**
No EID 5001 was written because Tamper Protection blocked the state change. Without Tamper Protection, EID 5001 would be the primary artifact.

**Sysmon EID 13 — Registry value change: 0 events**
Sysmon recorded no registry write to `DisableRealtimeMonitoring`, which confirms Tamper Protection blocked it.

**Defender state transition:**
```
Before:  RealTimeProtectionEnabled = True
Command: Set-MpPreference -DisableRealtimeMonitoring $true (returned success)
After:   RealTimeProtectionEnabled = True (unchanged -- tamper protected)
```

### Investigation

**Step 1 — Assess the attempt vs. outcome:**
The attacker tried to disable Defender and Tamper Protection blocked it. The command returned no error, so the attacker had no sign it failed, but the protection state never changed. The attempt is logged and the defense held.

**Step 2 — Detection without EID 5001:**
With no EID 5001 to fire on, the attempt still surfaces through:
1. **Sysmon EID 1:** Any PowerShell process containing `Set-MpPreference` and `DisableRealtimeMonitoring` in its command line or script content
2. **PowerShell ScriptBlock Logging:** If enabled, captures the exact Set-MpPreference call
3. **Defender Tamper Protection events:** Windows may log tamper protection blocks in the Defender operational log
4. **Command-line auditing:** Security EID 4688 (if process creation auditing is enabled)

**Step 3 — Attacker context assessment:**
This attempt occurred on COMPROMISED-HOST-01, which has:
- Active C2 connectivity (AGC-051/055/056)
- Confirmed data exfiltration (AGC-062/063/066)
- Recent log clearing (AGC-067)
The disable attempt fits the post-exfiltration cleanup: the attacker is stripping defensive layers after finishing the primary objectives.

**Step 4 — What would have happened without Tamper Protection:**
On systems without Tamper Protection (Windows 10 older builds, Server 2016/2019, or systems with TP disabled), this command would:
- Disable Real-Time Protection
- Generate EID 5001 in the Defender Operational log
- Allow subsequent malware deployment and tool execution without AV interference
- Create a detection gap until protection was re-enabled

### Report

**Verdict: True Positive** — Deliberate attempt to disable endpoint protection on a compromised host.

**Confidence: Critical** — Tamper Protection blocked the disable, but the attempt stands on its own:
1. The intent is unambiguous (Set-MpPreference -DisableRealtimeMonitoring $true)
2. The attempt originated from a confirmed compromised host with active C2
3. The command ran as Administrator at High integrity
4. The attempt came right after the AGC-066 exfiltration and the AGC-067 log clear
5. There is no legitimate reason for the compromised account to disable Defender

**Response recommendation:**
1. **Verify Tamper Protection is enabled** on all endpoints — it is what stopped the disable here
2. **Alert on Set-MpPreference -DisableRealtimeMonitoring** in PowerShell command lines (Sysmon EID 1 / ScriptBlock Logging) whether or not the command succeeds
3. **Deploy detection rules** for Defender disable attempts that do NOT rely on EID 5001 — on tamper-protected hosts, EID 5001 fires only when the protection fails
4. **Investigate all recent PowerShell activity** on COMPROMISED-HOST-01 for further defense evasion attempts
5. **Isolate COMPROMISED-HOST-01** — log clearing followed by a defense-disable attempt means the attacker is cleaning up after finishing

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Defense Evasion (TA0005) | T1562.001 | Impair Defenses: Disable or Modify Tools | Set-MpPreference -DisableRealtimeMonitoring $true attempted. Tamper Protection blocked actual change. Sysmon EID 1 captured PowerShell process (PID 4224). No EID 5001 (protection state unchanged). Administrator context on confirmed C2 host. | Critical |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### Defender state verification

```
BEFORE ATTEMPT:
  RealTimeProtectionEnabled: True
  AntivirusEnabled:          True
  AMServiceEnabled:          True

DISABLE COMMAND:
  Time:     2026-09-15 23:15:00.277 UTC
  Command:  Set-MpPreference -DisableRealtimeMonitoring $true
  Result:   Command returned without error

AFTER ATTEMPT:
  RealTimeProtectionEnabled: True  (UNCHANGED -- Tamper Protection held)
  AntivirusEnabled:          True

CLEANUP:
  Time:     2026-09-15 23:15:27.519 UTC
  Command:  Set-MpPreference -DisableRealtimeMonitoring $false
  Final:    RealTimeProtectionEnabled: True
```

### Tamper Protection as a defensive control

```
Attack outcome:    BLOCKED by Tamper Protection
Detection outcome: DETECTED via Sysmon EID 1 (attempt logged)

Key insight: Tamper Protection decouples "attempt" from "success."
  - The attacker believes the command succeeded (no error returned)
  - The actual protection state is unchanged (defense holds)
  - The attempt is still logged (detection fires)

This is defense-in-depth working as designed:
  Prevention:  Tamper Protection blocks the state change
  Detection:   Sysmon captures the process that attempted the change
  Deception:   The attacker receives false success feedback
```
