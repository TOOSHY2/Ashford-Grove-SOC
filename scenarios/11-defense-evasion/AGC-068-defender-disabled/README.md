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

**What:** Disable Windows Defender Real-Time Protection to prevent detection of subsequent malicious activities (malware deployment, tool execution, payload staging). `Set-MpPreference -DisableRealtimeMonitoring $true` is the PowerShell method to turn off the real-time scanning engine.

**Why an Attacker Uses It Here:**
- Real-time protection would detect and quarantine known-bad tools and payloads
- Disabling it creates a window where the attacker can operate without AV interference
- On older Windows versions (pre-tamper protection), this command succeeds with local admin
- Even on modern Windows, the attempt reveals attacker intent regardless of success

**Tamper Protection (Windows 11):** Microsoft introduced Tamper Protection to prevent unauthorized changes to security settings, even by processes running as Administrator. This lab demonstrates the defensive value: the attacker has full admin access but cannot disable the endpoint protection through standard API calls.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context
- Defender Real-Time Protection verified active (RealTimeProtectionEnabled: True)

**Execution:**
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
```

**Result:** Command returned without error, but Tamper Protection prevented the actual state change. Post-execution verification confirmed RealTimeProtectionEnabled remained True. No EID 5001 was generated (the protection was never actually disabled).

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
No EID 5001 was generated because Tamper Protection prevented the actual state change. In environments without Tamper Protection, EID 5001 would be the primary detection artifact.

**Sysmon EID 13 — Registry value change: 0 events**
No registry modification to `DisableRealtimeMonitoring` was recorded, confirming Tamper Protection blocked the write.

**Defender state transition:**
```
Before:  RealTimeProtectionEnabled = True
Command: Set-MpPreference -DisableRealtimeMonitoring $true (returned success)
After:   RealTimeProtectionEnabled = True (unchanged -- tamper protected)
```

### Investigation

**Step 1 — Assess the attempt vs. outcome:**
The critical distinction: the attacker attempted to disable Defender but was blocked by Tamper Protection. The command returned no error (misleading the attacker into believing it succeeded), but the actual protection state did not change. This is a defensive win — the attempt is logged but the defense held.

**Step 2 — Detection without EID 5001:**
Without the traditional EID 5001 detection, the attempt is still detectable through:
1. **Sysmon EID 1:** Any PowerShell process containing `Set-MpPreference` and `DisableRealtimeMonitoring` in its command line or script content
2. **PowerShell ScriptBlock Logging:** If enabled, would capture the exact Set-MpPreference call
3. **Defender Tamper Protection events:** Windows may log tamper protection blocks in the Defender operational log
4. **Command-line auditing:** Security EID 4688 (if process creation auditing is enabled)

**Step 3 — Attacker context assessment:**
This attempt occurred on COMPROMISED-HOST-01, which has:
- Active C2 connectivity (AGC-051/055/056)
- Confirmed data exfiltration (AGC-062/063/066)
- Recent log clearing (AGC-067)
The Defender disable attempt fits the post-exfiltration cleanup pattern: the attacker is attempting to remove defensive layers after completing primary objectives.

**Step 4 — What would have happened without Tamper Protection:**
On systems without Tamper Protection (Windows 10 older builds, Server 2016/2019, or systems with TP disabled), this command would:
- Successfully disable Real-Time Protection
- Generate EID 5001 in the Defender Operational log
- Allow subsequent malware deployment and tool execution without AV interference
- Create a detection gap until protection was re-enabled

### Report

**Verdict: True Positive** — Deliberate attempt to disable endpoint protection on a compromised host.

**Confidence: Critical** — Despite Tamper Protection preventing the actual disable:
1. The intent to disable defense is unambiguous (Set-MpPreference -DisableRealtimeMonitoring $true)
2. The attempt originated from a confirmed compromised host with active C2
3. Administrator privileges were used, indicating elevated access
4. The attempt follows the post-exfiltration cleanup pattern (after AGC-066 exfiltration and AGC-067 log clearing)
5. There is no legitimate reason for the compromised account to disable Defender

**Response recommendation:**
1. **Verify Tamper Protection is enabled** on all endpoints — it prevented the actual disable here
2. **Alert on Set-MpPreference -DisableRealtimeMonitoring** in PowerShell command lines (Sysmon EID 1 / ScriptBlock Logging) as a high-confidence indicator, regardless of whether the command succeeds
3. **Deploy detection rules** for Defender disable attempts that do NOT rely on EID 5001 — on tamper-protected systems, the traditional detection fires only when tamper protection fails
4. **Investigate all recent PowerShell activity** on COMPROMISED-HOST-01 for additional defense evasion attempts
5. **Isolate COMPROMISED-HOST-01** — the attacker is in the cleanup phase (log clearing + defense disable), indicating objectives are complete

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
