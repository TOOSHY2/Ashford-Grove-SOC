# AGC-069 — Wazuh Agent Tampering (Silenced Telemetry)

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-069` |
| Category | `11-defense-evasion` — Defense Evasion |
| MITRE Technique | `T1562.001` Impair Defenses: Disable or Modify Tools |
| Verdict | True Positive |
| Confidence | Critical |
| Time to Detect | Wazuh manager agent-status check (absence of telemetry is the signal) |
| Time to Triage | 03:00 (verify agent state, assess silence window, check pre-disconnect activity) |
| Affected Systems | `COMPROMISED-HOST-01` (10.10.10.103) |
| Chain | ◀ [AGC-068](../AGC-068-defender-disabled/README.md) · next [AGC-070](../AGC-070-staged-artifact-deletion/README.md) ▶ |
| One-line Summary | Wazuh monitoring agent stopped via `net stop WazuhSvc` under Administrator context, creating a 15-second telemetry blackout during which the SIEM received no events from COMPROMISED-HOST-01. The agent status transitioned from Active to Disconnected on the Wazuh manager. Three Sysmon EID 1 events captured the stop command (powershell.exe, net.exe, net1.exe). The key insight: the absence of telemetry is itself the alert — the Wazuh manager detects the disconnection even though the compromised host cannot report it. This is the SIEM-layer equivalent of AGC-068's Defender disable, targeting centralized monitoring rather than local AV. |

## Attacker Perspective

### Tradecraft

**What:** Stop the Wazuh agent so COMPROMISED-HOST-01 forwards nothing to the SIEM. Log clearing (AGC-067) destroyed the history; stopping the agent keeps new evidence from leaving the host for as long as it stays down.

**Why an Attacker Uses It Here:**
- With the agent stopped, nothing done on the host during the window reaches the SIEM, so no rule can fire on it
- Paired with AGC-067 (Security log clearing), the attacker has now removed both the history and the live feed
- Paired with AGC-068 (Defender disable attempt), it is the third defensive layer the attacker has gone after
- Anything run during the silence window is recorded locally and nowhere else
- `net stop WazuhSvc` is one built-in command and needs only local admin

**Detection paradox:** The agent cannot report its own stop. The manager has to notice the missing keep-alives, so this detection works on absence rather than on an event arriving.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context
- Wazuh agent (WazuhSvc) verified Running with Automatic start type

**Execution:**
```cmd
net stop WazuhSvc
```

**Result:** "The Wazuh service was stopped successfully." Service went from Running to Stopped. Agent held down for the 15-second demonstration window, then restarted via `net start WazuhSvc`.

## SOC Perspective

### Detection

**Sysmon EID 1 — net.exe service stop command:**
```
Process Create:
UtcTime: 2026-09-15 23:17:59.407
ProcessGuid: {eb65e329-d227-6aa9-f204-000000001400}
ProcessId: 2016
Image: C:\Windows\System32\net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" stop WazuhSvc
User: COMPROMISED-01\Administrator
IntegrityLevel: High
LogonId: 0x74B2AC
```

**Sysmon EID 1 — net1.exe (child process):**
```
Process Create:
UtcTime: 2026-09-15 23:17:59.440
ProcessGuid: {eb65e329-d227-6aa9-f304-000000001400}
ProcessId: 2420
Image: C:\Windows\System32\net1.exe
CommandLine: C:\WINDOWS\system32\net1 stop WazuhSvc
User: COMPROMISED-01\Administrator
IntegrityLevel: High
LogonId: 0x74B2AC
```

**Sysmon EID 1 — PowerShell orchestration:**
```
Process Create:
UtcTime: 2026-09-15 23:17:58.682
ProcessGuid: {eb65e329-d226-6aa9-f104-000000001400}
ProcessId: 5864
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc069-sim.ps1
User: COMPROMISED-01\Administrator
```

**Wazuh Manager — Agent status transition:**
The Wazuh manager moved the agent from Active to Disconnected once keep-alives stopped arriving. That transition is the primary detection for agent tampering.

**Agent silence window:**
```
Agent stopped:    2026-09-15 23:17:59 UTC
Agent restarted:  2026-09-15 23:18:46 UTC
Silence duration: ~47 seconds (15-second intentional window + service start time)
```

### Investigation

**Step 1 — Absence detection pattern:**
Event-based detection fires when something arrives. This one fires on absence: the Wazuh manager notices that an agent that was Active has gone quiet. That takes:
- Periodic agent health checks on the manager
- Alerting on unexpected state transitions (Active to Disconnected)
- Telling a network drop apart from a deliberate service stop

**Step 2 — Pre-disconnect event analysis:**
The events forwarded before the agent went silent cover all prior scenario activity. Read the last ones to reach the SIEM before the disconnect — here they hold the run-up to the tampering: the AGC-067 log clear and the AGC-068 Defender attempt.

**Step 3 — Silence window risk assessment:**
During the 47-second silence window:
- No Security events were forwarded to the SIEM
- No Sysmon events were forwarded (though still logged locally on the endpoint)
- No file integrity monitoring (FIM) events were forwarded
- Anything done in this window shows up only in local logs, and the attacker has already shown a willingness to clear those (AGC-067)

**Step 4 — Systematic defense evasion pattern:**
This is the third defense evasion technique in sequence:
```
AGC-067: Security log clearing     (destroy historical evidence)
AGC-068: Defender disable          (remove local AV detection)
AGC-069: Wazuh agent stop          (blind centralized monitoring)
```
Together the three are one coordinated effort to blind every detection and forensic layer on COMPROMISED-HOST-01.

### Report

**Verdict: True Positive** — Deliberate SIEM agent tampering to create a monitoring blackout.

**Confidence: Critical** — the evidence lines up without gaps:
1. `net stop WazuhSvc` names the monitoring agent by service name
2. The command ran on a confirmed compromised host (active C2 since AGC-051)
3. It is the third defense evasion action in a row (AGC-067, AGC-068)
4. The 47-second silence window left the host unmonitored
5. There is no legitimate reason for the compromised account to stop the Wazuh agent

**Response recommendation:**
1. **Treat the silence window as an assumed-compromise period** — anything in those 47 seconds has to be rebuilt from local logs, if they survived AGC-067
2. **Investigate the host through an independent channel** — do not rely on the silenced agent; use a separate management interface or physical access
3. **Deploy agent self-protection** — run the Wazuh agent as a protected service (Windows PPL or service ACL restrictions) so non-SYSTEM accounts cannot stop it
4. **Implement agent health monitoring** — alert whenever an agent goes Active to Disconnected outside a scheduled maintenance window
5. **Correlate with AGC-067 and AGC-068** — three defense evasion actions in a row mean the attacker is cleaning up

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Defense Evasion (TA0005) | T1562.001 | Impair Defenses: Disable or Modify Tools | net stop WazuhSvc stopped monitoring agent. 3 Sysmon EID 1 events (powershell, net.exe, net1.exe). 47-second silence window. Active to Disconnected transition on manager. Administrator on confirmed C2 host. | Critical |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### Agent service state transition

```
BEFORE TAMPERING:
  Service:    Wazuh (WazuhSvc)
  Status:     Running
  StartType:  Automatic
  Agent:      Active (reporting to Wazuh manager)

TAMPERING ACTION:
  Time:       2026-09-15 23:17:59 UTC
  Command:    net stop WazuhSvc
  Result:     "The Wazuh service was stopped successfully."
  Process:    net.exe (PID 2016) -> net1.exe (PID 2420)
  LogonId:    0x74B2AC (Administrator session)

SILENCE WINDOW:
  Start:      2026-09-15 23:17:59 UTC
  End:        2026-09-15 23:18:46 UTC
  Duration:   ~47 seconds
  Impact:     Zero telemetry forwarded to SIEM

RECOVERY:
  Time:       2026-09-15 23:18:46 UTC
  Command:    net start WazuhSvc
  Final:      Running (agent reconnected to manager)
```

### Defense evasion trilogy (AGC-067 through AGC-069)

```
AGC-067: Clear Security log        --> Destroy forensic history
AGC-068: Disable Defender RTP       --> Remove local AV (blocked by Tamper Protection)
AGC-069: Stop Wazuh agent          --> Blind centralized monitoring

Combined effect: eliminate detection at every layer
  Local AV:       Defender (attempted disable, blocked)
  Local logs:     Security log (cleared)
  Central SIEM:   Wazuh agent (stopped)
  
Only Sysmon remains operational -- the attacker's next logical target.
```
