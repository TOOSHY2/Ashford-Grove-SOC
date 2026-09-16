# AGC-040 — Service and Process Discovery

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-040` |
| Category | `06-discovery` — Discovery |
| MITRE Technique | `T1057` Process Discovery / `T1007` System Service Discovery |
| Verdict | True Positive |
| Confidence | Medium |
| Time to Detect | Immediate — Sysmon EID 1 captures `tasklist.exe` and `sc.exe` process creation |
| Time to Triage | 03:00 (cross-reference with subsequent defense evasion attempts targeting discovered security processes) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ [AGC-039](../AGC-039-group-enumeration/README.md) · next [AGC-041](../AGC-041-network-share-enum/README.md) ▶ |
| One-line Summary | Service and process enumeration burst: `tasklist`, `tasklist /svc`, `sc query`, `Get-Process`, `Get-Service` from Administrator context in 2 seconds. Discovered security stack: WinDefend (NOT_STOPPABLE), Sysmon64 (STOPPABLE), WazuhSvc (STOPPABLE). Intelligence gathered feeds directly into defense evasion planning. |

## Attacker Perspective

### Tradecraft

**What:** Process and service discovery maps what is running on the compromised host, with particular interest in:
- **Security tools** — antivirus (MsMpEng/WinDefend), EDR (Sysmon), SIEM agents (Wazuh) — to plan defense evasion
- **Administrative services** — remote management, backup agents — for persistence opportunities
- **Service stop-ability** — `sc query` reveals which services are STOPPABLE vs. NOT_STOPPABLE, directly informing whether a service can be disabled

The attacker is not listing processes for curiosity — they are scoping the security tooling before choosing a next move. This output feeds the defense evasion phase (AGC-067+).

**Why at this lifecycle stage:** With the host (AGC-037), domain (AGC-038), and privileged accounts (AGC-039) mapped, the attacker needs to know which defenses are active. It is the last discovery step before lateral movement or defense evasion. The question: "What is watching me, and can I turn it off?"

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Result |
|---|---|---|---|---|
| 1 | 2026-09-15 20:46:08 | tasklist | COMPROMISED-HOST-01 | 101 output lines, security processes: MpDefenderCoreService (3152), MsMpEng (3220), sysmon64 (3228) |
| 2 | 2026-09-15 20:46:09 | tasklist /svc | COMPROMISED-HOST-01 | Service-to-process mapping: MDCoreSvc->3152, WazuhSvc->3212, WinDefend->3220, Sysmon64->3228, SecurityHealthService->5936 |
| 3 | 2026-09-15 20:46:09 | sc query | COMPROMISED-HOST-01 | 73 services; WinDefend=NOT_STOPPABLE, Sysmon64=STOPPABLE, WazuhSvc=STOPPABLE |
| 4 | 2026-09-15 20:46:10 | Get-Process | COMPROMISED-HOST-01 | 98 processes; Wazuh agent at `C:\Program Files (x86)\ossec-agent\wazuh-agent.exe` |
| 5 | 2026-09-15 20:46:10 | Get-Service | COMPROMISED-HOST-01 | 248 services; security services all Running |

**Key intelligence gathered by attacker:**

| Service | Status | Stoppable | Attacker Implication |
|---|---|---|---|
| WinDefend (Defender AV) | Running | NO | Cannot be stopped via `sc stop`; requires tampering via registry/policy |
| Sysmon64 | Running | YES | Can be stopped or unloaded — high-value defense evasion target |
| WazuhSvc (SIEM agent) | Running | YES | Can be stopped — would blind the SOC to further activity |
| SecurityHealthService | Running | NO | Cannot be stopped via `sc stop` |
| mpssvc (Defender Firewall) | Running | N/A | Firewall rules can be modified without stopping the service |

**Cleanup:** No persistent artifacts. Commands are read-only.

## SOC Perspective

### Detection

**Sysmon EID 1 — Process Create (3 events in 2 seconds):**

| Timestamp (UTC) | Image | CommandLine | PID | User | IntegrityLevel |
|---|---|---|---|---|---|
| 2026-09-15 20:46:08 | tasklist.exe | `tasklist.exe` | 1960 | Administrator | High |
| 2026-09-15 20:46:09 | tasklist.exe | `tasklist.exe /svc` | 1732 | Administrator | High |
| 2026-09-15 20:46:09 | sc.exe | `sc.exe query` | 5844 | Administrator | High |

All share `LogonGuid: {eb65e329-ae90-6aa9-4e8a-560000000000}`, confirming single session.

`Get-Process` and `Get-Service` are PowerShell cmdlets that run in-process — no child executable, so no Sysmon EID 1. PowerShell script-block logging (EID 4104) would capture them, but the external tool invocations remain the primary detection.

### Investigation

**Step 1 — Assess the cluster pattern:**
Three process/service enumeration commands from one session within 2 seconds. As in AGC-037, the pattern (count + diversity + timing) is the indicator. But `tasklist` and `sc query` are everyday admin tools, so the pattern overlaps heavily with legitimate IT work.

**Step 2 — Forward correlation with defense evasion (critical):**
This detection earns its value from what comes after it. If the discovery is followed by:
- `sc stop Sysmon64` or `sc stop WazuhSvc` — direct defense evasion
- Registry modifications to disable Defender (`Set-MpPreference -DisableRealtimeMonitoring $true`)
- Process termination of security tools (`taskkill /f /im sysmon64.exe`)
- Sysmon driver unload (`fltmc unload SysmonDrv`)

...then discovery plus evasion is a much stronger signal than either alone. Check the same LogonGuid for any of these actions within the next 5-10 minutes.

**Step 3 — Account context:**
Administrator (RID-500) on a workstation. `tasklist` alone is routine, but pairing it with `sc query` and `tasklist /svc` maps service to process — the view an attacker needs to pick which service to stop, not the view a technician needs to fix a slow machine.

**Step 4 — Detection reuse:**
Same pattern as the AGC-037 burst rule: aggregate Sysmon EID 1 by LogonGuid, count process/service enumeration tools (`tasklist`, `sc.exe`, `wmic process`) within a sliding window. On its own the rule is low-value; correlated with later defense evasion it is high-value.

### Report

**Verdict: True Positive** — The Administrator account on COMPROMISED-HOST-01 enumerated processes and services as the fourth step of the discovery chain.

**Confidence: Medium** — Calibrated assessment:
1. `tasklist` and `sc query` are dual-use — IT staff run them daily. No single command is suspicious on its own.
2. The burst from the same session as AGC-037/038/039 adds chain context that lifts the signal.
3. Confidence stays Medium because routine system administration produces the same pattern. Raising it to High/Critical needs a confirmed defense evasion action against one of the security processes found here.
4. What the attacker learned (Sysmon64=STOPPABLE, WazuhSvc=STOPPABLE) is directly usable — if either service later stops, this discovery becomes a confirmed precursor.

**Response recommendation:**
1. **Correlate forward:** Check for defense evasion (service stops, process kills, registry changes) against WinDefend, Sysmon64, WazuhSvc, or SecurityHealthService from the same session within 10 minutes.
2. **If defense evasion is confirmed:** Isolate the host and escalate the incident. Discovery plus evasion from one session is not a troubleshooting pattern.
3. **If no follow-on evasion:** Log it in the discovery chain timeline; do not escalate on its own.
4. **Detection rule:** Alert on `tasklist /svc` OR `sc query` from a LogonGuid that already fired a discovery-burst alert (AGC-037 pattern). Requiring both cuts the false positives down to sessions worth looking at.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Discovery (TA0007) | T1057 | Process Discovery | Sysmon EID 1: `tasklist.exe` and `tasklist.exe /svc` executed by Administrator. 98 processes enumerated including security tools (MsMpEng, sysmon64, wazuh-agent). | Medium |
| Discovery (TA0007) | T1007 | System Service Discovery | Sysmon EID 1: `sc.exe query` executed by Administrator. 73 services enumerated. Security service stoppability mapped: Sysmon64=STOPPABLE, WazuhSvc=STOPPABLE, WinDefend=NOT_STOPPABLE. | Medium |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### Security processes discovered (tasklist)

```
MpDefenderCoreService.exe     3152 Services                   0     22,864 K
MsMpEng.exe                   3220 Services                   0    262,948 K
sysmon64.exe                  3228 Services                   0     21,768 K
```

### Security service mappings (tasklist /svc)

```
MpDefenderCoreService.exe     3152 MDCoreSvc
wazuh-agent.exe               3212 WazuhSvc
MsMpEng.exe                   3220 WinDefend
sysmon64.exe                  3228 Sysmon64
SecurityHealthService.exe     5936 SecurityHealthService
```

### Security service stoppability (sc query)

```
SERVICE_NAME: WinDefend
DISPLAY_NAME: Microsoft Defender Antivirus Service
        STATE              : 4  RUNNING
                                (NOT_STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)

SERVICE_NAME: Sysmon64
DISPLAY_NAME: Sysmon64
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)

SERVICE_NAME: WazuhSvc
DISPLAY_NAME: Wazuh
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, IGNORES_SHUTDOWN)
```

### Raw Sysmon EID 1 (tasklist)

```
Process Create:
UtcTime: 2026-09-15 20:46:08.713
ProcessId: 1960
Image: C:\Windows\System32\tasklist.exe
OriginalFileName: tasklist.exe
CommandLine: "C:\WINDOWS\system32\tasklist.exe"
User: COMPROMISED-01\Administrator
LogonGuid: {eb65e329-ae90-6aa9-4e8a-560000000000}
LogonId: 0x568A4E
IntegrityLevel: High
Hashes: MD5=8ADD46C82B40A6F635F1406CF28DABA1
```

### Raw Sysmon EID 1 (sc query)

```
Process Create:
UtcTime: 2026-09-15 20:46:09.953
ProcessId: 5844
Image: C:\Windows\System32\sc.exe
OriginalFileName: sc.exe
CommandLine: "C:\WINDOWS\system32\sc.exe" query
User: COMPROMISED-01\Administrator
LogonGuid: {eb65e329-ae90-6aa9-4e8a-560000000000}
LogonId: 0x568A4E
IntegrityLevel: High
Hashes: MD5=C8F632A326219F85927B3F33A13F7C7D
```
