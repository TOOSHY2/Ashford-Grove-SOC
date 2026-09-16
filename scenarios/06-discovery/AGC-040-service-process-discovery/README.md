# AGC-040 — Service and Process Discovery

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

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

The attacker is not just listing processes for awareness — they are performing security tool reconnaissance to plan their next move. The output of this discovery directly feeds the defense evasion phase (AGC-067+).

**Why at this lifecycle stage:** After mapping the host (AGC-037), domain (AGC-038), and privileged accounts (AGC-039), the attacker now needs to understand what defenses are active. This is the final discovery step before transitioning to either lateral movement or defense evasion. The key question: "What is watching me, and can I turn it off?"

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

Note: `Get-Process` and `Get-Service` are PowerShell cmdlets that execute in-process — they do not spawn separate executables and therefore do not generate Sysmon EID 1 events. PowerShell script-block logging (EID 4104) would capture these, but the key detection remains the external tool invocations.

### Investigation

**Step 1 — Assess the cluster pattern:**
Three process/service enumeration commands from the same session within 2 seconds. Like AGC-037, the pattern (count + diversity + timing) is the indicator. However, `tasklist` and `sc query` are common administrative and troubleshooting tools, so this pattern overlaps significantly with legitimate IT activity.

**Step 2 — Forward correlation with defense evasion (critical):**
The real value of this detection is what comes AFTER it. If process/service discovery is followed by:
- `sc stop Sysmon64` or `sc stop WazuhSvc` — direct defense evasion
- Registry modifications to disable Defender (`Set-MpPreference -DisableRealtimeMonitoring $true`)
- Process termination of security tools (`taskkill /f /im sysmon64.exe`)
- Sysmon driver unload (`fltmc unload SysmonDrv`)

...then the discovery + evasion combination is far stronger than either alone. Check the same LogonGuid for any of these actions within the next 5-10 minutes.

**Step 3 — Account context:**
Administrator (RID-500) on a workstation. While `tasklist` is commonly used for troubleshooting, the combination with `sc query` and `tasklist /svc` specifically maps the service-to-process relationship, which is more diagnostic of attacker tradecraft than routine troubleshooting.

**Step 4 — Detection reuse:**
This reuses the AGC-037 burst detection pattern: aggregate Sysmon EID 1 by LogonGuid, count process/service enumeration tools (`tasklist`, `sc.exe`, `wmic process`) within a sliding window. The detection is low-value in isolation but becomes high-value when correlated with subsequent defense evasion activity.

### Report

**Verdict: True Positive** — Process and service enumeration was executed from a compromised workstation by the Administrator account, as part of a documented discovery chain.

**Confidence: Medium** — Calibrated assessment:
1. `tasklist` and `sc query` are inherently dual-use — they are standard troubleshooting commands run daily by IT staff. No single command is suspicious in isolation.
2. The burst pattern from the same session as AGC-037/038/039 provides chain context that elevates the signal.
3. Confidence stays Medium because the same pattern is commonly generated by legitimate system administration. Elevation to High/Critical requires confirmed correlation with a subsequent defense evasion action targeting a security process discovered in this enumeration.
4. The specific intelligence gathered (Sysmon64=STOPPABLE, WazuhSvc=STOPPABLE) is directly actionable for defense evasion — if either service is subsequently stopped, this discovery becomes a confirmed precursor.

**Response recommendation:**
1. **Correlate forward:** Check for any defense evasion activity (service stops, process kills, registry changes) targeting WinDefend, Sysmon64, WazuhSvc, or SecurityHealthService from the same session within 10 minutes.
2. **If defense evasion is confirmed:** This discovery + evasion pair warrants immediate host isolation and incident escalation. The combined signal is far stronger than either alone.
3. **If no follow-on evasion:** Log as part of the discovery chain for timeline documentation but do not escalate independently.
4. **Detection rule:** Alert on `tasklist /svc` OR `sc query` from the same LogonGuid that also generated discovery-burst alerts (AGC-037 pattern). This cross-detection correlation dramatically reduces false positives.

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
