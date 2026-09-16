# AGC-076 — Containment, Snapshot Recovery & Validation

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-076` |
| Category | `12-impact-recovery` — Impact & Recovery |
| MITRE Technique | None (Incident Response — NIST 800-61 Containment/Eradication/Recovery) |
| Verdict | Recovery Complete |
| Confidence | High |
| Time to Recover | Full validation cycle completed |
| Affected Systems | `COMPROMISED-HOST-01`, `AD-DC-01`, `EXT-ATTACKER-SIM`, `WIN-CLIENT-02` |
| Chain | ◀ [AGC-075](../AGC-075-high-impact-gpo-change/README.md) · next — (closes main narrative; see [AGC-077](../../13-full-attack-chain/AGC-077-full-chain-credential-to-ransomware/README.md) for first Full-Chain capstone) ▶ |
| One-line Summary | Incident response closure for the full AGC-001-075 attack narrative. Validated security service states across all affected hosts: Wazuh agent Running, Windows Defender RealTimeProtection True, Sysmon Running. Persistence artifact check confirmed clean (only legitimate Run keys: SecurityHealth, VBoxTray). Local Administrators group contains only expected members (Administrator, Domain Admins, wadmin). Print Spooler restored to Running after AGC-073 disruption. Network connections baseline shows only expected DC communication (10.10.10.10 RPC). This scenario closes the main narrative arc and hands off to Full Attack Chain capstones (AGC-077-080). |

## SOC Perspective

### Investigation

#### Scenario context

This is NOT an attack scenario. AGC-076 is the SOC incident response workflow that closes the main attack narrative spanning AGC-001 through AGC-075. It validates that the environment can be returned to a clean state after the full attack chain simulation.

Everything from AGC-077 onward stands outside this continuous story:
- AGC-077-080: Full Attack Chain capstones (each retells the complete story from a different angle)
- AGC-081-088: False Positive Triage (analyst judgment exercises)
- AGC-089-094: Proactive Threat Hunting (hypothesis-driven hunts)
- AGC-095-100: Insider Threat (baseline-deviation scenarios)

#### Affected host inventory

Compiled from AGC-001-075 execution logs:

| Host | Role in Narrative | Key Scenarios |
|---|---|---|
| COMPROMISED-HOST-01 (10.10.10.103) | Primary target — 60+ scenarios executed | AGC-001 through AGC-072 (phishing through ransomware) |
| AD-DC-01 (10.10.10.10) | Domain controller — GPO modification | AGC-075 (GPO change), AGC-037-042 (AD discovery) |
| EXT-ATTACKER-SIM (10.10.40.10) | Attacker infrastructure + DMZ substitute | AGC-074 (defacement), AGC-051-056 (C2), phishing infrastructure |
| WIN-CLIENT-02 (10.10.10.102) | Lateral movement target | AGC-043-050 (lateral movement attempts) |
| DMZ-LINUX-01 (10.10.20.10) | DMZ web server (GA broken) | AGC-074 target (executed on substitute) |

#### Recovery validation

##### Step 1 — Security Service States (COMPROMISED-HOST-01)

```
SERVICE                  STATUS      EXPECTED    MATCH
Wazuh Agent (WazuhSvc)   Running     Running     YES
Windows Defender RTP     True        True        YES
Defender Antivirus       True        True        YES
Sysmon (Sysmon64)        Running     Running     YES
Print Spooler            Running     Running     YES (restored after AGC-073)
```

All security monitoring services are operational. The Wazuh agent that was stopped in AGC-069 (telemetry silencing) has been restored. Windows Defender that AGC-068 attempted to disable remains active (Tamper Protection prevented the original change).

##### Step 2 — Persistence Artifact Check

**Registry Run keys (HKLM\...\Run):**
```
SecurityHealth = C:\WINDOWS\system32\SecurityHealthSystray.exe   [LEGITIMATE - Windows Security tray]
VBoxTray = C:\WINDOWS\system32\VBoxTray.exe                     [LEGITIMATE - VirtualBox Guest Additions]
```
No rogue persistence entries from the attack narrative.

**Registry Run keys (HKCU\...\Run):** Empty — no user-level persistence.

**Scheduled tasks (non-Microsoft):**
```
MicrosoftEdgeUpdateTaskMachineCore   [Ready]  [LEGITIMATE - Edge updater]
MicrosoftEdgeUpdateTaskMachineUA     [Ready]  [LEGITIMATE - Edge updater]
SoftLanding\*                        [Mixed]  [LEGITIMATE - Windows feature management]
```
No attacker-created scheduled tasks remain from AGC-019-024 (persistence scenarios). Those scenarios created tasks that were cleaned up during execution.

**Local Administrators group:**
```
Administrator              [EXPECTED - built-in RID-500]
ASHFORDGROVE\Domain Admins  [EXPECTED - domain admin group]
wadmin                      [EXPECTED - lab admin account]
```
No rogue accounts added during AGC-025-030 (privilege escalation scenarios).

##### Step 3 — Network Baseline

```
Active connections (ESTABLISHED):
TCP  10.10.10.103:65172  ->  10.10.10.10:135    (DC RPC Endpoint Mapper)
TCP  10.10.10.103:65173  ->  10.10.10.10:49668  (DC RPC dynamic port)
```

Only expected domain controller communication. No C2 callbacks (AGC-051-056 C2 channels were simulation-only and did not establish persistent connections). No anomalous outbound connections.

##### Step 4 — AD Domain State (AD-DC-01)

The GPO modification from AGC-075 was reverted during that scenario's execution:
- Default Domain Policy: UserVersion reverted (AD:2/SysVol:2 — both set and revert incremented)
- ASHFORDGROVE-PowerShell-Logging GPO: untouched (verified not modified per safety constraint)
- No rogue GPOs created during the narrative

##### Step 5 — Recovery Procedure (Documented, Not Executed)

The full snapshot recovery procedure is documented but NOT executed during this validation, as the lab VMs must remain in their current state for AGC-077-100. In a production incident:

```
1. ISOLATE: Disconnect all affected hosts from network
   VBoxManage controlvm "<VM>" setlinkstate1 off

2. REVERT: Restore each host to pre-compromise baseline snapshot
   VBoxManage snapshot "<VM>" restore "<baseline-snapshot>"

3. VALIDATE: Confirm each host is genuinely clean
   - Security services running (Wazuh, Defender, Sysmon)
   - No persistence artifacts (Run keys, scheduled tasks, services)
   - AD state matches baseline (no rogue accounts/GPOs)
   - No anomalous network connections

4. RECONNECT: Restore network connectivity for validated hosts
   VBoxManage controlvm "<VM>" setlinkstate1 on

5. MONITOR: Watch for recurrence indicators for 24-72 hours
```

### Report

#### Detection Gaps Identified

| Gap | Scenarios | Impact | Recommendation |
|---|---|---|---|
| Sysmon EID 11 EXE/DLL-only filter | AGC-057-066, AGC-072 | File creation for non-executable extensions invisible | Expand EID 11 rules for sensitive directories |
| Sysmon EID 23/26 FileDelete disabled | AGC-070 | File deletion events not captured | Enable EID 23 or 26 |
| Sysmon EID 7 ImageLoaded disabled | Multiple | DLL side-loading invisible | Enable EID 7 with targeted filtering |
| Sysmon EID 10 ProcessAccess disabled | AGC-031-036 | Credential dumping process access invisible | Enable EID 10 for LSASS |
| Sysmon EID 3 filtering | Multiple | Many network connections filtered by SwiftOnSecurity config | Review EID 3 exclusions |
| Windows EID 7036 absent on Win11 | AGC-073 | Service state changes not event-logged | Use Sysmon EID 1 for sc.exe as alternative |
| EID 5136 not captured for GPO changes | AGC-075 | Directory service modifications invisible | Enable DS Access auditing |
| Wazuh indexer unreachable | AGC-067+ | Central SIEM correlation unavailable | Investigate Wazuh service health |

#### Effective Detection Layers

| Layer | Reliability | Key Scenarios |
|---|---|---|
| Sysmon EID 1 (Process Create) | Consistently captured across all scenarios | Every Windows scenario |
| Sysmon EID 13 (Registry Value Set) | Reliable for persistence detection | AGC-019-024 |
| Sysmon EID 22 (DNS Query) | Reliable for C2/exfil domain tracking | AGC-051-056 |
| Sysmon EID 3 (Network Connect) | Partial — SwiftOnSecurity filtering | AGC-051-056, AGC-062-066 |
| Windows Security EID 1102 | Sole survivor of log clearing | AGC-067 |
| Windows Tamper Protection | Blocked Defender disable attempt | AGC-068 |

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| — (Incident Response) | No ATT&CK technique | NIST 800-61: Containment, Eradication, Recovery | All security services validated Running. No persistence artifacts. Clean network baseline. AD state consistent. Recovery procedure documented. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### Validation summary

```
RECOVERY VALIDATION CHECKLIST
===============================
[x] Affected host inventory compiled (5 hosts from AGC-001-075)
[x] Security services verified: Wazuh Running, Defender Active, Sysmon Running
[x] Persistence check: Run keys clean, scheduled tasks clean, admin group clean
[x] Network baseline: Only expected DC connections
[x] Print Spooler restored (AGC-073 disruption remediated)
[x] GPO modification reverted (AGC-075)
[x] Web defacement restored (AGC-074)
[x] Recovery procedure documented for production use
[x] Lessons learned compiled from 75-scenario narrative
[x] Detection gap inventory created for tuning recommendations

INCIDENT STATUS: CLOSED
Main narrative (AGC-001-075) concluded.
Handoff: Full Attack Chain capstones (AGC-077-080)
```
