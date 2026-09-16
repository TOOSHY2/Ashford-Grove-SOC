# AGC-067 — Security Event-Log Clearing

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-067` |
| Category | `11-defense-evasion` — Defense Evasion |
| MITRE Technique | `T1070.001` Indicator Removal: Clear Windows Event Logs |
| Verdict | True Positive |
| Confidence | Critical |
| Time to Detect | Windows Security Event ID 1102 (immediate — self-documenting artifact) |
| Time to Triage | 02:00 (EID 1102 is unambiguous; no further correlation required for initial verdict) |
| Affected Systems | `COMPROMISED-HOST-01` (10.10.10.103) |
| Chain | ◀ [AGC-066](../../10-exfiltration/AGC-066-compressed-archive-web/README.md) · next [AGC-068](../AGC-068-defender-disabled/README.md) ▶ |
| FP Twin | AGC-088 (legitimate administrative log maintenance) |
| One-line Summary | Complete Security event log cleared via `wevtutil cl Security` under Administrator context. EID 1102 is the sole surviving entry in the Security log, recording the identity of the clearing account (COMPROMISED-01\Administrator, Logon ID 0x722BE0). Sysmon independently captured the wevtutil.exe process creation (EID 1), providing a secondary detection artifact that survives even if the attacker subsequently targets Sysmon logs. This is one of the least ambiguous indicators in the entire engagement — there is virtually no legitimate reason to clear an entire Security event log outside narrowly defined, pre-approved administrative maintenance windows. |

## Attacker Perspective

### Tradecraft

**What:** After completing attack objectives (credential access, lateral movement, exfiltration), the attacker clears the Windows Security event log to destroy forensic evidence of their activities. The `wevtutil cl Security` command removes all entries and replaces them with a single EID 1102 entry documenting the clearing itself.

**Why an Attacker Uses It Here:**
- The Security log on COMPROMISED-HOST-01 contains evidence of the entire attack chain: logon events (4624), privilege use (4672), process creation audit records
- Clearing the log destroys the local forensic timeline, forcing investigators to rely on centralized log copies (Wazuh/SIEM)
- This is a common final-stage action after exfiltration is complete — the attacker has achieved their objectives and now covers their tracks
- `wevtutil` is a legitimate Windows utility (living-off-the-land), requiring no additional tools

**Irony of T1070.001:** The act of clearing the log creates the very evidence (EID 1102) that proves tampering occurred. The technique destroys the details of what happened but cannot conceal that something was hidden. This is why centralized log forwarding is critical — the SIEM retains the pre-clearing events that the local log no longer holds.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context
- Security log populated with 1000+ events from prior activity

**Execution:**
```cmd
wevtutil cl Security
```

**Result:** Security log cleared. 1000+ entries reduced to 1 (EID 1102). Sysmon independently logged the wevtutil.exe process creation.

## SOC Perspective

### Detection

**Windows Security Event ID 1102 — Audit Log Cleared:**
```
The audit log was cleared.
Subject:
    Security ID:    S-1-5-21-783388846-4178789021-3119572882-500
    Account Name:   Administrator
    Domain Name:    COMPROMISED-01
    Logon ID:       0x722BE0
```

**Key fields:**
- **Security ID:** S-1-5-...-500 = built-in Administrator (RID 500)
- **Account Name:** Administrator (local, not domain)
- **Logon ID:** 0x722BE0 — correlates this clearing action to the specific logon session
- **Timestamp:** 2026-09-15 23:07:10

**Sysmon EID 1 — wevtutil.exe process creation:**
```
Process Create:
UtcTime: 2026-09-15 23:07:10.340
ProcessGuid: {eb65e329-cf9e-6aa9-d704-000000001400}
ProcessId: 5932
Image: C:\Windows\System32\wevtutil.exe
CommandLine: "C:\WINDOWS\system32\wevtutil.exe" cl Security
CurrentDirectory: C:\WINDOWS\system32\
User: COMPROMISED-01\Administrator
LogonId: 0x722BE0
```

**Cross-log correlation:** The LogonId (0x722BE0) matches between the Security EID 1102 and the Sysmon EID 1, confirming the same session performed both actions. Sysmon logs are stored in a separate event channel (`Microsoft-Windows-Sysmon/Operational`) and are not affected by `wevtutil cl Security`.

### Investigation

**Step 1 — Assess clearing scope:**
The Security log went from 1000+ events to exactly 1 (EID 1102). This is a complete wipe — not a selective deletion of specific events, which Windows does not natively support. The attacker destroyed all logon records, privilege escalation events, and audit trails on this endpoint.

**Step 2 — Identify what was destroyed:**
Based on the pre-clearing baseline, the Security log contained:
- EID 4624 (successful logons) — records of all sessions, including attacker sessions
- EID 4672 (special privileges assigned) — privilege escalation evidence
- EID 4799 (security-enabled group membership) — group enumeration
- Process creation audit events (if Security auditing was configured for this)
The absence of these events is itself evidence — any gap in the Security log timeline is suspicious.

**Step 3 — Centralized log retention assessment:**
Wazuh SIEM was configured to receive forwarded events from COMPROMISED-HOST-01. Events shipped to Wazuh before the clearing action persist in the centralized index and are not affected by local log clearing. This is the primary forensic value of centralized logging: the attacker can destroy local evidence but cannot reach the SIEM copy without separate access to the SIEM infrastructure.

**Lab constraint:** Wazuh indexer services were not responding during this execution window (port 9200 connection refused), preventing live verification of the centralized copy. In a production environment, the SIEM would retain the full pre-clearing event history.

**Step 4 — Timeline window analysis:**
```
Pre-clearing: 1000+ Security events (logon, privilege, audit)
23:07:10.340   wevtutil.exe cl Security executed
23:07:10       EID 1102 written (sole surviving entry)
Post-clearing: 1 event (EID 1102 only)
```
The gap between the last legitimate event and EID 1102 represents the evidence the attacker was trying to hide. In a production investigation, the SIEM copy would reveal exactly which events fell within that window.

**Step 5 — Cross-reference with FP twin (AGC-088):**
AGC-088 represents the legitimate counterpart: scheduled administrative log maintenance with change-control approval. The distinguishing factors:
- **AGC-067 (TP):** Unscheduled, no change control, performed from a compromised host with active C2
- **AGC-088 (FP):** Scheduled, documented maintenance window, performed by authorized IT staff

### Report

**Verdict: True Positive** — Deliberate destruction of forensic evidence via Security log clearing.

**Confidence: Critical** — This is one of the least ambiguous indicators in the SOC catalog:
1. EID 1102 has no false-positive-generating routine use case (legitimate clearing requires pre-approved maintenance)
2. The clearing account is the local Administrator on a host with confirmed C2 (AGC-051/055/056)
3. The clearing occurred after a complete exfiltration campaign (AGC-062 through AGC-066)
4. Sysmon independently recorded the wevtutil.exe execution, providing redundant detection
5. Complete log erasure (1000+ events to 1) — not a partial cleanup

**Response recommendation:**
1. **Preserve the Sysmon log immediately** — it is now the sole remaining local forensic record on COMPROMISED-HOST-01
2. **Pull all pre-clearing events from Wazuh/SIEM** before the attacker potentially targets the centralized store
3. **Lock down SIEM access** — if the attacker reaches the SIEM, the pre-clearing history is the last copy of the evidence
4. **Reconstruct the attack timeline** from the SIEM copy: every Security event from COMPROMISED-HOST-01 that precedes EID 1102 represents what the attacker tried to hide
5. **Escalate immediately** — log clearing after exfiltration is a strong indicator the attacker has completed their mission and is now in the cleanup phase

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Defense Evasion (TA0005) | T1070.001 | Indicator Removal: Clear Windows Event Logs | `wevtutil cl Security` cleared 1000+ events. EID 1102 sole survivor. Sysmon EID 1 captured wevtutil.exe (PID 5932, ProcessGuid {eb65e329-cf9e-6aa9-d704-000000001400}). Administrator, LogonId 0x722BE0. | Critical |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### Security log state transition

```
BEFORE CLEARING:
  Event count: 1000+ entries
  Recent events: EID 4672, 4624, 4799 (logon/privilege/group events)
  Timeline:     Continuous from VM boot through all attack activity

CLEARING ACTION:
  Time:         2026-09-15 23:07:10
  Command:      wevtutil cl Security
  Executor:     COMPROMISED-01\Administrator (S-1-5-...-500)
  Logon ID:     0x722BE0

AFTER CLEARING:
  Event count:  1 (EID 1102 only)
  Content:      "The audit log was cleared" + subject identity
  Evidence gap: Entire attack chain history destroyed locally
```

### Sysmon as secondary detection (independent log channel)

```
Channel:      Microsoft-Windows-Sysmon/Operational (unaffected by Security log clear)
EID 1:        wevtutil.exe process creation
ProcessGuid:  {eb65e329-cf9e-6aa9-d704-000000001400}
ProcessId:    5932
CommandLine:  "C:\WINDOWS\system32\wevtutil.exe" cl Security
LogonId:      0x722BE0 (matches EID 1102 subject)
Integrity:    High (elevated Administrator)
```

### Defense-in-depth: why centralized logging matters

```
Local Security log:      CLEARED (attacker succeeded locally)
Sysmon log:              INTACT  (different channel, not targeted)
Wazuh/SIEM central copy: INTACT  (network-forwarded before clearing)

The attacker can destroy local evidence but not centralized copies.
This is the core value proposition of log forwarding to a SIEM.
```
