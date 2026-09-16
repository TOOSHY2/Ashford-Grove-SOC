# AGC-067 — Security Event-Log Clearing

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

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

**What:** With credential access, lateral movement, and exfiltration done, the attacker clears the Windows Security event log to destroy the local record of the intrusion. `wevtutil cl Security` removes every entry and leaves a single EID 1102 that documents the clearing itself.

**Why an Attacker Uses It Here:**
- The Security log on COMPROMISED-HOST-01 holds the record of the whole chain: logons (4624), special privilege assignment (4672), and process-creation audit records
- Clearing it destroys the local timeline and leaves investigators dependent on the forwarded copy (Wazuh/SIEM)
- The clear follows the AGC-062 through AGC-066 exfiltration run — the attacker has the data and is now covering tracks
- `wevtutil` ships with Windows, so the attacker needs no extra tooling (living off the land)

**Irony of T1070.001:** Clearing the log writes the one event (EID 1102) that proves tampering. The attacker erases what happened but cannot hide that something was erased. The pre-clearing detail survives only where it was forwarded — the SIEM copy holds what the local log no longer does.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context
- Security log populated with 1000+ events from prior activity

**Execution:**
```cmd
wevtutil cl Security
```

**Result:** Security log cleared. 1000+ entries reduced to 1 (EID 1102). Sysmon logged the wevtutil.exe process creation in its own channel.

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
- **Logon ID:** 0x722BE0 — ties the clear to one logon session
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

**Cross-log correlation:** The LogonId (0x722BE0) on the Security EID 1102 matches the Sysmon EID 1, so one session ran wevtutil and produced the clear. Sysmon writes to its own channel (`Microsoft-Windows-Sysmon/Operational`), which `wevtutil cl Security` does not touch.

### Investigation

**Step 1 — Assess clearing scope:**
The Security log dropped from 1000+ events to exactly 1 (EID 1102). That is a full wipe; Windows offers no native way to delete individual Security events. Every logon record, privilege assignment, and audit entry on COMPROMISED-HOST-01 is gone locally.

**Step 2 — Identify what was destroyed:**
From the pre-clearing baseline, the Security log held:
- EID 4624 (successful logons) — every session on the host, the attacker's included
- EID 4672 (special privileges assigned) — the elevation trail
- EID 4799 (security-enabled group membership) — group enumeration
- Process creation audit events (if Security auditing was configured for this)
Their absence is itself evidence: the local log now begins at the EID 1102 entry and nothing before it survives on the host.

**Step 3 — Centralized log retention assessment:**
Wazuh was configured to receive forwarded events from COMPROMISED-HOST-01. Anything shipped before the clear sits in the central index, untouched by the local wipe. Reaching that copy would take separate access to the SIEM infrastructure.

**Lab constraint:** The Wazuh indexer was not responding during the execution window (port 9200 connection refused), so the central copy could not be checked live. A working SIEM would hold the full pre-clearing history.

**Step 4 — Timeline window analysis:**
```
Pre-clearing: 1000+ Security events (logon, privilege, audit)
23:07:10.340   wevtutil.exe cl Security executed
23:07:10       EID 1102 written (sole surviving entry)
Post-clearing: 1 event (EID 1102 only)
```
Everything between the last pre-clear event and EID 1102 is what the attacker wanted gone. The SIEM copy is where an analyst reads back exactly which events fell in that window.

**Step 5 — Cross-reference with FP twin (AGC-088):**
AGC-088 is the legitimate counterpart: scheduled log maintenance with change-control approval. What separates them:
- **AGC-067 (TP):** Unscheduled, no change control, performed from a compromised host with active C2
- **AGC-088 (FP):** Scheduled, documented maintenance window, performed by authorized IT staff

### Report

**Verdict: True Positive** — Deliberate destruction of forensic evidence via Security log clearing.

**Confidence: Critical** — five facts leave no other reading:
1. EID 1102 has no routine benign source; legitimate clearing happens only inside a pre-approved maintenance window
2. The clearing account is the local Administrator on a host with confirmed C2 (AGC-051/055/056)
3. The clear came after the full exfiltration run (AGC-062 through AGC-066)
4. Sysmon recorded the wevtutil.exe execution in a channel the clear did not touch
5. Complete log erasure (1000+ events to 1) — not a partial cleanup

**Response recommendation:**
1. **Preserve the Sysmon log immediately** — it is now the sole remaining local forensic record on COMPROMISED-HOST-01
2. **Pull all pre-clearing events from Wazuh/SIEM** before the attacker turns to the central store
3. **Lock down SIEM access** — the pre-clearing history there is the last copy of the evidence
4. **Reconstruct the attack timeline** from the SIEM copy: every Security event from COMPROMISED-HOST-01 that precedes EID 1102 is what the attacker tried to hide
5. **Escalate immediately** — log clearing right after exfiltration means the attacker is done and cleaning up

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
