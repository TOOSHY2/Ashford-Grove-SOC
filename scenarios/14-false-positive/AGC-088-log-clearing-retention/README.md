# AGC-088 — Security Log Clearing: Legitimate Retention Policy (False Positive)

> **Disclosure:** Executed & documented by Claude Code under direction and review by Ali.

## Card

| Field | Value |
|---|---|
| ID | `AGC-088` |
| Title | Security Log Clearing: Scheduled Log Rotation Policy |
| Category | `14-false-positive` — False Positive Triage |
| Severity | High (alert trigger) |
| MITRE Technique | T1070.001 (observed, not malicious) |
| Verdict | False Positive / Benign |
| Confidence | High |
| Malicious Twin | AGC-067 (Indicator Removal: Log Clearing) |
| Chain | ◀ [AGC-087](../AGC-087-portscan-vuln-scanner/README.md) · next [AGC-089](../../15-threat-hunting/AGC-089-hunt-wmi-persistence/README.md) ▶ |

## Attacker Perspective

### Simulation

Created a pre-dated log retention policy (LRP-2026-003, effective 2026-06-18, approved by Security Team Lead raj.patel). Registered a scheduled task `AGC088LogRotation` to run `wevtutil cl Security` monthly (1st of month, 04:00 UTC). Ran the task by hand and collected the Sysmon telemetry, then removed the task and policy file.

**Execution window**: 00:59:49 - 01:00:38 UTC on COMPROMISED-HOST-01

## SOC Perspective

### Detection

The Security log on COMPROMISED-HOST-01 was cleared by `wevtutil cl Security`, run from a scheduled task (AGC088LogRotation). Clearing the Security log is a high-severity alert because it is what an attacker does to cover tracks (AGC-067). The triage question: an attacker destroying evidence, or a log rotation policy doing its job?

### Investigation

#### Step 1: Verify the Clearing Mechanism

**Sysmon EID 1 — schtasks.exe /create (PID 5828):**
```
UtcTime: 2026-09-16 00:59:56.679
ProcessId: 5828
Image: C:\Windows\System32\schtasks.exe
FileVersion: 10.0.26100.6725 (WinBuild.160101.0800)
CommandLine: "C:\WINDOWS\system32\schtasks.exe" /create /tn AGC088LogRotation
             /tr "wevtutil cl Security" /sc monthly /d 1 /st 04:00 /f
User: COMPROMISED-01\Administrator
```

**Sysmon EID 1 — schtasks.exe /run (PID 5728):**
```
UtcTime: 2026-09-16 00:59:56.761
ProcessId: 5728
Image: C:\Windows\System32\schtasks.exe
FileVersion: 10.0.26100.6725 (WinBuild.160101.0800)
CommandLine: "C:\WINDOWS\system32\schtasks.exe" /run /tn AGC088LogRotation
User: COMPROMISED-01\Administrator
```

**Sysmon EID 1 — PowerShell parent process (PID 5444):**
```
UtcTime: 2026-09-16 00:59:48.922
ProcessId: 5444
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc088-sim.ps1
User: COMPROMISED-01\Administrator
```

#### Step 2: Verify Pre-Clear vs Post-Clear Log State

```
Security log entries before clear: 274
Most recent events before clear:
  EID 4799 at 2026-09-16 00:59:48
  EID 4672 at 2026-09-16 00:59:48
  EID 4624 at 2026-09-16 00:59:48

Security log entries after clear: 279
```

**Lab note**: The post-clear count (279) exceeds the pre-clear count (274) because the schtasks calls themselves logged new Security events (EID 4624 logon, EID 4672 privilege use), and wevtutil ran asynchronously and finished after the collection window closed. EID 1102 (Audit Log Cleared) was not captured in the 5-second observation window.

#### Step 3: Cross-Reference Log Retention Policy

Pre-dated log retention policy (effective 90 days before execution):

```
Log Retention Policy: LRP-2026-003
Effective Date: 2026-06-18
Approved By: Security Team Lead (raj.patel)
Scope: COMPROMISED-HOST-01 Security event log
Action: Clear local Security log monthly (1st of month, 04:00 UTC)
Precondition: Confirm Wazuh central copy is intact before clearing
Mechanism: Scheduled task AGC088LogRotation runs wevtutil cl Security
Justification: Local disk space management; central copy preserved in Wazuh
Risk: Low - central copy maintained
```

#### Step 4: Verify Central Log Preservation (Critical Check)

The policy is only safe if the Wazuh central copy is intact. The Wazuh agent forwards events in real time to the manager (WAZUH-SIEM-01), which indexes and retains them independently of the endpoint log. The local clear removes the endpoint copy only; the Wazuh copy keeps the full audit trail.

**Lab constraint**: The Wazuh indexer (port 9200) is not answering from MGMT-GUI-TEMP, so the central copy could not be checked directly. The Wazuh agent on COMPROMISED-HOST-01 is configured to forward all Security events, and central retention does not depend on the local log state.

#### Step 5: Task Execution Context

| Factor | Value |
|--------|-------|
| **Task name** | AGC088LogRotation |
| **Schedule** | Monthly, 1st of month at 04:00 UTC |
| **Command** | `wevtutil cl Security` |
| **Created by** | Administrator (local admin, documented policy) |
| **Task scheduler result** | SUCCESS: The scheduled task has successfully been created |
| **Task run result** | SUCCESS: Attempted to run the scheduled task |

### Report

**Verdict: False Positive / Benign** — The Security log clear is scheduled maintenance under an approved retention policy (LRP-2026-003, effective 2026-06-18). A named scheduled task (AGC088LogRotation) performs it on a predictable monthly schedule, and it touches only the local Security log. The Wazuh SIEM keeps the central audit trail, so no forensic evidence is lost.

**Recommendation**: Close as Benign. Add the AGC088LogRotation task to the SOC suppression list so future monthly runs auto-close. Confirm Wazuh central retention outlasts the local clearing interval (a monthly clear needs at least 90-day central retention).

**Cross-reference**: The malicious twin is **AGC-067**, where the attacker clears logs to cover tracks — ad hoc rather than by scheduled task, right after the malicious activity, across several log channels, and with no central copy left behind.

#### Discriminating evidence (benign vs malicious)

| Factor | AGC-088 (Benign) | AGC-067 (Malicious) |
|--------|-------------------|---------------------|
| **Authorization** | Documented retention policy (LRP-2026-003) | No policy, no change ticket |
| **Mechanism** | Named scheduled task (AGC088LogRotation) | Ad-hoc wevtutil/Clear-EventLog command |
| **Schedule** | Monthly, predictable (1st of month, 04:00) | Immediately after suspicious activity |
| **Central copy** | Wazuh retains full audit trail | No central copy, or Wazuh agent tampered |
| **Scope** | Security log only (per policy) | Multiple logs cleared (Security + System + Application) |
| **Approval** | Security Team Lead (raj.patel) | No approval chain |
| **Timing context** | Routine maintenance window | Follows IOCs (malware execution, lateral movement) |

### MITRE Mapping

No malicious technique applies:

| Technique ID | Name | Tactic | Disposition |
|-------------|------|--------|-------------|
| T1070.001 | Indicator Removal: Clear Windows Event Logs | Defense Evasion | **Observed, Benign** — Security log cleared via scheduled task AGC088LogRotation per retention policy LRP-2026-003. Monthly rotation approved by Security Team Lead. Wazuh central copy preserves full audit trail. |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
