# AGC-094 — Proactive Hunt: Scheduled Tasks Created Outside Change Windows

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-094` |
| Title | Hunt: Scheduled Task Creation Outside Change-Management Hours |
| Category | `15-threat-hunting` — Proactive Threat Hunting |
| Hunt Type | Hypothesis-Driven (Policy Compliance) |
| MITRE Technique | T1053.005 (Scheduled Task) |
| Hunt Result | Hypothesis Confirmed (Residual Scenario Artifacts) |
| Related Scenarios | AGC-020, AGC-081, AGC-085, AGC-088 |
| Chain | ◀ [AGC-093](../AGC-093-hunt-dns-entropy/README.md) · next [AGC-095](../../16-insider-threat/AGC-095-unusual-file-access/README.md) ▶ |

## SOC Perspective

### Hypothesis

*Stated before any query was executed:*

> If an adversary has created persistence via scheduled tasks, the task creation events (EID 4698) will fall outside the documented change-management windows (Tue/Thu 22:00-02:00 UTC), and the task definitions will not match any approved change ticket.

### Investigation

#### Methodology

**Data sources**:
1. Windows Security EID 4698 (Scheduled Task Created)
2. Current non-Microsoft scheduled tasks via `Get-ScheduledTask`
3. Sysmon EID 1 for `schtasks.exe` execution history

**Scope**: COMPROMISED-HOST-01

**Execution window**: 01:09:52 - 01:10:27 UTC

#### Results

##### EID 4698 (Task Created Events)

```
Total EID 4698 events: 0
```

No EID 4698 events present in the current Security log. This is expected because the Security log was cleared during AGC-088 (log retention policy scenario) at approximately 01:00 UTC, removing historical task creation audit events.

##### Current Non-Microsoft Scheduled Tasks

**6 tasks found** — all in the `\SoftLanding\` path:

| Task Name | State | Assessment |
|-----------|-------|------------|
| SoftLandingCreativeManagementTask (SID ...1105) | Ready | **Benign** — Windows SoftLanding (Spotlight/Tips feature) |
| SoftLandingDeferralTask (SID ...1105) | Ready | **Benign** — Windows SoftLanding |
| SoftLandingTriggerTask (SID ...1105) | Disabled | **Benign** — Windows SoftLanding |
| SoftLandingCreativeManagementTask (SID ...1000) | Ready | **Benign** — Windows SoftLanding |
| SoftLandingDeferralTask (SID ...1000) | Ready | **Benign** — Windows SoftLanding |
| SoftLandingTriggerTask (SID ...1000) | Disabled | **Benign** — Windows SoftLanding |

All 6 tasks are Windows SoftLanding tasks (content delivery/tips system), present under two user SIDs. These are legitimate Windows system tasks and not persistence mechanisms.

**No scenario-planted tasks remain** — the cleanup steps in AGC-081, AGC-085, and AGC-088 successfully removed all simulation tasks (AGC081Backup, AGC085NightlyReport, AGC088LogRotation).

##### Sysmon EID 1: schtasks.exe History

**9 schtasks.exe executions** found in Sysmon log, all from current session scenarios:

| Timestamp (UTC) | Command | Assessment |
|-----------------|---------|------------|
| 00:32:49 | `/create /tn AGC081Backup /tr "powershell.exe -EncodedCommand ..."` | AGC-081 scenario (cleaned up) |
| 00:32:49 | `/run /tn AGC081Backup` | AGC-081 execution |
| 00:33:08 | `/delete /tn AGC081Backup /f` | AGC-081 cleanup |
| 00:49:27 | `/create /tn AGC085NightlyReport /tr "cmd.exe /c echo ..." /ru svc_reporting` | AGC-085 scenario (cleaned up) |
| 00:49:27 | `/run /tn AGC085NightlyReport` | AGC-085 execution |
| 00:50:28 | `/delete /tn AGC085NightlyReport /f` | AGC-085 cleanup |
| 00:59:56 | `/create /tn AGC088LogRotation /tr "wevtutil cl Security"` | AGC-088 scenario (cleaned up) |
| 00:59:56 | `/run /tn AGC088LogRotation` | AGC-088 execution |
| 01:00:38 | `/delete /tn AGC088LogRotation /f` | AGC-088 cleanup |

##### Change-Window Compliance Check

Documented change-management window: **Tue/Thu 22:00-02:00 UTC**

All 9 schtasks.exe executions occurred on **2026-09-16 (Wednesday)** between **00:32-01:00 UTC** — outside the documented change window (the window covers only Tue and Thu). However, all are attributable to lab scenario execution (authorized testing activity), not unauthorized persistence.

### Report

**Result: Hypothesis Confirmed (Residual Scenario Artifacts)** — The Sysmon EID 1 history reveals 9 scheduled task operations outside the documented change-management window (Wednesday vs. Tue/Thu window). All are attributable to authorized lab scenario execution (AGC-081, AGC-085, AGC-088) and were properly cleaned up after each scenario. No unauthorized persistence via scheduled tasks is currently active.

**Value of this hunt**: The off-hours task creation hunt is highly effective in production environments where change-management policies are enforced. Any `schtasks /create` or EID 4698 event outside the approved window without a matching emergency ticket warrants immediate investigation per the AGC-020 playbook.

**Recommendation**: Add scheduled task creation monitoring to the SIEM correlation rules. Alert on EID 4698 events that fall outside documented change windows. Cross-reference against the change management system (ticketing) for approved emergency changes. Schedule weekly hunt queries to catch any tasks that evaded real-time detection.

### MITRE Mapping

| Technique ID | Name | Tactic | Disposition |
|-------------|------|--------|-------------|
| T1053.005 | Scheduled Task/Job: Scheduled Task | Execution / Persistence | **Hunted** — 9 schtasks.exe operations detected outside change windows, all attributable to authorized lab scenario execution (AGC-081, AGC-085, AGC-088). All simulation tasks cleaned up. 6 remaining non-Microsoft tasks are legitimate Windows SoftLanding components. No unauthorized persistence found. |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
