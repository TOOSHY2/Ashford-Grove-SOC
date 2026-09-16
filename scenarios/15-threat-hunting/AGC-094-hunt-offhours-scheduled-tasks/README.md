# AGC-094 — Proactive Hunt: Scheduled Tasks Created Outside Change Windows

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

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

The current Security log holds no EID 4698 events. That is expected: AGC-088 (the log retention policy scenario) cleared the Security log at approximately 01:00 UTC and took the historical task-creation audit events with it.

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

All 6 are Windows SoftLanding tasks (the content delivery/tips system), registered under two user SIDs. They are stock Windows tasks, not persistence.

**No scenario-planted tasks remain** — the cleanup steps in AGC-081, AGC-085, and AGC-088 removed every simulation task (AGC081Backup, AGC085NightlyReport, AGC088LogRotation).

##### Sysmon EID 1: schtasks.exe History

**9 schtasks.exe executions** in the Sysmon log, all from this session's scenarios:

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

All 9 schtasks.exe executions ran on **2026-09-16 (Wednesday)** between **00:32-01:00 UTC**, outside the documented change window, which covers only Tue and Thu. Every one traces to authorized lab scenario execution, not unauthorized persistence.

### Report

**Result: Hypothesis Confirmed (Residual Scenario Artifacts)** — Sysmon EID 1 history shows 9 scheduled-task operations outside the change-management window (Wednesday, against a Tue/Thu window). All trace to authorized lab scenario execution (AGC-081, AGC-085, AGC-088), and each scenario cleaned up its own task. No unauthorized scheduled-task persistence is active.

**Value of this hunt**: This hunt works wherever change-management windows are enforced, because the window itself is the baseline. Any `schtasks /create` or EID 4698 event outside the approved window with no matching emergency ticket goes straight to investigation under the AGC-020 playbook.

**Recommendation**: Add a SIEM correlation rule that alerts on EID 4698 events outside the documented change windows. Cross-reference each hit against the change-management ticketing system for approved emergency changes. Run the hunt query weekly to catch any task the real-time rule missed.

### MITRE Mapping

| Technique ID | Name | Tactic | Disposition |
|-------------|------|--------|-------------|
| T1053.005 | Scheduled Task/Job: Scheduled Task | Execution / Persistence | **Hunted** — 9 schtasks.exe operations detected outside change windows, all attributable to authorized lab scenario execution (AGC-081, AGC-085, AGC-088). All simulation tasks cleaned up. 6 remaining non-Microsoft tasks are legitimate Windows SoftLanding components. No unauthorized persistence found. |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
