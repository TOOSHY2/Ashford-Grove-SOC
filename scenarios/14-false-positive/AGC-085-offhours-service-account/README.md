# AGC-085: Off-Hours Logon -- Scheduled Task Under Service Account (False Positive)

## Scenario Overview

| Field              | Value                                                        |
|--------------------|--------------------------------------------------------------|
| **Scenario ID**    | AGC-085                                                      |
| **Title**          | Off-Hours Logon: Scheduled Task Under Service Account        |
| **Category**       | False Positive Triage (14-false-positive)                    |
| **Severity**       | Medium (alert trigger)                                       |
| **MITRE Techniques** | T1078 (observed, not malicious)                            |
| **Verdict**        | False Positive / Benign                                      |
| **Confidence**     | High                                                         |
| **Malicious Twin** | AGC-008 (Off-Hours Phishing Victim Logon)                    |

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

**Navigation:** [< AGC-084](../../14-false-positive/AGC-084-dns-beacon-saas/README.md) | [AGC-086 >](../../14-false-positive/AGC-086-regulatory-submission/README.md)

## Alert / Trigger

An off-hours authentication event for account `svc_reporting` detected on COMPROMISED-HOST-01. The scheduled task `AGC085NightlyReport` is configured to run daily at 03:00 UTC under the `svc_reporting` service account. Off-hours authentication alerts fire identically regardless of whether the account is a human user or a service account, creating one of the most common false positive patterns in SOC operations.

## Simulation Summary

Created a documented service account (`svc_reporting`) with a pre-existing service account registry entry (created 2026-08-17, approved by IT Operations). Registered a scheduled task (`AGC085NightlyReport`) to run under this account at 03:00 daily, then triggered it manually to simulate the off-hours execution.

**Lab constraint**: The `svc_reporting` account was created without "Log on as a batch job" privilege (requires Local Security Policy modification not available via guestcontrol). The scheduled task registered successfully but the batch logon event (EID 4624 Type 4) did not fire. Evidence is based on the schtasks creation/execution telemetry and account creation events.

**Execution window**: 00:49:26 - 00:49:27 UTC on COMPROMISED-HOST-01

## Investigation

### Step 1: Identify the Off-Hours Activity

**Sysmon EID 1 -- schtasks.exe task creation (PID 3028):**
```
UtcTime: 2026-09-16 00:49:27.093
ProcessId: 3028
Image: C:\Windows\System32\schtasks.exe
CommandLine: "C:\WINDOWS\system32\schtasks.exe" /create /tn AGC085NightlyReport /tr "cmd.exe /c echo AGC-085 nightly report > C:\Windows\Temp\agc085.txt" /sc daily /st 03:00 /ru COMPROMISED-01\svc_reporting /rp "SvcR3port2026!" /f
User: COMPROMISED-01\Administrator
```

**Sysmon EID 1 -- schtasks.exe task execution (PID 1176):**
```
UtcTime: 2026-09-16 00:49:27.185
ProcessId: 1176
Image: C:\Windows\System32\schtasks.exe
CommandLine: "C:\WINDOWS\system32\schtasks.exe" /run /tn AGC085NightlyReport
User: COMPROMISED-01\Administrator
```

The task is configured to run under `COMPROMISED-01\svc_reporting` (the `/ru` parameter), scheduled at 03:00 daily.

### Step 2: Identify Account Type

**Account creation -- net.exe (PID 4864):**
```
UtcTime: 2026-09-16 00:49:26.982
Image: C:\Windows\System32\net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" user svc_reporting SvcR3port2026! /add
User: COMPROMISED-01\Administrator
```

The account name `svc_reporting` follows the `svc_` naming convention for service accounts. This is the first discriminating check: is this a human interactive account or a dedicated service/automation account?

### Step 3: Cross-Reference Service Account Documentation

Pre-existing service account registry (documented 2026-08-17):

```
Service Account Registry
Account: svc_reporting
Created: 2026-08-17
Owner: Finance Team (raj.patel)
Purpose: Nightly financial report generation
Schedule: Daily at 03:00 UTC
Expected Logon Type: Batch (Type 4) or Service (Type 5)
Host: COMPROMISED-HOST-01
Approved By: IT Operations Manager
Notes: Non-interactive account, no interactive logon permitted
```

Field-by-field verification:

| Field | Documentation | Observed | Match |
|-------|--------------|----------|-------|
| **Account name** | `svc_reporting` | schtasks `/ru svc_reporting` | YES |
| **Schedule** | Daily at 03:00 UTC | schtasks `/st 03:00 /sc daily` | YES |
| **Host** | COMPROMISED-HOST-01 | Events on COMPROMISED-01 | YES |
| **Purpose** | Financial report generation | Task writes report output | YES |
| **Expected logon type** | Batch (Type 4) | schtasks batch execution | YES |

### Step 4: Logon Type Analysis

In production, the scheduled task execution under `svc_reporting` would generate:

- **EID 4624 with Logon Type 4 (Batch)**: Expected for scheduled task execution. This is the correct, non-interactive logon type for automated tasks.
- **NOT Logon Type 2 (Interactive)**: An interactive logon for a service account would be anomalous even during the documented schedule window.
- **NOT Logon Type 10 (RemoteInteractive/RDP)**: A remote desktop session under a service account would be highly suspicious regardless of timing.

**Lab constraint**: The batch logon privilege was not assigned to `svc_reporting` in the lab environment (requires Local Security Policy > User Rights Assignment > "Log on as a batch job"), so EID 4624 Type 4 did not fire. The schtasks warning confirms: "Batch logon privilege needs to be enabled for the task principal."

### Step 5: Task Scheduler Warning (Privilege Gap)

```
WARNING: The task is registered, but may fail to start.
Batch logon privilege needs to be enabled for the task principal.
```

This warning itself is useful evidence: it confirms the task was properly registered under the service account. In production, the service account would have the batch logon privilege assigned during provisioning, and the EID 4624 Type 4 event would fire normally.

## Discriminating Evidence (Benign vs Malicious)

| Factor | AGC-085 (Benign) | AGC-008 (Malicious) |
|--------|-------------------|---------------------|
| **Account type** | Service account (`svc_` prefix) | Human user account (e.g., `michael.chen`) |
| **Logon type** | Type 4 (Batch) or Type 5 (Service) | Type 2 (Interactive) or Type 10 (RDP) |
| **Documentation** | Service account registry with schedule match | No service account documentation |
| **Schedule consistency** | 03:00 matches documented schedule | Off-hours with no documented reason |
| **Account purpose** | Dedicated automation, non-interactive | Interactive human account used outside normal hours |
| **Behavioral baseline** | Identical pattern every night | Anomalous departure from user's normal hours |

**The account type check is the fastest discriminator.** Before evaluating whether the timing is suspicious, determine whether the account is a human interactive account or a service/automation account. For service accounts with documented schedules, off-hours activity is expected behavior, not anomalous behavior.

## MITRE ATT&CK Mapping

No malicious technique applies. The pattern could be confused with:

| Technique ID | Name | Tactic | Disposition |
|-------------|------|--------|-------------|
| T1078 | Valid Accounts | Persistence / Privilege Escalation | **Observed, Benign** -- Off-hours logon by documented service account `svc_reporting` with scheduled task `AGC085NightlyReport` at 03:00 daily. Account type (service), logon type (batch), and schedule all consistent with documented purpose. |

## Conclusion

**Verdict: False Positive / Benign** -- The off-hours authentication is from a documented service account (`svc_reporting`) running a nightly scheduled task at its expected time (03:00). The account type (service, not human), expected logon type (batch, not interactive), and documented schedule all match the observed activity.

**Lab constraint**: EID 4624 Type 4 (Batch logon) did not fire because the service account was not granted "Log on as a batch job" privilege in the lab environment. In production, this privilege would be assigned during service account provisioning.

**Recommendation**: Close as Benign. Implement a pre-filtered allowlist for documented service accounts with known schedules. The allowlist should verify three conditions: (1) account is in the service account registry, (2) logon type matches expected type (Batch/Service, not Interactive), (3) timing falls within the documented schedule window. All three must match -- a service account logging on interactively, or outside its documented schedule, should still generate an alert.

**Cross-reference**: The malicious twin of this scenario is **AGC-008**, where an off-hours logon involves a human user account (phishing victim) authenticating interactively outside normal business hours with no documented scheduled task.
