# AGC-085 — Off-Hours Logon: Scheduled Task Under Service Account (False Positive)

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-085` |
| Title | Off-Hours Logon: Scheduled Task Under Service Account |
| Category | `14-false-positive` — False Positive Triage |
| Severity | Medium (alert trigger) |
| MITRE Technique | T1078 (observed, not malicious) |
| Verdict | False Positive / Benign |
| Confidence | High |
| Malicious Twin | AGC-008 (Off-Hours Phishing Victim Logon) |
| Chain | ◀ [AGC-084](../AGC-084-dns-beacon-saas/README.md) · next [AGC-086](../AGC-086-regulatory-submission/README.md) ▶ |

## Attacker Perspective

### Simulation

Created a service account (`svc_reporting`) backed by a pre-existing registry entry (created 2026-08-17, approved by IT Operations). Registered a scheduled task (`AGC085NightlyReport`) to run under that account at 03:00 daily, then ran it by hand to stand in for the off-hours execution.

**Lab constraint**: The `svc_reporting` account was created without the "Log on as a batch job" privilege (that needs a Local Security Policy change guestcontrol cannot make). The task registered, but the batch logon event (EID 4624 Type 4) never fired. Evidence rests on the schtasks creation/run telemetry and the account creation event.

**Execution window**: 00:49:26 - 00:49:27 UTC on COMPROMISED-HOST-01

## SOC Perspective

### Detection

An off-hours authentication event for account `svc_reporting` was detected on COMPROMISED-HOST-01. The scheduled task `AGC085NightlyReport` runs daily at 03:00 UTC under that account. Off-hours logon rules fire the same way for a human user and a service account, which makes this one of the most common false positive patterns a SOC sees.

### Investigation

#### Step 1: Identify the Off-Hours Activity

**Sysmon EID 1 — schtasks.exe task creation (PID 3028):**
```
UtcTime: 2026-09-16 00:49:27.093
ProcessId: 3028
Image: C:\Windows\System32\schtasks.exe
CommandLine: "C:\WINDOWS\system32\schtasks.exe" /create /tn AGC085NightlyReport /tr "cmd.exe /c echo AGC-085 nightly report > C:\Windows\Temp\agc085.txt" /sc daily /st 03:00 /ru COMPROMISED-01\svc_reporting /rp "[REDACTED]" /f
User: COMPROMISED-01\Administrator
```

**Sysmon EID 1 — schtasks.exe task execution (PID 1176):**
```
UtcTime: 2026-09-16 00:49:27.185
ProcessId: 1176
Image: C:\Windows\System32\schtasks.exe
CommandLine: "C:\WINDOWS\system32\schtasks.exe" /run /tn AGC085NightlyReport
User: COMPROMISED-01\Administrator
```

The task is configured to run under `COMPROMISED-01\svc_reporting` (the `/ru` parameter), scheduled at 03:00 daily.

#### Step 2: Identify Account Type

**Account creation — net.exe (PID 4864):**
```
UtcTime: 2026-09-16 00:49:26.982
Image: C:\Windows\System32\net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" user svc_reporting [REDACTED] /add
User: COMPROMISED-01\Administrator
```

The name `svc_reporting` follows the `svc_` convention for service accounts. That is the first discriminating check: human interactive account, or dedicated automation account?

#### Step 3: Cross-Reference Service Account Documentation

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

#### Step 4: Logon Type Analysis

In production, the task running under `svc_reporting` would log:

- **EID 4624 with Logon Type 4 (Batch)**: the expected non-interactive logon type for a scheduled task.
- **NOT Logon Type 2 (Interactive)**: an interactive logon by a service account is anomalous even inside the documented schedule window.
- **NOT Logon Type 10 (RemoteInteractive/RDP)**: an RDP session under a service account is suspicious at any hour.

**Lab constraint**: The lab never granted `svc_reporting` the batch logon privilege (Local Security Policy > User Rights Assignment > "Log on as a batch job"), so EID 4624 Type 4 did not fire. The schtasks warning says as much: "Batch logon privilege needs to be enabled for the task principal."

#### Step 5: Task Scheduler Warning (Privilege Gap)

```
WARNING: The task is registered, but may fail to start.
Batch logon privilege needs to be enabled for the task principal.
```

The warning is evidence in its own right: it confirms the task was registered under the service account. In production the privilege is assigned at provisioning, and the EID 4624 Type 4 event fires as normal.

### Report

**Verdict: False Positive / Benign** — The off-hours authentication belongs to a documented service account (`svc_reporting`) running its nightly scheduled task at the expected time (03:00). Account type (service, not human), expected logon type (batch, not interactive), and documented schedule all match what was observed.

**Lab constraint**: EID 4624 Type 4 (Batch logon) did not fire because the lab never granted the account "Log on as a batch job". In production that privilege is assigned when the service account is provisioned.

**Recommendation**: Close as Benign. Build an allowlist for documented service accounts with known schedules that checks three conditions: (1) the account is in the service account registry, (2) the logon type is the expected one (Batch/Service, not Interactive), (3) the time falls inside the documented schedule window. All three must hold — a service account logging on interactively, or outside its schedule, should still alert.

**Cross-reference**: The malicious twin is **AGC-008**, where a human user account (a phishing victim) logs on interactively outside business hours with no scheduled task to explain it.

#### Discriminating evidence (benign vs malicious)

| Factor | AGC-085 (Benign) | AGC-008 (Malicious) |
|--------|-------------------|---------------------|
| **Account type** | Service account (`svc_` prefix) | Human user account (e.g., `michael.chen`) |
| **Logon type** | Type 4 (Batch) or Type 5 (Service) | Type 2 (Interactive) or Type 10 (RDP) |
| **Documentation** | Service account registry with schedule match | No service account documentation |
| **Schedule consistency** | 03:00 matches documented schedule | Off-hours with no documented reason |
| **Account purpose** | Dedicated automation, non-interactive | Interactive human account used outside normal hours |
| **Behavioral baseline** | Identical pattern every night | Anomalous departure from user's normal hours |

**The account type check is the fastest discriminator.** Before judging the timing, settle whether the account is a human interactive account or an automation account. For a service account with a documented schedule, off-hours activity is the expected behavior.

### MITRE Mapping

No malicious technique applies. The pattern could be confused with:

| Technique ID | Name | Tactic | Disposition |
|-------------|------|--------|-------------|
| T1078 | Valid Accounts | Persistence / Privilege Escalation | **Observed, Benign** — Off-hours logon by documented service account `svc_reporting` with scheduled task `AGC085NightlyReport` at 03:00 daily. Account type (service), logon type (batch), and schedule all consistent with documented purpose. |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
