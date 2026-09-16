# AGC-082: New Local Admin Account -- Matches IT Onboarding Ticket (False Positive)

## Scenario Overview

| Field              | Value                                                        |
|--------------------|--------------------------------------------------------------|
| **Scenario ID**    | AGC-082                                                      |
| **Title**          | New Local Admin: Matches an IT Change Ticket                 |
| **Category**       | False Positive Triage (14-false-positive)                    |
| **Severity**       | Medium (alert trigger)                                       |
| **MITRE Techniques** | T1136.001 (observed, not malicious)                        |
| **Verdict**        | False Positive / Benign                                      |
| **Confidence**     | High                                                         |
| **Malicious Twin** | AGC-023 (Unauthorized Local Admin Creation)                  |

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

**Navigation:** [< AGC-081](../../14-false-positive/AGC-081-encoded-ps-backup/README.md) | [AGC-083 >](../../14-false-positive/AGC-083-sysadmin-tool-change-window/README.md)

## Alert / Trigger

Security Event ID 4720 (user account created) and Event ID 4732 (member added to Administrators group) fired on COMPROMISED-HOST-01. The new account `new_it_tech` was created by `COMPROMISED-01\Administrator` and immediately added to the local Administrators group. This is the identical event signature produced by AGC-023 (unauthorized admin persistence). The triage question: was this an authorized IT onboarding operation, or unauthorized account creation for persistence?

## Simulation Summary

Created a pre-dated IT onboarding ticket (OB-2026-0847, approved 2026-09-11) documenting the provisioning of a local admin account for a new IT support technician. Then executed the account creation (`net user new_it_tech /add`) and group addition (`net localgroup Administrators new_it_tech /add`) on COMPROMISED-HOST-01. The technical artifacts are identical to those produced by the malicious twin AGC-023.

**Execution window**: 00:38:48 - 00:38:50 UTC on COMPROMISED-HOST-01

## Investigation

### Step 1: Identify the Alert Events

**Security EID 4720 -- Account Created:**
```
TimeCreated: 2026-09-16 00:38:48
Event ID: 4720 - A user account was created.

Subject:
    Security ID:    S-1-5-21-783388846-4178789021-3119572882-500
    Account Name:   Administrator
    Account Domain: COMPROMISED-01
    Logon ID:       0xB76442

New Account:
    Security ID:    S-1-5-21-783388846-4178789021-3119572882-1004
    Account Name:   new_it_tech
    Account Domain: COMPROMISED-01
    SAM Account Name: new_it_tech
```

**Security EID 4732 -- Added to Administrators Group:**
```
TimeCreated: 2026-09-16 00:38:50
Event ID: 4732 - A member was added to a security-enabled local group.

Subject:
    Security ID:    S-1-5-21-783388846-4178789021-3119572882-500
    Account Name:   Administrator
    Account Domain: COMPROMISED-01
    Logon ID:       0xB76442

Member:
    Security ID:    S-1-5-21-783388846-4178789021-3119572882-1004

Group:
    Security ID:    S-1-5-32-544
    Group Name:     Administrators
    Group Domain:   Builtin
```

These events are technically identical in shape to what AGC-023 produces. Without the paper trail, there is no way to distinguish benign from malicious from the events alone.

### Step 2: Corroborating Sysmon Evidence

**Sysmon EID 1 -- net.exe account creation (PID 128):**
```
UtcTime: 2026-09-16 00:38:48.642
ProcessId: 128
Image: C:\Windows\System32\net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" user new_it_tech P@ssw0rd2026! /add
User: COMPROMISED-01\Administrator
```

**Sysmon EID 1 -- net.exe group addition (PID 4348):**
```
UtcTime: 2026-09-16 00:38:50.749
ProcessId: 4348
Image: C:\Windows\System32\net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" localgroup Administrators new_it_tech /add
User: COMPROMISED-01\Administrator
```

Both commands executed under the local `Administrator` account, 2 seconds apart.

### Step 3: Cross-Reference Onboarding Ticket

Pre-dated IT onboarding ticket (submitted 2026-09-11, 5 days before execution):

```
IT Onboarding Ticket: OB-2026-0847
Date Submitted: 2026-09-11
Approved By: raj.patel (IT Operations Manager)
New Hire: Alex Torres, IT Support Technician
Start Date: 2026-09-16
Requested Action: Provision local admin on COMPROMISED-HOST-01 per standard onboarding checklist
Account Name: new_it_tech
Justification: New IT support technician requires local admin for hardware diagnostics and software deployment
Risk Assessment: Low - standard onboarding procedure
```

### Step 4: Field-by-Field Verification

| Field | Onboarding Ticket | Event Evidence | Match |
|-------|-------------------|----------------|-------|
| **Account Name** | `new_it_tech` | EID 4720: `new_it_tech` | YES |
| **Target Host** | COMPROMISED-HOST-01 | EID 4720: `COMPROMISED-01` | YES |
| **Creating Identity** | Administrator (IT provisioning) | EID 4720 Subject: `COMPROMISED-01\Administrator` | YES |
| **Target Group** | Local Administrators | EID 4732: `Administrators (Builtin)` | YES |
| **Timing** | Start date 2026-09-16 | Events fired 2026-09-16 00:38 UTC | YES |

All five fields match precisely. The ticket pre-dates the technical execution by 5 days and names the exact account, host, group, and provisioning identity.

## Discriminating Evidence (Benign vs Malicious)

| Factor | AGC-082 (Benign) | AGC-023 (Malicious) |
|--------|-------------------|---------------------|
| **Onboarding ticket** | Pre-dated OB-2026-0847, approved by raj.patel | None -- no documentation exists |
| **Account purpose** | Named new hire (Alex Torres, IT Support) | Unknown / undocumented account |
| **Creating identity** | Administrator (matches ticket provisioner) | May be compromised or unauthorized account |
| **Timing** | Matches documented start date | Unexpected / outside business process |
| **Technical events** | Identical EID 4720 + 4732 | Identical EID 4720 + 4732 |

The technical telemetry is indistinguishable between the two scenarios. The **entire** difference is the existence and consistency of the pre-dated onboarding ticket. This makes documentation verification the critical step in the SOC playbook for this alert type.

## MITRE ATT&CK Mapping

No malicious technique applies. The alert fires through the same detection rules as AGC-023:

| Technique ID | Name | Tactic | Disposition |
|-------------|------|--------|-------------|
| T1136.001 | Create Account: Local Account | Persistence | **Observed, Benign** -- EID 4720/4732 for `new_it_tech` account creation and Administrators group addition. Confirmed by pre-dated onboarding ticket OB-2026-0847 matching all event fields. |

## Conclusion

**Verdict: False Positive / Benign** -- The local admin account `new_it_tech` was created as part of a documented IT onboarding process for a new IT support technician. The pre-dated onboarding ticket (OB-2026-0847, approved 2026-09-11 by raj.patel) names the exact account, target host, provisioning identity, and target group, all of which match the Security EID 4720/4732 events field-for-field.

**Recommendation**: Close as Benign. Consider implementing a standard SOC notification workflow where HR/IT Operations sends the SOC a pre-provisioning notification for expected onboarding events. This would allow analysts to pre-validate the ticket before the events fire, reducing triage time for this common, recurring alert pattern.

**Cross-reference**: The malicious twin of this scenario is **AGC-023**, where the same EID 4720/4732 events indicate unauthorized local account creation for persistence, with no corresponding onboarding documentation.
