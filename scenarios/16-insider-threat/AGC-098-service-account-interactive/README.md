# AGC-098: Service Account Used for Interactive Logon

## Scenario Overview

| Field              | Value                                                        |
|--------------------|--------------------------------------------------------------|
| **Scenario ID**    | AGC-098                                                      |
| **Title**          | Insider Threat: Service Account Interactive Logon Attempt    |
| **Category**       | Insider Threat (16-insider-threat)                           |
| **Severity**       | High                                                         |
| **MITRE Techniques** | None (authorized identity used in unauthorized manner)      |
| **Verdict**        | Confirmed Policy Violation -- Identify Human Operator        |
| **Confidence**     | High                                                         |

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

**Navigation:** [< AGC-097](../../16-insider-threat/AGC-097-personal-cloud-upload/README.md) | [AGC-099 >](../../16-insider-threat/AGC-099-afterhours-no-ticket/README.md)

## Service Account Registry (Documented Before Simulation)

| Account | Designated Purpose | Authorized Logon Types | Prohibited |
|---------|-------------------|----------------------|------------|
| svc_reporting | Automated batch reporting tasks | Type 4 (Batch), Type 5 (Service) | **Type 2 (Interactive)**, Type 3 (Network) |

## Alert / Trigger

Credential staging detected for service account `svc_reporting` on COMPROMISED-HOST-01. The `cmdkey` command was used to store credentials for this account, indicating an attempt to use the service account interactively. Service accounts are designated for automated tasks only and should never be used for interactive logon.

## Simulation Summary

Verified that `svc_reporting` no longer exists on the local system (cleaned up after AGC-085). Used `cmdkey /add` to simulate credential staging for the service account, demonstrating the pattern of a human operator attempting to use a service account interactively. The credential was immediately cleaned up via `cmdkey /delete`.

**Execution window**: 01:20:00 - 01:20:31 UTC on COMPROMISED-HOST-01

## Investigation

### Step 1: Confirm Credential Staging Event

**Sysmon EID 1 -- cmdkey credential add (PID 1792):**
```
UtcTime: 2026-09-16 01:20:29
ProcessId: 1792
Image: C:\Windows\System32\cmdkey.exe
CommandLine: "C:\WINDOWS\system32\cmdkey.exe" /add:COMPROMISED-01
             /user:svc_reporting /pass:[REDACTED]
User: COMPROMISED-01\Administrator
```

**Sysmon EID 1 -- cmdkey credential delete (PID 4064):**
```
UtcTime: 2026-09-16 01:20:31
ProcessId: 4064
Image: C:\Windows\System32\cmdkey.exe
CommandLine: "C:\WINDOWS\system32\cmdkey.exe" /delete:COMPROMISED-01
```

**Critical finding**: The `cmdkey /add` command exposes the service account password (`[REDACTED]`) in cleartext in the Sysmon EID 1 command line field.

### Step 2: Verify Account Designation

```
net user svc_reporting: The user name could not be found.
```

The `svc_reporting` account was cleaned up after AGC-085 and no longer exists locally. However, the credential staging attempt demonstrates the attack pattern: a human operator with knowledge of the service account password attempted to store credentials for interactive use.

### Step 3: Identify the Human Behind the Keyboard

| Factor | Evidence |
|--------|----------|
| **Source workstation** | COMPROMISED-HOST-01 |
| **Executing user** | COMPROMISED-01\Administrator |
| **Parent process** | PowerShell (simulation script) |
| **Credential staging time** | 01:20:29 UTC |

In a production investigation, the source workstation and executing user context would identify which human operator was at the keyboard when the service account credentials were staged.

### Step 4: Assess Risk

- **Password exposure**: Service account password visible in cleartext in Sysmon logs
- **Credential misuse**: Service account credentials being used outside their designated purpose
- **Accountability gap**: Interactive use of a shared/service account breaks individual accountability

## MITRE ATT&CK Mapping

No MITRE ATT&CK technique applies. The service account credentials are legitimately known to authorized personnel; the finding is the **unauthorized manner of use** (interactive instead of batch/service), not credential theft or privilege escalation.

**Cross-reference**: This scenario is the insider-threat companion to **AGC-085** (False Positive), where the same service account was used within its authorized parameters (scheduled task execution). The distinction is the logon type: Type 4/5 (batch/service) is authorized; Type 2 (interactive) is not.

## Conclusion

**Verdict: Confirmed Policy Violation** -- A human operator staged credentials for the `svc_reporting` service account using `cmdkey`, indicating an intent to use the account interactively. Service accounts are designated for automated batch tasks only, and interactive use violates the service account policy and breaks individual accountability.

**Recommendation**:
1. Identify the human operator via source workstation and session context
2. Rotate the service account password immediately (credential exposed in cleartext in Sysmon logs)
3. Implement GPO "Deny interactive logon" (`SeDenyInteractiveLogonRight`) for all service accounts
4. Review service account password distribution -- limit knowledge to the minimum necessary personnel
5. Implement Credential Guard or Managed Service Accounts (gMSA) to eliminate human knowledge of service account passwords
