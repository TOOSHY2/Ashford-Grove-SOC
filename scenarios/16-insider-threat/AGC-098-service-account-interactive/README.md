# AGC-098 — Service Account Used for Interactive Logon

> **Disclosure:** Executed & documented by Claude Code under direction and review by Ali.

## Card

| Field | Value |
|---|---|
| ID | `AGC-098` |
| Title | Insider Threat: Service Account Interactive Logon Attempt |
| Category | `16-insider-threat` — Insider Threat |
| Severity | High |
| MITRE Technique | None (authorized identity used in unauthorized manner) |
| Verdict | Confirmed Policy Violation — Identify Human Operator |
| Confidence | High |
| Chain | ◀ [AGC-097](../AGC-097-personal-cloud-upload/README.md) · next [AGC-099](../AGC-099-afterhours-no-ticket/README.md) ▶ |

## Attacker Perspective

### Tradecraft

#### Service Account Registry (documented before simulation)

| Account | Designated Purpose | Authorized Logon Types | Prohibited |
|---------|-------------------|----------------------|------------|
| svc_reporting | Automated batch reporting tasks | Type 4 (Batch), Type 5 (Service) | **Type 2 (Interactive)**, Type 3 (Network) |

### Simulation

The simulation first confirmed that `svc_reporting` no longer exists locally (cleaned up after AGC-085). It then ran `cmdkey /add` to stage credentials for the account, the same move a human operator makes before logging on with a service account interactively, and removed them two seconds later with `cmdkey /delete`.

**Execution window**: 01:20:00 - 01:20:31 UTC on COMPROMISED-HOST-01

## SOC Perspective

### Detection

Sysmon captured `cmdkey` storing credentials for the service account `svc_reporting` on COMPROMISED-HOST-01. Staging a saved credential is the setup for interactive use, and the registry above restricts this account to batch and service logons only.

### Investigation

#### Step 1: Confirm Credential Staging Event

**Sysmon EID 1 — cmdkey credential add (PID 1792):**
```
UtcTime: 2026-09-16 01:20:29
ProcessId: 1792
Image: C:\Windows\System32\cmdkey.exe
CommandLine: "C:\WINDOWS\system32\cmdkey.exe" /add:COMPROMISED-01
             /user:svc_reporting /pass:[REDACTED]
User: COMPROMISED-01\Administrator
```

**Sysmon EID 1 — cmdkey credential delete (PID 4064):**
```
UtcTime: 2026-09-16 01:20:31
ProcessId: 4064
Image: C:\Windows\System32\cmdkey.exe
CommandLine: "C:\WINDOWS\system32\cmdkey.exe" /delete:COMPROMISED-01
```

**Critical finding**: `cmdkey /add` writes the service account password (`[REDACTED]`) in cleartext into the Sysmon EID 1 command line field.

#### Step 2: Verify Account Designation

```
net user svc_reporting: The user name could not be found.
```

The `svc_reporting` account was cleaned up after AGC-085 and no longer exists locally. The staging attempt still shows the pattern that matters: someone who knew the service account password stored it for interactive use.

#### Step 3: Identify the Human Behind the Keyboard

| Factor | Evidence |
|--------|----------|
| **Source workstation** | COMPROMISED-HOST-01 |
| **Executing user** | COMPROMISED-01\Administrator |
| **Parent process** | PowerShell (simulation script) |
| **Credential staging time** | 01:20:29 UTC |

In production, the source workstation plus the executing user context would name the person at the keyboard when the credentials were staged. In the lab that context resolves only to the shared Administrator account and the simulation script.

#### Step 4: Assess Risk

- **Password exposure**: Service account password visible in cleartext in Sysmon logs
- **Credential misuse**: Service account credentials being used outside their designated purpose
- **Accountability gap**: Interactive use of a shared/service account breaks individual accountability

### Report

**Verdict: Confirmed Policy Violation** — A human operator staged credentials for the `svc_reporting` service account with `cmdkey`, which signals intent to use the account interactively. The service account policy limits `svc_reporting` to automated batch tasks; interactive use breaks that policy and removes individual accountability.

**Recommendation**:
1. Identify the human operator via source workstation and session context
2. Rotate the service account password immediately (credential exposed in cleartext in Sysmon logs)
3. Implement GPO "Deny interactive logon" (`SeDenyInteractiveLogonRight`) for all service accounts
4. Review service account password distribution — limit knowledge to the minimum necessary personnel
5. Implement Credential Guard or Managed Service Accounts (gMSA) to eliminate human knowledge of service account passwords

### MITRE Mapping

No MITRE ATT&CK technique applies. Authorized personnel legitimately know the service account credentials; the finding is the **unauthorized manner of use** (interactive instead of batch/service), not credential theft or privilege escalation.

**Cross-reference**: This scenario is the insider-threat companion to **AGC-085** (False Positive), where the same service account ran a scheduled task inside its authorized parameters. The only thing that separates the two is the logon type: Type 4/5 (batch/service) is authorized; Type 2 (interactive) is not.

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
