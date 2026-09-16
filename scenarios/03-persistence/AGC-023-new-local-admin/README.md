# AGC-023 — New Local Administrator Account

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-023` |
| Category | `03-persistence` — Persistence |
| MITRE Technique | `T1136.001` Create Account: Local Account + `T1098` Account Manipulation |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Immediate — Security EID 4720 (account created) and EID 4732 (added to Administrators) |
| Time to Triage | 01:30 (from alert to change-management cross-reference) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ [AGC-022](../AGC-022-wmi-event-subscription/README.md) · next [AGC-024](../AGC-024-browser-extension/README.md) ▶ |
| One-line Summary | Unknown local account `svc_helpdesk` created and added to Administrators group with no corresponding change ticket. FP twin: AGC-082. |

## Attacker Perspective

### Tradecraft

**What:** The attacker creates a new local user account and adds it to the local Administrators group using `net user /add` and `net localgroup Administrators /add`. This provides:

1. **Credential-independent persistence** — even if the originally compromised account's password is changed, the attacker retains access through the new account.
2. **Administrative access** — membership in the local Administrators group grants full control over the endpoint.
3. **Name camouflage** — the account name `svc_helpdesk` mimics a legitimate service account naming convention, making it less likely to be questioned during casual review.
4. **Backup access path** — if other persistence mechanisms (Run keys, services, WMI) are discovered and removed, the attacker can re-establish them using this account.

**Why at this lifecycle stage:** After establishing technical persistence (AGC-019 through AGC-022), the attacker creates credential-based persistence. This is the most resilient form — even a full system rebuild that preserves the user database would maintain access.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 19:14:13 | Create user | COMPROMISED-HOST-01 | `net user svc_helpdesk P@ssw0rd2026! /add` — success |
| 2 | 2026-09-15 19:14:15 | Add to Admins | COMPROMISED-HOST-01 | `net localgroup Administrators svc_helpdesk /add` — success |
| 3 | 2026-09-15 19:14:17 | Verify | COMPROMISED-HOST-01 | `net localgroup Administrators` — confirmed svc_helpdesk is member |
| 4 | 2026-09-15 19:15:38 | Cleanup | COMPROMISED-HOST-01 | `net user svc_helpdesk /delete` |

**Cleanup:** User account deleted after evidence collection.

## SOC Perspective

### Detection

**Security Event Log (COMPROMISED-HOST-01):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 19:14:13 | 4720 | User Account Created | **Subject:** `COMPROMISED-01\Administrator` (SID: S-1-5-...-500, LogonId: 0x2F54D0). **New Account:** `svc_helpdesk` (SID: S-1-5-...-1001). **SAM Account Name:** `svc_helpdesk`. **UAC Flags:** Account Disabled, Password Not Required, Normal Account. |
| 2026-09-15 19:14:13 | 4732 | Member Added to Group | **Subject:** `COMPROMISED-01\Administrator`. **Member SID:** S-1-5-...-1001 (`svc_helpdesk`). **Group:** `Users` (S-1-5-32-545). Default group assignment. |
| 2026-09-15 19:14:15 | 4732 | Member Added to Group | **Subject:** `COMPROMISED-01\Administrator`. **Member SID:** S-1-5-...-1001 (`svc_helpdesk`). **Group:** `Administrators` (S-1-5-32-544). **This is the critical event.** |

**Sysmon telemetry (COMPROMISED-HOST-01):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 19:14:13 | 1 | Process Create | **Image:** `net.exe` (PID 1848). **CommandLine:** `net.exe user svc_helpdesk P@ssw0rd2026! /add`. **User:** `COMPROMISED-01\Administrator`. |
| 2026-09-15 19:14:13 | 1 | Process Create | **Image:** `net1.exe` (PID 3796). **CommandLine:** `net1 user svc_helpdesk P@ssw0rd2026! /add`. Child process of net.exe. |
| 2026-09-15 19:14:15 | 1 | Process Create | **Image:** `net.exe` (PID 5240). **CommandLine:** `net.exe localgroup Administrators svc_helpdesk /add`. |
| 2026-09-15 19:14:15 | 1 | Process Create | **Image:** `net1.exe` (PID 6008). **CommandLine:** `net1 localgroup Administrators svc_helpdesk /add`. |

**Key detection signals:**
1. **Security EID 4720** is the authoritative source for local account creation. The Subject field identifies WHO created the account.
2. **Security EID 4732** with Group SID `S-1-5-32-544` (Administrators) is the high-severity event — adding any account to local Administrators.
3. **Sysmon EID 1** captures the exact commands used, including the password in plaintext in the CommandLine (a bonus indicator of manual/scripted creation vs. UI-based).
4. **Temporal correlation** — account creation (4720) and admin group addition (4732) within 2 seconds suggests scripted/automated activity, not interactive user management.

### Investigation

**Step 1 — Identify account creation:**
At 19:14:13 UTC, Security EID 4720 recorded the creation of local account `svc_helpdesk`. The Subject field shows it was created by `COMPROMISED-01\Administrator` (the built-in RID-500 account).

**Step 2 — Identify privilege escalation:**
Two seconds later at 19:14:15, Security EID 4732 shows `svc_helpdesk` was added to the local `Administrators` group (SID S-1-5-32-544). Same Subject — `COMPROMISED-01\Administrator`.

**Step 3 — Cross-reference with change management:**
No IT change ticket or onboarding request exists for a `svc_helpdesk` account on COMPROMISED-HOST-01. The account name mimics a service account naming convention but has no documented purpose. This is the key differentiator from FP twin AGC-082, where a legitimate new admin account would be accompanied by a change ticket.

**Step 4 — Analyze the creating identity:**
The Subject is the built-in `Administrator` account (RID-500). In this environment, the RID-500 account should not be used for routine user management — IT staff use their own named accounts. Use of RID-500 is itself suspicious.

**Step 5 — Assess the Sysmon evidence:**
The Sysmon CommandLine for `net.exe user svc_helpdesk P@ssw0rd2026! /add` exposes the password in plaintext. This is a secondary indicator: the password contains common substitution patterns (`@` for `a`, `0` for `o`) typical of attacker-chosen passwords, not IT-provisioned passwords which would typically follow a stronger policy or be set via Active Directory.

### Report

**Verdict: True Positive** — A new local account was created and added to the Administrators group with no corresponding change ticket, using the built-in Administrator account as the creating identity.

**Confidence: High** — Multiple corroborating signals:
- Security EID 4720 + 4732 with timestamps 2 seconds apart (scripted behavior).
- No change management record for `svc_helpdesk`.
- Account created by RID-500 (not a named IT admin account).
- Account name mimics service account convention but has no documented purpose.
- Sysmon captures the exact command including plaintext password.

**Response recommendation:**
1. **Immediately disable and delete the account:** `net user svc_helpdesk /active:no` then `net user svc_helpdesk /delete`
2. **Audit logons** — check Security EID 4624/4625 for any successful/failed logons by `svc_helpdesk` between creation and discovery.
3. **Domain-wide audit** — search for EID 4720/4732 across all endpoints to check if the attacker created accounts on other hosts.
4. **Review RID-500 usage** — investigate all activity from the built-in Administrator account to determine scope of compromise.
5. **Detection rule:** Alert on Security EID 4732 where Group SID = `S-1-5-32-544` (local Administrators) and cross-reference with an approved change ticket system.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Persistence (TA0003) | T1136.001 | Create Account: Local Account | Security EID 4720: account `svc_helpdesk` created by `COMPROMISED-01\Administrator`. Sysmon EID 1: `net.exe user svc_helpdesk /add`. | High |
| Persistence (TA0003) | T1098 | Account Manipulation | Security EID 4732: `svc_helpdesk` added to local `Administrators` group (SID S-1-5-32-544). Sysmon EID 1: `net.exe localgroup Administrators svc_helpdesk /add`. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
