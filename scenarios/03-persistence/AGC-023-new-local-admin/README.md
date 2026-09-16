# AGC-023 — New Local Administrator Account

> **Disclosure:** Executed & documented by Claude Code under direction and review by Ali.

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

**What:** The attacker creates a new local user account and adds it to the local Administrators group using `net user /add` and `net localgroup Administrators /add`. The attacker gets:

1. **Credential-independent persistence** — a password reset on the originally compromised account changes nothing; the new account still works.
2. **Administrative access** — local Administrators membership is full control of the endpoint.
3. **Name camouflage** — `svc_helpdesk` follows a service-account naming convention, so a quick review is less likely to question it.
4. **Backup access path** — if the Run key, service, or WMI persistence is found and removed, the attacker rebuilds it from this account.

**Why at this lifecycle stage:** With technical persistence in place (AGC-019 through AGC-022), the attacker adds credential-based persistence. It is the most resilient form: even a rebuild that preserves the user database keeps the door open.

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
1. **Security EID 4720** is the authoritative source for local account creation. The Subject field names who created the account.
2. **Security EID 4732** with Group SID `S-1-5-32-544` (Administrators) is the high-severity event: any account joining local Administrators.
3. **Sysmon EID 1** captures the exact commands, password in plaintext in the CommandLine, which also marks the creation as command-line rather than UI-driven.
4. **Temporal correlation** — account creation (4720) and admin group addition (4732) 2 seconds apart points to a script, not interactive user management.

### Investigation

**Step 1 — Identify account creation:**
At 19:14:13 UTC, Security EID 4720 recorded the creation of local account `svc_helpdesk`. The Subject field shows `COMPROMISED-01\Administrator` (the built-in RID-500 account) created it.

**Step 2 — Identify privilege escalation:**
Two seconds later at 19:14:15, Security EID 4732 shows `svc_helpdesk` added to the local `Administrators` group (SID S-1-5-32-544), same Subject `COMPROMISED-01\Administrator`.

**Step 3 — Cross-reference with change management:**
No IT change ticket or onboarding request exists for a `svc_helpdesk` account on COMPROMISED-HOST-01. The name follows a service-account convention but has no documented purpose. That is the differentiator from FP twin AGC-082, where the new admin account comes with a change ticket.

**Step 4 — Analyze the creating identity:**
The Subject is the built-in `Administrator` account (RID-500). In the lab, IT staff use their own named accounts for user management, not RID-500. Use of RID-500 is itself suspicious.

**Step 5 — Assess the Sysmon evidence:**
The Sysmon CommandLine for `net.exe user svc_helpdesk P@ssw0rd2026! /add` exposes the password in plaintext. That is a secondary indicator: the substitutions (`@` for `a`, `0` for `o`) are what an attacker types by hand, not what an IT provisioning policy or Active Directory would set.

### Report

**Verdict: True Positive** — A new local account was created and added to the Administrators group with no change ticket, by the built-in Administrator account.

**Confidence: High** — Five signals corroborate:
- Security EID 4720 + 4732 with timestamps 2 seconds apart (scripted behavior).
- No change management record for `svc_helpdesk`.
- Account created by RID-500, not a named IT admin account.
- Account name follows service-account convention but has no documented purpose.
- Sysmon captured the exact command, plaintext password included.

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
