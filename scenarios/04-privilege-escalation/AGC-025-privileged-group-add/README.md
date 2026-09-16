# AGC-025 — Existing Account Added to Privileged Group

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-025` |
| Category | `04-privilege-escalation` — Privilege Escalation |
| MITRE Technique | `T1098` Account Manipulation |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Immediate — Sysmon EID 1 captures `net localgroup Administrators <user> /add`; Security EID 4732 logs the group membership change |
| Time to Triage | 01:30 (from alert to role verification and change-ticket cross-reference) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ [AGC-024](../../03-persistence/AGC-024-browser-extension/README.md) (Persistence category) · next [AGC-026](../AGC-026-uac-bypass-behavior/README.md) ▶ |
| One-line Summary | Existing account added to local Administrators group detected by Sysmon process monitoring and Security EID 4732. Initial domain-user attempt failed (domain trust broken); succeeded with local account. Key detection differentiator from AGC-023: EID 4732 without a paired EID 4720 indicates existing-account escalation. Compare FP twin AGC-082. |

## Attacker Perspective

### Tradecraft

**What:** The attacker adds an already-compromised user account to the local Administrators group. Where AGC-023 creates a NEW account, this technique elevates an EXISTING one:

1. **No new account artifact** — no account is created, so Security never logs EID 4720, and SIEM rules that correlate 4720+4732 pairs miss the change.
2. **Legitimate-looking identity** — an existing employee account sitting in Administrators does not trip name-based alerts.
3. **Immediate privilege use** — the next logon or token refresh grants admin rights, with no new credentials to manage.
4. **Evasion-aware** — a new account like `svc_helpdesk` in AGC-023 stands out in a user audit; an existing employee account does not.

**Why at this lifecycle stage:** With persistence in place and admin access already obtained, the attacker grants a compromised user account permanent admin rights. They can then operate elevated from that user's normal sessions.

**Key differentiator from AGC-023:** AGC-023 creates a new account and logs EID 4720 + 4732. AGC-025 targets an existing account and logs only EID 4732. The missing 4720 is itself the signal: an existing identity is being escalated, not a new one provisioned.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 19:20:08 | Attempt domain user group add | COMPROMISED-HOST-01 | `net localgroup Administrators michael.chen /add` — FAILED with error 1789 (domain trust relationship broken between COMPROMISED-HOST-01 and ASHFORDGROVE domain) |
| 2 | 2026-09-15 19:26:26 | Create temp local user | COMPROMISED-HOST-01 | `net user agc025user Passw0rd!25 /add` — created local account to complete simulation after domain trust failure |
| 3 | 2026-09-15 19:26:28 | Add to Administrators | COMPROMISED-HOST-01 | `net localgroup Administrators agc025user /add` — succeeded |
| 4 | 2026-09-15 19:26:31 | Verify membership | COMPROMISED-HOST-01 | `net localgroup Administrators` confirmed agc025user in group (Administrator, agc025user, wadmin) |
| 5 | 2026-09-15 19:27:50 | Cleanup | COMPROMISED-HOST-01 | agc025user removed from Administrators and deleted |

**Lab limitation:** The guide calls for `michael.chen` (a domain user) to be added to Administrators. That failed with error 1789 because the trust between COMPROMISED-HOST-01 and the ASHFORDGROVE domain has broken. The retry used a local account to exercise the full detection chain. The Sysmon EID 1 record from the failed michael.chen attempt is kept because it carries the same detection signature an analyst would work.

**Cleanup:** agc025user removed from Administrators and deleted. michael.chen was never added; the command failed.

## SOC Perspective

### Detection

**Evidence from failed domain-user attempt (19:20:08 UTC):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 19:20:08 | 1 (Sysmon) | Process Create | **Image:** `C:\Windows\System32\net.exe` (PID 3556). **CommandLine:** `net.exe localgroup Administrators michael.chen /add`. **User:** `COMPROMISED-01\Administrator`. **IntegrityLevel:** High. Command FAILED (error 1789) but Sysmon captured the full intent. |

**Evidence from successful local-user retry (19:26:26-28 UTC):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 19:26:28 | 4732 (Security) | Member added to security-enabled local group | **Subject:** `COMPROMISED-01\Administrator` (SID ...500, Logon ID 0x326A16). **Member SID:** `S-1-5-21-783388846-4178789021-3119572882-1002`. **Group:** `Administrators` (SID `S-1-5-32-544`). |
| 2026-09-15 19:26:28 | 1 (Sysmon) | Process Create | **Image:** `C:\Windows\System32\net.exe` (PID 5480). **CommandLine:** `net.exe localgroup Administrators agc025user /add`. **User:** `COMPROMISED-01\Administrator`. **IntegrityLevel:** High. |
| 2026-09-15 19:26:28 | 1 (Sysmon) | Process Create | **Image:** `C:\Windows\System32\net1.exe` (PID 1512). **CommandLine:** `net1 localgroup Administrators agc025user /add`. Child process of net.exe. |

**Note on EID 4720:** Security logged EID 4720 (account creation) at 19:26:26 because the retry had to create a temp local user. Against an EXISTING account, the intended scenario, that 4720 would not exist; only EID 4732 would be logged. A 4732 with no 4720 nearby is the signature to hunt for.

### Investigation

**Step 1 — Identify the privilege escalation attempt:**
At 19:20:08 UTC, Sysmon EID 1 captured `net.exe` running `localgroup Administrators michael.chen /add`: a direct attempt to add an existing domain user to local Administrators. The command failed with error 1789, but the intent is on record.

At 19:26:28 UTC, the same technique succeeded with a local account. Security EID 4732 confirmed agc025user was added to the Administrators group (SID `S-1-5-32-544`).

**Step 2 — Check for paired EID 4720 (technique signature):**
Against a real existing account there is NO EID 4720 paired with the EID 4732. That absence separates the two patterns:
- AGC-023 pattern: EID 4720 (account created) + EID 4732 (added to group) = new account provisioned with admin rights.
- AGC-025 pattern: EID 4732 alone (no 4720) = existing identity escalated. Harder to spot.
SIEM rules should rank an unpaired EID 4732 above a paired 4720+4732: it suggests the attacker is riding an already-compromised identity rather than creating an obvious new account.

**Step 3 — Assess the target user's role:**
`michael.chen` is a regular employee, the phishing victim earlier in the AGC chain. Not an IT administrator, and no business need for local admin on any endpoint. A non-IT user added to Administrators with no change ticket is a strong indicator of compromise. In FP twin AGC-082 the same addition comes with a matching change ticket and IT approval.

**Step 4 — Cross-reference with AGC-023 and FP twin AGC-082:**
- AGC-023: NEW account `svc_helpdesk` created AND added to Administrators — logs both EID 4720 and 4732.
- AGC-025: EXISTING account escalated — logs only EID 4732 (no 4720). Harder to spot.
- AGC-082 (FP twin): Legitimate admin group addition with matching change ticket and IT approval.

**Step 5 — Assess the domain trust failure:**
The initial michael.chen attempt failed with error 1789 (domain trust broken). In production that failure is its own lead: the attacker may have cut the host from the domain to isolate it, or a wider infrastructure fault may exist.

### Report

**Verdict: True Positive** — The attacker attempted to add an existing account to local Administrators. Sysmon captured the domain-user attempt, which failed on the broken domain trust. The local-account retry succeeded and Security logged EID 4732. Both attempts are T1098.

**Confidence: High** — Both attempts show privilege-escalation intent:
- Sysmon EID 1 captured `net localgroup Administrators michael.chen /add` (failed attempt, 19:20:08 UTC).
- Sysmon EID 1 captured `net localgroup Administrators agc025user /add` (successful, 19:26:28 UTC).
- Security EID 4732 confirmed agc025user added to Administrators group (SID `S-1-5-32-544`).
- Executed by `COMPROMISED-01\Administrator` (RID-500).
- No corresponding change ticket for either attempt.

**Response recommendation:**
1. **Remove unauthorized accounts from Administrators** immediately and audit the group membership fleet-wide.
2. **Treat affected accounts as compromised** — the attacker has control of the RID-500 Administrator account and attempted to escalate additional identities.
3. **Investigate the domain trust failure** — error 1789 may indicate intentional domain isolation or broader infrastructure compromise.
4. **Detection rule (Sysmon):** Alert on EID 1 where CommandLine matches `net* localgroup Administrators * /add` and cross-reference Subject with authorized IT staff.
5. **Detection rule (Security):** EID 4732 where Group SID = `S-1-5-32-544` WITHOUT a paired EID 4720 within 60 seconds should fire at HIGHER priority than the paired case; it indicates existing-account escalation.
6. **Compare with FP twin AGC-082** for the legitimate version of this activity pattern.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Privilege Escalation (TA0004) | T1098 | Account Manipulation | Sysmon EID 1: `net.exe localgroup Administrators michael.chen /add` (failed, 19:20:08) and `net.exe localgroup Administrators agc025user /add` (succeeded, 19:26:28). Security EID 4732: member added to Administrators (SID S-1-5-32-544) by Administrator (SID ...500). | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
