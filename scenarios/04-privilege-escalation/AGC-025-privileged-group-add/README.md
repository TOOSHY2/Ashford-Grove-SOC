# AGC-025 — Existing Account Added to Privileged Group

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

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

**What:** The attacker adds an existing (already-compromised) user account to the local Administrators group. Unlike AGC-023 which creates a NEW account, this technique elevates an EXISTING account's privileges:

1. **No new account artifact** — in a real attack, no Security EID 4720 is generated because no account is created, making the change less visible in SIEM rules that correlate 4720+4732 pairs.
2. **Legitimate-looking identity** — an existing employee account's presence in the Administrators group may not trigger name-based alerts.
3. **Immediate privilege use** — the next logon or token refresh grants the user admin rights without any new credentials to manage.
4. **Evasion-aware** — experienced attackers prefer escalating existing accounts over creating new ones because new accounts are more conspicuous in user audits.

**Why at this lifecycle stage:** After establishing persistence and obtaining admin access through another path, the attacker grants a compromised user account permanent admin rights. This ensures they can operate with elevated privileges even from the legitimate user's normal sessions.

**Key differentiator from AGC-023:** AGC-023 creates a new account (triggers EID 4720 + 4732). AGC-025 targets an existing account (triggers only EID 4732). The absence of a paired EID 4720 is itself an indicator — it means an existing identity is being escalated rather than a new one provisioned.

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

**Lab limitation:** The original guide calls for `michael.chen` (a domain user) to be added to Administrators. This failed because the trust relationship between COMPROMISED-HOST-01 and the ASHFORDGROVE domain has degraded (error 1789). The retry used a local user account to demonstrate the full detection chain. The Sysmon EID 1 evidence from the failed michael.chen attempt is also documented as it shows the same detection signature an analyst would investigate.

**Cleanup:** agc025user removed from Administrators group and account deleted. michael.chen was never successfully added (command failed).

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

**Note on EID 4720:** A Security EID 4720 (account creation) was generated at 19:26:26 because the retry required creating a temp local user. In a real attack using an EXISTING account (the intended scenario), this 4720 would NOT exist — the attacker would only generate EID 4732. The absence of 4720 near a 4732 is the key detection differentiator for this technique.

### Investigation

**Step 1 — Identify the privilege escalation attempt:**
At 19:20:08 UTC, Sysmon EID 1 recorded `net.exe` executing `localgroup Administrators michael.chen /add`. This is a direct attempt to add an existing domain user to the local Administrators group. The command failed (error 1789) but the intent is clear.

At 19:26:28 UTC, the same technique succeeded with a local account — Security EID 4732 confirmed agc025user was added to the Administrators group (SID `S-1-5-32-544`).

**Step 2 — Check for paired EID 4720 (technique signature):**
In a real attack targeting an existing account, there would be NO paired EID 4720 near the EID 4732. This absence is the key detection differentiator:
- AGC-023 pattern: EID 4720 (account created) + EID 4732 (added to group) = new account provisioned with admin rights.
- AGC-025 pattern: EID 4732 alone (no 4720) = existing identity escalated. More evasion-aware.
SIEM rules should treat an unpaired EID 4732 with HIGHER priority than a paired 4720+4732, because it suggests an attacker is using an already-compromised identity rather than creating an obvious new account.

**Step 3 — Assess the target user's role:**
`michael.chen` is a regular employee (phishing victim per AGC scenario chain). They are NOT an IT administrator and have no business justification for local admin privileges on any endpoint. Adding a non-IT user to the Administrators group with no change ticket is a strong indicator of compromise. Compare with FP twin AGC-082 where a legitimate admin addition includes a matching change ticket and IT-approved justification.

**Step 4 — Cross-reference with AGC-023 and FP twin AGC-082:**
- AGC-023: NEW account `svc_helpdesk` created AND added to Administrators — generates both EID 4720 and 4732.
- AGC-025: EXISTING account targeted for escalation — generates only EID 4732 (no 4720). More evasion-aware.
- AGC-082 (FP twin): Legitimate admin group addition with matching change ticket and IT approval.

**Step 5 — Assess the domain trust failure:**
The initial michael.chen attempt failed with error 1789 (domain trust broken). In a production environment, this failure itself warrants investigation — it may indicate the host has been disconnected from the domain intentionally by the attacker for isolation, or that a broader infrastructure issue exists.

### Report

**Verdict: True Positive** — An attempt was made to add an existing account to the local Administrators group. The initial domain-user attempt was captured by Sysmon process monitoring (failed due to domain trust issue). A retry with a local account succeeded and generated full Security EID 4732 evidence. Both attempts demonstrate the T1098 technique.

**Confidence: High** — The evidence clearly demonstrates privilege escalation intent:
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
5. **Detection rule (Security):** EID 4732 where Group SID = `S-1-5-32-544` WITHOUT a paired EID 4720 within 60 seconds should trigger HIGHER priority than the paired case — it indicates existing-account escalation (more evasion-aware).
6. **Compare with FP twin AGC-082** for the legitimate version of this activity pattern.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Privilege Escalation (TA0004) | T1098 | Account Manipulation | Sysmon EID 1: `net.exe localgroup Administrators michael.chen /add` (failed, 19:20:08) and `net.exe localgroup Administrators agc025user /add` (succeeded, 19:26:28). Security EID 4732: member added to Administrators (SID S-1-5-32-544) by Administrator (SID ...500). | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
