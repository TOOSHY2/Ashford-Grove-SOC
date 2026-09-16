# AGC-008 — Password-Reset Phishing Lure

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-008` |
| Category | `01-phishing` — Phishing & Initial Access |
| MITRE Technique | `T1566.002` Phishing: Spearphishing Link (password-reset pretext) |
| Verdict | True Positive |
| Confidence | Critical |
| Time to Detect | N/A — no automated alert; Sysmon EID 1 captures the process chain |
| Time to Triage | 02:00 (from link click to POST confirmation) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103), `EXT-ATTACKER-SIM` (10.10.40.10) |
| Chain | ◀ [AGC-007](../AGC-007-macro-lure-document/README.md) · next [AGC-009](../AGC-009-oauth-consent-phish/README.md) ▶ |
| One-line Summary | Urgency-framed "password expiration" email lures victim to fake reset page; credentials captured via POST to non-corporate IP. |

## Attacker Perspective

### Tradecraft

**What:** The attacker sends a phishing email styled as an automated security notification: "Your Ashford Grove Capital password expires in 24 hours — reset now to avoid lockout." The link points to a credential-harvesting page on the attacker's infrastructure. The page presents fields for "current password" and "new password," capturing the victim's valid credentials when submitted.

**Why at this lifecycle stage:** Password-reset pretexts are among the most effective social-engineering frames because they (1) create artificial urgency ("24 hours"), (2) align with a legitimate action users expect to perform, and (3) exploit the user's security-conscious behavior — they think they are protecting their account by resetting their password. The attacker gains the victim's current, valid credentials.

**Comparison with AGC-003:** The technical delivery (phishing link → credential-harvesting page → POST) is nearly identical to AGC-003. The difference is purely in the social-engineering frame: AGC-003 used a generic "review document" pretext; AGC-008 uses a security-notification/urgency frame. The same detection and investigation logic applies, but AGC-008 is more likely to succeed because it preys on security-conscious behavior rather than curiosity.

**Where in this lab's tooling:**
- **Endpoint (Sysmon):** EID 1 (Process Create) captures the browser/PowerShell process that makes the outbound request. EID 3 (Network Connect) would capture the connection to 10.10.40.10.
- **Wazuh:** Standard logon events. No rule distinguishes a phishing-form POST from legitimate web traffic.
- **Network (Security Onion):** HTTP POST from 10.10.10.103 to 10.10.40.10 with form data.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Wazuh agent Active, Sysmon running.
- `EXT-ATTACKER-SIM` running with lab-sink on port 80 (same `/portal-login` credential harvester used across the phishing campaign).

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 18:17:05 | Click password-reset link | COMPROMISED-HOST-01 | `GET http://10.10.40.10/portal-login` — HTTP 200, credential form with username + password fields |
| 2 | 2026-09-15 18:17:06 | Submit "current password" | COMPROMISED-HOST-01 | `POST http://10.10.40.10/portal-login` — body: `username=michael.chen&password=[REDACTED]&current_password=[REDACTED]&new_password=[REDACTED]` |
| 3 | 2026-09-15 18:17:06 | Server confirms capture | EXT-ATTACKER-SIM | HTTP 200: "Sign-in received. Redirecting..." |

**Cleanup:** No persistent artifacts beyond network logs.

## SOC Perspective

### Detection

**Automated alerts:** No phishing-specific alert. Wazuh agent reconnecting after VM cold boot — standard logon events expected once the agent re-registers.

**Sysmon telemetry (COMPROMISED-HOST-01):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 18:17:05 | 1 | Process Create | `powershell.exe` (PID 5264), parent: `VBoxService.exe` — the process that made the outbound HTTP request to the credential harvester |

**Key detection signal:** Same as AGC-003 — outbound HTTP POST carrying credential-shaped form data (`username=...&password=...`) to a non-corporate IP address. The distinguishing feature of AGC-008 is the pretext, not the technical indicator.

### Investigation

**Step 1 — Outbound POST confirmation:**
At 18:17:06 UTC, a POST request was sent from 10.10.10.103 to 10.10.40.10/portal-login with URL-encoded form data containing `username=michael.chen`, `password=[REDACTED]`, `current_password=[REDACTED]`, and `new_password=[REDACTED]`. The server responded with HTTP 200 and "Sign-in received. Redirecting..." — confirming the credentials were captured.

**Step 2 — Destination verification:**
The destination `10.10.40.10` does not match any Ashford Grove Capital corporate endpoint. The legitimate password-reset endpoint would be on the domain controller at `ashfordgrove.local` (10.10.10.100), not on an external IP in the 10.10.40.0/24 (DMZ-External) subnet. This is a non-corporate, attacker-controlled destination.

**Step 3 — Cross-reference with AGC-003:**
The same credential-harvesting infrastructure (`10.10.40.10/portal-login`) was used in AGC-003. The server response ("Sign-in received. Redirecting...") is identical. This confirms the same campaign with a different social-engineering pretext.

**Step 4 — AGC-085 False Positive relationship:**
AGC-085 (False Positive: off-hours service account logon) is the FP twin of this scenario. If the credentials harvested here were used later by the attacker during off-hours, the resulting authentication event would produce the same pattern of "anomalous off-hours logon" that AGC-085 is built to distinguish as benign (service account). A SOC analyst must determine whether an off-hours logon uses a service account (AGC-085, benign) or compromised user credentials (post-AGC-008 exploitation, malicious).

### Report

**Verdict: True Positive** — Confirmed credential harvesting via password-reset phishing lure.

**Confidence: Critical** — The evidence chain is unambiguous:
1. POST to non-corporate IP (10.10.40.10) carrying cleartext credentials
2. Server confirmed receipt ("Sign-in received. Redirecting...")
3. Destination does not match corporate password-reset endpoint (ashfordgrove.local)
4. Same campaign infrastructure as AGC-001 through AGC-007

**Response recommendation:**
1. **Immediate password reset** for `michael.chen` on the domain controller — the account is compromised.
2. **Treat the account as compromised** — revoke active sessions, invalidate cached Kerberos tickets.
3. **Block the destination** (10.10.40.10) at the firewall.
4. **Search other mailboxes** for the same password-reset email (Subject/sender pattern match).
5. **Detection engineering:** Alert on outbound POST requests to non-corporate IPs where the request body contains `password=` or `current_password=` patterns.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Initial Access (TA0001) | T1566.002 | Phishing: Spearphishing Link | Password-reset-pretext email links to `http://10.10.40.10/portal-login`; victim submits credentials via POST; server confirms capture ("Sign-in received"); non-corporate destination confirmed; same campaign as AGC-001–007 | Critical |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
