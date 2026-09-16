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

**What:** A phishing email styled as an automated security notice: "Your Ashford Grove Capital password expires in 24 hours — reset now to avoid lockout." The link leads to a credential-harvesting page on attacker infrastructure with "current password" and "new password" fields, so the victim hands over a valid credential while thinking they are rotating it.

**Why at this lifecycle stage:** The password-reset frame works because it (1) manufactures urgency ("24 hours"), (2) matches an action users expect to perform anyway, and (3) turns the user's own caution against them — they believe they are protecting the account. The attacker ends up with the victim's current, valid credentials.

**Comparison with AGC-003:** The delivery (link → credential page → POST) is nearly identical to AGC-003. Only the frame differs: AGC-003 used a "review document" pretext; AGC-008 uses a security notice with a deadline. Detection and investigation are the same, but AGC-008 is the more likely to land because it preys on caution rather than curiosity.

**Where in this lab's tooling:**
- **Endpoint (Sysmon):** Sysmon EID 1 (Process Create) captures the browser or PowerShell process that makes the outbound request. EID 3 (Network Connect) would capture the connection to 10.10.40.10.
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

**Automated alerts:** No phishing-specific alert fired. The Wazuh agent was reconnecting after a VM cold boot; the standard logon events appear once it re-registers.

**Sysmon telemetry (COMPROMISED-HOST-01):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 18:17:05 | 1 | Process Create | `powershell.exe` (PID 5264), parent: `VBoxService.exe` — the process that made the outbound HTTP request to the credential harvester |

**Key detection signal:** Same as AGC-003: an outbound HTTP POST carrying credential-shaped form data (`username=...&password=...`) to a non-corporate IP. What sets AGC-008 apart is the pretext, not the indicator.

### Investigation

**Step 1 — Outbound POST confirmation:**
At 18:17:06 UTC, 10.10.10.103 sent a POST to 10.10.40.10/portal-login with URL-encoded form data: `username=michael.chen`, `password=[REDACTED]`, `current_password=[REDACTED]`, and `new_password=[REDACTED]`. The server answered HTTP 200 with "Sign-in received. Redirecting..." — the credentials landed.

**Step 2 — Destination verification:**
`10.10.40.10` is not an Ashford Grove Capital endpoint. A real password reset would go to the domain controller for `ashfordgrove.local` (10.10.10.100), not to an external IP in the 10.10.40.0/24 (DMZ-External) subnet. The destination is attacker-controlled.

**Step 3 — Cross-reference with AGC-003:**
AGC-003 used the same harvester (`10.10.40.10/portal-login`) and drew the same response ("Sign-in received. Redirecting..."). Same campaign, different pretext.

**Step 4 — AGC-085 False Positive relationship:**
AGC-085 (False Positive: off-hours service account logon) is this scenario's FP twin. If the attacker later used the credentials harvested here during off-hours, the authentication event would look like the "anomalous off-hours logon" that AGC-085 exists to clear as benign. The analyst has to tell an off-hours service-account logon (AGC-085, benign) from a logon with stolen user credentials (post-AGC-008, malicious).

### Report

**Verdict: True Positive** — Confirmed credential harvesting via password-reset phishing lure.

**Confidence: Critical** — Four points, none of them circumstantial:
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
