# AGC-009 — OAuth-Consent Phishing Review

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-009` |
| Category | `01-phishing` — Phishing & Initial Access |
| MITRE Technique | `T1528` Steal Application Access Token |
| Verdict | True Positive (conceptual) |
| Confidence | Medium |
| Time to Detect | N/A — lab cannot produce real OAuth consent telemetry; detection requires cloud IdP audit logs |
| Time to Triage | Conceptual — real-world triage requires IdP-integrated SOC |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103), `EXT-ATTACKER-SIM` (10.10.40.10) |
| Chain | ◀ [AGC-008](../AGC-008-password-reset-lure/README.md) · next [AGC-010](../AGC-010-user-reported-triage/README.md) ▶ |
| One-line Summary | Simulated OAuth consent phishing — victim clicks "Allow" on a fake consent screen granting read-email/read-files permissions to an attacker-controlled app. |

## Attacker Perspective

### Tradecraft

**What:** OAuth consent phishing. The attacker registers an application and sends the victim a link to a consent screen asking for broad permissions (read email, read files, read calendar). When the victim clicks "Allow," the application receives an OAuth token with standing access to the victim's data — no password needed, and the token survives a password reset.

**Why at this lifecycle stage:** Three things make this technique worth its own scenario:
1. **Password reset does not revoke OAuth grants.** If the playbook stops at "reset the user's password," the attacker keeps access through the token. Revoking the application's consent grant is a separate step.
2. **The consent screen looks legitimate** — it copies the pattern users see from real Google and Microsoft apps ("Allow this app to access your...").
3. **Persistence without malware** — nothing is dropped on the endpoint and no backdoor is installed. The attacker reads data through ordinary API calls with the granted token.

**Lab limitations:** The lab has no Identity Provider (IdP) such as Azure AD/Entra ID or Google Workspace. The simulation shows the **concept** — the outbound request and the "Allow" action — but cannot produce the real detection telemetry, an IdP audit log entry for a new application consent grant.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Sysmon running.
- `EXT-ATTACKER-SIM` running with lab-sink on port 80 (simulating OAuth consent page).

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 18:19:05 | Navigate to consent page | COMPROMISED-HOST-01 | `GET http://10.10.40.10/portal-login` — HTTP 200 (1440 bytes), simulating OAuth consent screen |
| 2 | 2026-09-15 18:19:05 | Click "Allow" | COMPROMISED-HOST-01 | `POST http://10.10.40.10/portal-login` — body: `action=allow&scope=mail.read+files.read+calendars.read&client_id=malicious-scheduler-app` |
| 3 | 2026-09-15 18:19:05 | Server captures consent | EXT-ATTACKER-SIM | HTTP 200: "Sign-in received. Redirecting..." — consent grant logged server-side |

**Cleanup:** No persistent artifacts beyond network logs.

## SOC Perspective

### Detection

**Automated alerts:** None fired. The lab cannot produce the telemetry that would detect OAuth consent phishing.

**What a real SOC would see (cloud-integrated environment):**
- **IdP audit log:** New application consent grant for `malicious-scheduler-app` with scopes `mail.read`, `files.read`, `calendars.read`.
- **Unusual application:** `malicious-scheduler-app` is not on the organization's approved application list.
- **Broad permissions:** `mail.read` + `files.read` from a "scheduling tool" is disproportionate — a calendar app needs `calendars.read`, not email and file access.

**Lab telemetry (limited):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 18:19:05 | 1 | Process Create | `powershell.exe` (PID 2928) — process that made the outbound HTTP request simulating the consent flow |

### Investigation

**Step 1 — Confirm outbound request:**
COMPROMISED-HOST-01 sent an HTTP GET to `10.10.40.10/portal-login` (standing in for the consent screen), then a POST with `action=allow` and the three scopes. The server confirmed the grant with "Sign-in received. Redirecting..."

**Step 2 — What a cloud-integrated SOC would investigate:**
With an IdP in place, the analyst would:
1. **Review IdP audit logs** for new application consent grants.
2. **Check the application's registration** — is it a known/approved app? Who registered it?
3. **Review the granted scopes** — are they proportionate to the app's stated purpose?
4. **Check if other users granted consent** to the same app (campaign scope).
5. **Revoke the OAuth token** — the step a password reset does not cover.

**Step 3 — Lab limitation statement:**
The lab cannot produce the detection telemetry for this technique. In a cloud-integrated SOC (Azure AD/Entra ID, Google Workspace) the signal is the IdP audit log entry for a new application consent grant. What the lab shows is the request pattern and the "Allow" action; the real workflow needs IdP integration the lab does not have.

**Step 4 — Key insight: password reset is insufficient:**
If the response to a compromised account stops at "reset the password and terminate sessions," the consent grant survives and the application keeps reading the victim's email, files, and calendar. Remediation means: (1) revoke the application's consent grant, (2) revoke any tokens issued to it, and (3) block the application in the IdP.

### Report

**Verdict: True Positive (conceptual)** — The outbound request pattern and consent grant action were confirmed, but real detection telemetry cannot be produced in this lab.

**Confidence: Medium** — The lab evidence, one HTTP request to a consent-styled page, is thin on its own. The scenario's value is the detection gap it names and the remediation difference it forces: token revocation, not password reset.

**Response recommendation:**
1. **Revoke the OAuth consent grant** for the malicious application in the IdP admin console.
2. **Revoke all tokens** issued to the application.
3. **Block the application** in the organization's IdP to prevent re-consent.
4. **Search for other victims** — query the IdP audit logs for other users who granted consent to the same application.
5. **Update the playbook:** Make OAuth token revocation a required step in the compromised-account playbook, separate from password reset.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Credential Access (TA0006) | T1528 | Steal Application Access Token | Simulated OAuth consent grant — POST with `action=allow&scope=mail.read+files.read+calendars.read` to attacker server; HTTP 200 confirmation. Lab limitation: no real IdP audit log. Conceptual demonstration. | Medium |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
