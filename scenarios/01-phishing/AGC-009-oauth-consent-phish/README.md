# AGC-009 — OAuth-Consent Phishing Review

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

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
| Chain | ◀ AGC-008 · next AGC-010 ▶ |
| One-line Summary | Simulated OAuth consent phishing — victim clicks "Allow" on a fake consent screen granting read-email/read-files permissions to an attacker-controlled app. |

## Attacker Perspective

### Tradecraft

**What:** OAuth/consent phishing — the attacker creates a malicious application and sends the victim a link to an OAuth consent screen that requests broad permissions (read email, read files, read calendar). When the victim clicks "Allow," the attacker's application receives an OAuth token that grants persistent access to the victim's data — without needing the victim's password. The token survives password resets.

**Why at this lifecycle stage:** This technique is especially dangerous because:
1. **Password reset does not revoke OAuth grants.** If the SOC's incident response playbook stops at "reset the user's password," the attacker retains access via the OAuth token. Revoking the malicious application's consent grant is a separate remediation step.
2. **The consent screen looks legitimate** — it mimics the trusted pattern users see from real applications (Google/Microsoft "Allow this app to access your...").
3. **Persistence without malware** — no file is dropped on the endpoint, no backdoor is installed. The attacker accesses data through legitimate API calls using the granted token.

**Lab limitations:** This lab does not include a real Identity Provider (IdP) such as Azure AD/Entra ID or Google Workspace. The simulation demonstrates the **concept** of consent phishing — the outbound request and "Allow" action — but cannot produce the real detection telemetry (IdP audit logs showing a new application consent grant). This is explicitly documented.

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

**Automated alerts:** None. This lab's infrastructure cannot produce the telemetry needed to detect OAuth consent phishing.

**What a real SOC would see (cloud-integrated environment):**
- **IdP audit log:** New application consent grant for `malicious-scheduler-app` with scopes `mail.read`, `files.read`, `calendars.read`.
- **Unusual application:** The application would be unrecognized — not in the organization's approved application list.
- **Broad permissions:** `mail.read` + `files.read` from a "scheduling tool" is disproportionate — a calendar app needs `calendars.read`, not email and file access.

**Lab telemetry (limited):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 18:19:05 | 1 | Process Create | `powershell.exe` (PID 2928) — process that made the outbound HTTP request simulating the consent flow |

### Investigation

**Step 1 — Confirm outbound request:**
The victim's endpoint made an HTTP GET to `10.10.40.10/portal-login` (simulating the consent screen) followed by an HTTP POST with `action=allow` and broad permission scopes. The server confirmed the grant with "Sign-in received. Redirecting..."

**Step 2 — What a cloud-integrated SOC would investigate:**
In a real environment, the SOC analyst would:
1. **Review IdP audit logs** for new application consent grants.
2. **Check the application's registration** — is it a known/approved app? Who registered it?
3. **Review the granted scopes** — are they proportionate to the app's stated purpose?
4. **Check if other users granted consent** to the same app (campaign scope).
5. **Revoke the OAuth token** — this is the critical remediation step.

**Step 3 — Lab limitation statement:**
This lab cannot produce the actual detection telemetry for this technique. In a cloud-integrated SOC (Azure AD/Entra ID, Google Workspace), the detection signal is the IdP audit log entry showing a new application consent grant. The lab demonstrates the concept — the outbound request pattern and the "Allow" action — but the SOC analyst's real workflow requires IdP integration that this lab does not have.

**Step 4 — Key insight: password reset is insufficient:**
If the SOC's response to a compromised account stops at "reset the password and terminate sessions," an OAuth consent grant survives. The attacker's application retains its token and continues to access the victim's email, files, and calendar. Remediation requires: (1) revoking the application's consent grant, (2) revoking any tokens issued to the application, and (3) blocking the application in the IdP.

### Report

**Verdict: True Positive (conceptual)** — The outbound request pattern and consent grant action were confirmed, but real detection telemetry cannot be produced in this lab.

**Confidence: Medium** — Lab evidence (a single HTTP request to a consent-styled page) is weak on its own. The scenario's value is in identifying the detection gap and the critical remediation difference: OAuth token revocation versus password reset.

**Response recommendation:**
1. **Revoke the OAuth consent grant** for the malicious application in the IdP admin console.
2. **Revoke all tokens** issued to the application.
3. **Block the application** in the organization's IdP to prevent re-consent.
4. **Search for other victims** — query the IdP audit logs for other users who granted consent to the same application.
5. **Update the playbook:** Ensure the incident response playbook for compromised accounts includes OAuth token revocation as a mandatory step, separate from password reset.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Credential Access (TA0006) | T1528 | Steal Application Access Token | Simulated OAuth consent grant — POST with `action=allow&scope=mail.read+files.read+calendars.read` to attacker server; HTTP 200 confirmation. Lab limitation: no real IdP audit log. Conceptual demonstration. | Medium |

## Evidence

Screenshots: to be added manually by the analyst.
