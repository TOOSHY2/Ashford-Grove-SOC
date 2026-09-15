# AGC-001 — Spoofed Display-Name Phishing

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-001` |
| Category | `01-phishing` — Phishing & Initial Access |
| MITRE Technique | `T1566.002` Phishing: Spearphishing Link |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | N/A — no automated alert; detection via manual email-header inspection |
| Time to Triage | 04:00 (from email inspection to verdict) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103), `EXT-ATTACKER-SIM` (10.10.40.10) |
| Chain | ◀ — (first scenario) · next AGC-002 ▶ |
| One-line Summary | Spoofed "IT Support" display name delivers credential-harvesting link to an employee workstation. |

## Attacker Perspective

### Tradecraft

**What:** Display-name spoofing — the attacker sets the `From` header's display name to a trusted identity ("IT Support") while using an entirely different sending domain (`ashford-grove-support.local` instead of the legitimate `ashfordgrove.local`). Most email clients render the display name prominently and hide the actual address, making this a low-effort, high-success phishing vector.

**Why at this lifecycle stage:** This is the initial access point (MITRE TA0001). The attacker needs a foothold before any later-stage technique is possible. A credential-harvesting phish is preferred over a payload-delivery phish when the target has endpoint protection (Defender + Sysmon) because clicking a link generates far less endpoint telemetry than executing an attachment.

**Where in this lab's tooling:**
- **Email gateway:** None. The lab has no MTA or email gateway, so SPF/DKIM/DMARC checks do not exist. Detection depends entirely on manual header inspection or user reporting.
- **Network (Security Onion):** Zeek `http.log` and `conn.log` capture the outbound HTTP request from COMPROMISED-HOST-01 (10.10.10.103) to the attacker-controlled sink at EXT-ATTACKER-SIM (10.10.40.10). Suricata may flag the connection if a relevant rule matches.
- **Endpoint (Sysmon):** Sysmon EID 1 (Process Create) logs the browser/PowerShell process making the request. With the SwiftOnSecurity config, EID 3 (Network Connection) is filtered for common processes, so no network event is logged for this specific connection.
- **Wazuh:** No built-in rule triggers specifically for display-name spoofing. Wazuh records Windows logon events (Rule 60118) and privilege assignments (Rule 67028) for the user session but has no phishing-specific detection in default rulesets.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Wazuh agent 004 Active, Sysmon running.
- `EXT-ATTACKER-SIM` running with lab-sink web server on ports 80/443 (`attacker-smtp.service` active, HTTP returning 200 at `/portal-login`).
- `WAZUH-SIEM-01` and `SECURITY-ONION-01` running.
- Pre-staged .eml file at `C:\PhishingDelivery\AGC-001-spoofed-display-name.eml` on COMPROMISED-HOST-01.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 16:48:27 | Baseline verification | Host | Wazuh agent 004 (COMPROMISED-01) confirmed Active via `agent_control -l` |
| 2 | 2026-09-15 16:48:27 | Baseline screenshot | COMPROMISED-HOST-01 | `01-baseline-desktop.png` — desktop with Edge browser open |
| 3 | 2026-09-15 16:50:30 | Phishing link click | COMPROMISED-HOST-01 | `Invoke-WebRequest -Uri 'http://10.10.40.10/portal-login'` as `michael.chen` |
| 4 | 2026-09-15 16:50:31 | Response received | COMPROMISED-HOST-01 | HTTP 200 — "Acme Corp - Secure Document Portal" credential harvesting form |

**Phishing email content** (`C:\PhishingDelivery\AGC-001-spoofed-display-name.eml`):
```
From: "IT Support" <it-support@ashford-grove-support.local>
To: michael.chen@ashfordgrove.local
Subject: Mailbox Storage Almost Full
Date: Mon, 15 Sep 2026 12:00:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Your mailbox is almost full. Click here to request more space:
http://10.10.40.10/portal-login
```

**Key evidence — the spoof:**
- Display name: `IT Support` (trusted)
- Actual sender: `it-support@ashford-grove-support.local` (attacker-controlled domain, NOT `ashfordgrove.local`)
- Link destination: `10.10.40.10` (EXT-SIM-NET — external attacker infrastructure)

**Credential harvesting page** returned:
```html
<title>Acme Corp - Secure Document Portal</title>
<!-- Login form styled to look legitimate, hosted on attacker infrastructure -->
```

**Cleanup:** No persistent changes made. PowerShell request was stateless. VM can be reverted to baseline snapshot `post-domain-rename-2026-09-13`.

## SOC Perspective

### Detection

**Automated alerts:** No phishing-specific alert fired. Wazuh generated standard Windows logon events:

| Timestamp (UTC) | Rule ID | Level | Description |
|---|---|---|---|
| 2026-09-15 16:50:50 | 60118 | 3 | Windows Workstation Logon Success |
| 2026-09-15 16:50:44 | 67028 | 3 | Special privileges assigned to new logon |
| 2026-09-15 16:50:44 | 67023 | 3 | Non service account logged off |

**Sysmon telemetry (COMPROMISED-HOST-01):**
- EID 1 (Process Create): `powershell.exe` executed as `michael.chen.ASHFORDGROVE` at 16:50:50 UTC
- EID 11 (File Create): PSScriptPolicyTest temp files created during execution
- EID 3 (Network Connection): Not captured — filtered by SwiftOnSecurity Sysmon config for PowerShell outbound

**Detection gap identified:** The current lab stack has no automated mechanism to detect display-name spoofing or email header anomalies. Detection relies entirely on:
1. User awareness (recognizing the mismatch)
2. Manual inspection of raw email headers
3. Network monitoring for connections to known-bad or unusual external IPs

### Investigation

**Step 1 — Email header analysis:**
Inspected the .eml file raw headers. The `From` header shows:
- Display name: `IT Support`
- Actual address: `it-support@ashford-grove-support.local`

The sending domain `ashford-grove-support.local` is **not** the legitimate organizational domain `ashfordgrove.local`. The subtle difference (hyphenated, with `-support` suffix) is a classic typosquat/lookalike pattern designed to pass casual visual inspection.

**Step 2 — Link analysis:**
The email body links to `http://10.10.40.10/portal-login`. This IP address resolves to `EXT-ATTACKER-SIM` on the EXT-SIM-NET (10.10.40.0/24), which is outside the organization's trusted network zones (LAN-NET 10.10.10.0/24, SOC-NET 10.10.30.0/24). The page returned a credential-harvesting form titled "Acme Corp - Secure Document Portal" — a generic name inconsistent with the organization's branding ("Ashford Grove Capital").

**Step 3 — Endpoint impact assessment:**
The victim (`michael.chen`) clicked the link. HTTP 200 response confirmed the page loaded. However, no credential submission was performed (the phish-click simulation only loaded the page, did not submit form data). Sysmon shows the PowerShell process creation but no further suspicious activity chain.

**Step 4 — Network correlation:**
Connection from 10.10.10.103 (COMPROMISED-HOST-01) to 10.10.40.10 (EXT-ATTACKER-SIM) on port 80 at approximately 16:50:30 UTC. Security Onion Zeek logs would capture this in `conn.log` and `http.log` (Security Onion Guest Additions unavailable for automated extraction; manual verification via SOC Console recommended).

**Dead end:** Checked Wazuh for phishing-specific rules — none exist in the default ruleset. Rule 60118 (Workstation Logon Success) fires for the guestcontrol session, not for the phishing event itself.

### Report

**Verdict: True Positive** — Confirmed phishing attempt via spoofed display name targeting employee `michael.chen`.

**Confidence: High** — Three independent indicators confirm malicious intent:
1. From-address domain (`ashford-grove-support.local`) does not match the legitimate domain (`ashfordgrove.local`)
2. Link destination (10.10.40.10) is on an external, untrusted network segment
3. Landing page is a generic credential-harvesting form inconsistent with organizational branding

**Response recommendation:**
1. **Immediate:** Block `10.10.40.10` at the firewall (OPNsense-FW). Block/sinkhole `ashford-grove-support.local` in DNS.
2. **Containment:** Reset `michael.chen`'s credentials if any were submitted. Inspect browser history and cache on COMPROMISED-HOST-01 for evidence of form submission.
3. **Detection engineering:** Create a custom Wazuh rule or email gateway policy to flag mismatches between `From` display name and domain. Implement SPF/DKIM/DMARC checking.
4. **Awareness:** Distribute advisory to all users about display-name spoofing, using this incident as a sanitized example.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Initial Access (TA0001) | T1566.002 | Phishing: Spearphishing Link | .eml file with spoofed display name "IT Support" from `ashford-grove-support.local`; link to `http://10.10.40.10/portal-login` (credential harvesting page); HTTP 200 response confirmed | High |

## Evidence Screenshots

| # | Filename | Description |
|---|---|---|
| 01 | `screenshots/01-baseline-desktop.png` | COMPROMISED-HOST-01 desktop state before scenario execution |
| 02 | `screenshots/02-wazuh-dashboard-baseline.png` | MGMT-GUI-TEMP desktop (Wazuh dashboard access point) |
| 03 | `screenshots/03-email-opened.png` | COMPROMISED-HOST-01 showing Edge browser with phishing page loaded |
| 04 | `screenshots/04-credential-harvesting-page.png` | COMPROMISED-HOST-01 showing the credential harvesting page after link click |
