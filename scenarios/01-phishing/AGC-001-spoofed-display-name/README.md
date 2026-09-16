# AGC-001 — Spoofed Display-Name Phishing

> **Disclosure:** Executed & documented by Claude Code under direction and review by Ali.

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
| Chain | ◀ — (first scenario) · next [AGC-002](../AGC-002-lookalike-domain/README.md) ▶ |
| One-line Summary | Spoofed "IT Support" display name delivers credential-harvesting link to an employee workstation. |

## Attacker Perspective

### Tradecraft

**What:** Display-name spoofing. The attacker sets the `From` header's display name to "IT Support" and sends from `ashford-grove-support.local` rather than the legitimate `ashfordgrove.local`. Most mail clients show the display name and hide the address, so the mismatch is easy to miss.

**Why at this lifecycle stage:** Initial access (MITRE TA0001) — nothing later in the chain happens without a foothold. The attacker chose a credential-harvesting link over an attachment because the target runs Defender and Sysmon, and a link click leaves far less endpoint telemetry than a payload execution.

**Where in this lab's tooling:**
- **Email gateway:** None. The lab has no MTA or gateway, so no SPF/DKIM/DMARC checks run. Detection depends on manual header inspection or a user report.
- **Network (Security Onion):** Zeek `http.log` and `conn.log` capture the outbound HTTP request from COMPROMISED-HOST-01 (10.10.10.103) to the attacker sink at EXT-ATTACKER-SIM (10.10.40.10). Suricata fires only if a rule matches the request.
- **Endpoint (Sysmon):** Sysmon EID 1 (Process Create) captures the browser or PowerShell process that makes the request. The SwiftOnSecurity config filters EID 3 (Network Connection) for common processes, so this connection produces no network event.
- **Wazuh:** No default rule covers display-name spoofing. Wazuh logs the user session's logon (Wazuh rule 60118) and privilege assignment (Wazuh rule 67028) but nothing phishing-specific.

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

**Cleanup:** The PowerShell request was stateless and left no persistent changes. The VM reverts to baseline snapshot `post-domain-rename-2026-09-13`.

## SOC Perspective

### Detection

**Automated alerts:** No phishing-specific alert fired. Wazuh logged only the standard Windows logon events:

| Timestamp (UTC) | Rule ID | Level | Description |
|---|---|---|---|
| 2026-09-15 16:50:50 | 60118 | 3 | Windows Workstation Logon Success |
| 2026-09-15 16:50:44 | 67028 | 3 | Special privileges assigned to new logon |
| 2026-09-15 16:50:44 | 67023 | 3 | Non service account logged off |

**Sysmon telemetry (COMPROMISED-HOST-01):**
- EID 1 (Process Create): `powershell.exe` executed as `michael.chen.ASHFORDGROVE` at 16:50:50 UTC
- EID 11 (File Create): PSScriptPolicyTest temp files created during execution
- EID 3 (Network Connection): Not captured — filtered by SwiftOnSecurity Sysmon config for PowerShell outbound

**Detection gap identified:** Nothing in the lab stack detects display-name spoofing or header anomalies automatically. Detection relies on:
1. User awareness (recognizing the mismatch)
2. Manual inspection of raw email headers
3. Network monitoring for connections to known-bad or unusual external IPs

### Investigation

**Step 1 — Email header analysis:**
Inspected the .eml file raw headers. The `From` header shows:
- Display name: `IT Support`
- Actual address: `it-support@ashford-grove-support.local`

The sending domain `ashford-grove-support.local` is **not** the organization's `ashfordgrove.local`. The hyphen and `-support` suffix are small enough to survive a glance at the inbox.

**Step 2 — Link analysis:**
The body links to `http://10.10.40.10/portal-login`. That IP is `EXT-ATTACKER-SIM` on EXT-SIM-NET (10.10.40.0/24), outside the trusted zones LAN-NET (10.10.10.0/24) and SOC-NET (10.10.30.0/24). The page returned a credential form titled "Acme Corp - Secure Document Portal", which does not match the organization's branding ("Ashford Grove Capital").

**Step 3 — Endpoint impact assessment:**
`michael.chen` clicked the link and the HTTP 200 confirms the page loaded. No credentials were submitted — the simulation fetched the page and stopped. Sysmon shows the PowerShell process creation and nothing after it.

**Step 4 — Network correlation:**
10.10.10.103 (COMPROMISED-HOST-01) connected to 10.10.40.10 (EXT-ATTACKER-SIM) on port 80 at about 16:50:30 UTC. Zeek on Security Onion should hold this in `conn.log` and `http.log`; Guest Additions are unavailable for automated extraction, so confirm it by hand in the SOC Console.

**Dead end:** Checked Wazuh for phishing-specific rules — none exist in the default ruleset. Wazuh rule 60118 (Workstation Logon Success) fires for the guestcontrol session, not for the phishing event itself.

### Report

**Verdict: True Positive** — Confirmed phishing attempt via spoofed display name targeting employee `michael.chen`.

**Confidence: High** — Three independent indicators confirm malicious intent:
1. From-address domain (`ashford-grove-support.local`) does not match the legitimate domain (`ashfordgrove.local`)
2. Link destination (10.10.40.10) is on an external, untrusted network segment
3. Landing page is a credential-harvesting form branded "Acme Corp", not "Ashford Grove Capital"

**Response recommendation:**
1. **Immediate:** Block `10.10.40.10` at the firewall (OPNsense-FW). Block/sinkhole `ashford-grove-support.local` in DNS.
2. **Containment:** Reset `michael.chen`'s credentials if any were submitted. Inspect browser history and cache on COMPROMISED-HOST-01 for evidence of form submission.
3. **Detection engineering:** Create a custom Wazuh rule or email gateway policy to flag mismatches between `From` display name and domain. Implement SPF/DKIM/DMARC checking.
4. **Awareness:** Send all users an advisory on display-name spoofing, using this email as a sanitized example.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Initial Access (TA0001) | T1566.002 | Phishing: Spearphishing Link | .eml file with spoofed display name "IT Support" from `ashford-grove-support.local`; link to `http://10.10.40.10/portal-login` (credential harvesting page); HTTP 200 response confirmed | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
