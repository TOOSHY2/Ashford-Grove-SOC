# AGC-006 — HTML Attachment Redirect Indicator

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-006` |
| Category | `01-phishing` — Phishing & Initial Access |
| MITRE Technique | `T1566.001` Phishing: Spearphishing Attachment |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | N/A — no automated alert; Sysmon EID 11 captured the file write but no rule correlates it with the redirect |
| Time to Triage | 04:00 (from attachment save to redirect chain confirmation) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103), `EXT-ATTACKER-SIM` (10.10.40.10) |
| Chain | ◀ [AGC-005](../AGC-005-url-shortener-redirect/README.md) · next [AGC-007](../AGC-007-macro-lure-document/README.md) ▶ |
| One-line Summary | HTML email attachment with meta-refresh auto-redirects the victim's browser to the credential-harvesting page when opened locally. |

## Attacker Perspective

### Tradecraft

**What:** HTML smuggling via meta-refresh. The attacker attaches an HTML file whose `<meta http-equiv="refresh" content="0;url=...">` tag sends the browser to the phishing page the moment the file opens. In AGC-001 through AGC-005 the URL sat in the email body or a QR code; here it is buried inside the attachment. The body itself can be spotless — "Please review the attached invoice."

**Why at this lifecycle stage:** This gets past body URL scanning more completely than AGC-004 (QR) or AGC-005 (shortener): the body contains zero URLs. The URL lives in an `.html` attachment, which many gateways wave through as a document format. Once the victim double-clicks the file, the redirect runs on its own.

**Where in this lab's tooling:**
- **Email gateway:** None. Even with one, the `.html` attachment would have to be sandboxed or parsed to expose the meta-refresh URL, and many gateways do not inspect HTML attachments that deeply.
- **Endpoint (Sysmon):** **Sysmon EID 11 (File Create)** captures the `.html` file landing in the Downloads folder — the strongest signal here. The SwiftOnSecurity config tags it `RuleName: Downloads`. EID 1 (Process Create) captures the PowerShell or browser process. EID 3 captures the outbound connection.
- **Wazuh:** No rule correlates an `.html` write in Downloads with a following outbound HTTP request.
- **Network (Security Onion):** Captures the outbound HTTP request to 10.10.40.10.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Wazuh agent Active, Sysmon running.
- `EXT-ATTACKER-SIM` running with lab-sink on port 80.

**Malicious HTML attachment content (`Invoice-2026-Q3.html`):**
```html
<!DOCTYPE html>
<html>
<head>
<meta http-equiv="refresh" content="0;url=http://10.10.40.10/portal-login">
<title>Invoice-2026-Q3.html</title>
</head>
<body>
<p>Loading document... please wait.</p>
</body>
</html>
```

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 17:39:51 | Save HTML attachment to Downloads | COMPROMISED-HOST-01 | `Invoice-2026-Q3.html` written to `C:\Users\michael.chen\Downloads\` |
| 2 | 2026-09-15 17:39:51 | Open HTML file (simulated) | COMPROMISED-HOST-01 | Read file content, extracted meta-refresh URL: `http://10.10.40.10/portal-login` |
| 3 | 2026-09-15 17:39:51 | Follow meta-refresh redirect | COMPROMISED-HOST-01 | `GET http://10.10.40.10/portal-login` — HTTP 200, credential form detected |

**Cleanup:** HTML file left in Downloads as evidence artifact.

## SOC Perspective

### Detection

**Automated alerts:** No phishing-specific alert fired. Wazuh logged only the standard logon events from the guestcontrol session.

**Sysmon telemetry (COMPROMISED-HOST-01):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 17:39:51 | 11 | File Create | **RuleName: Downloads** — `powershell.exe` wrote `C:\Users\michael.chen\Downloads\Invoice-2026-Q3.html` |
| 2026-09-15 17:39:51 | 1 | Process Create | `powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc006-sim.ps1`, parent: `VBoxService.exe` |

**Key detection signal:** Sysmon EID 11 with `RuleName: Downloads` is the strongest indicator. An `.html` file in a user's Downloads folder is odd on its own — business documents arrive as `.pdf`, `.docx`, `.xlsx`. An HTML file in Downloads followed at once by an outbound HTTP request to a non-corporate IP is a high-fidelity signal for this pattern.

### Investigation

**Step 1 — Sysmon EID 11 file write:**
`Invoice-2026-Q3.html` was written to `C:\Users\michael.chen\Downloads\` at 17:39:51. Sysmon tagged it `RuleName: Downloads`, since the SwiftOnSecurity config watches writes to user Download folders. The writer was `powershell.exe`; in a real attack it would be the mail client or browser saving the attachment.

**Step 2 — Correlate file write with browser launch:**
In the same second (17:39:51), a `powershell.exe` process made an outbound HTTP request to `10.10.40.10/portal-login`. A real attack would run: (1) mail client saves the `.html` to Downloads, (2) user double-clicks it, (3) the default browser opens and honors the meta-refresh, (4) the browser connects to the phishing server. The short gap between file write and outbound request is the tell.

**Step 3 — Inspect the HTML content:**
The file contains `<meta http-equiv="refresh" content="0;url=http://10.10.40.10/portal-login">` — a redirect with a zero-second delay. No invoice needs a meta-refresh; the tag is there to phish.

**Step 4 — Cross-reference destination:**
The redirect target `10.10.40.10/portal-login` is the credential-harvesting infrastructure from AGC-001 through AGC-005. Same campaign, different delivery vector.

### Report

**Verdict: True Positive** — Confirmed phishing attempt via HTML attachment with meta-refresh redirect to credential harvester.

**Confidence: High** — The full chain is confirmed:
1. HTML file written to user Downloads folder (Sysmon EID 11, RuleName: Downloads)
2. File contains meta-refresh redirect to `http://10.10.40.10/portal-login` (zero delay)
3. Redirect destination is the same credential-harvesting page from prior campaign scenarios
4. An HTML "invoice" has no business reason to redirect the browser anywhere

**Response recommendation:**
1. **Quarantine the attachment** and any copies in other users' mailboxes (search on Subject or hash).
2. **Detection engineering:** Create a Wazuh rule that alerts on Sysmon EID 11 where `TargetFilename` matches `*.html` or `*.htm` in `Downloads`, `AppData\Local\Temp`, or `Desktop` — none of those is a normal place for a business HTML file.
3. **Email policy:** Block or sandbox `.html`/`.htm` attachments at the gateway. Almost no legitimate mail needs them, and phishing kits lean on them.
4. **Enhanced rule:** Correlate EID 11 (`.html` write to Downloads) with EID 3 (outbound connection to an external IP) inside a 30-second window — that two-event pair is the HTML-smuggling signature.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Initial Access (TA0001) | T1566.001 | Phishing: Spearphishing Attachment | HTML attachment `Invoice-2026-Q3.html` saved to Downloads; meta-refresh redirect to `http://10.10.40.10/portal-login`; Sysmon EID 11 file write (RuleName: Downloads) + EID 1 process create; HTTP 200 credential harvester | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
