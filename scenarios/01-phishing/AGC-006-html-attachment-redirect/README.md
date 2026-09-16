# AGC-006 — HTML Attachment Redirect Indicator

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

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

**What:** HTML smuggling via meta-refresh — the attacker sends an HTML file as an email attachment. The HTML contains a `<meta http-equiv="refresh" content="0;url=...">` tag that instantly redirects the browser to the phishing page when the file is opened. Unlike AGC-001 through AGC-005 where the malicious URL is in the email body (or encoded in a QR code), here the URL is buried inside an attachment file. The email body itself can be completely clean — just "Please review the attached invoice."

**Why at this lifecycle stage:** This technique bypasses email-body URL scanning even more completely than AGC-004 (QR) or AGC-005 (shortener). The email body contains zero URLs. The malicious URL is inside an `.html` file attachment that many gateways allow through because HTML is considered a document format. When the victim opens the attachment, the redirect happens automatically — no click required beyond double-clicking the file.

**Where in this lab's tooling:**
- **Email gateway:** None. Even with one, the `.html` attachment would need to be sandboxed or its content parsed to find the meta-refresh URL. Many gateways do not deeply inspect HTML attachments.
- **Endpoint (Sysmon):** **EID 11 (File Create)** captures the `.html` file being saved to the Downloads folder — this is the strongest detection signal. Sysmon's SwiftOnSecurity config even tags it with `RuleName: Downloads`. EID 1 (Process Create) captures the PowerShell/browser process. EID 3 captures the outbound connection.
- **Wazuh:** No rule correlates `.html` file creation in Downloads with subsequent outbound HTTP requests.
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

**Automated alerts:** No phishing-specific alert. Wazuh logged standard logon events from the guestcontrol session.

**Sysmon telemetry (COMPROMISED-HOST-01):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 17:39:51 | 11 | File Create | **RuleName: Downloads** — `powershell.exe` wrote `C:\Users\michael.chen\Downloads\Invoice-2026-Q3.html` |
| 2026-09-15 17:39:51 | 1 | Process Create | `powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc006-sim.ps1`, parent: `VBoxService.exe` |

**Key detection signal:** Sysmon EID 11 with `RuleName: Downloads` is the strongest indicator. An `.html` file appearing in a user's Downloads folder is unusual — legitimate business documents are typically `.pdf`, `.docx`, `.xlsx`. An HTML file in Downloads that immediately triggers an outbound HTTP request to a non-corporate IP is a high-fidelity signal for this attack pattern.

### Investigation

**Step 1 — Sysmon EID 11 file write:**
The `.html` file `Invoice-2026-Q3.html` was written to `C:\Users\michael.chen\Downloads\` at 17:39:51. Sysmon tagged this with `RuleName: Downloads` — the SwiftOnSecurity config specifically monitors file writes to user Download folders. The writing process was `powershell.exe` (in the real attack, this would be the email client or browser saving the attachment).

**Step 2 — Correlate file write with browser launch:**
Within the same second (17:39:51), a `powershell.exe` process made an outbound HTTP request to `10.10.40.10/portal-login`. In a real attack, the timeline would be: (1) email client saves `.html` to Downloads, (2) user double-clicks the file, (3) default browser opens and executes the meta-refresh, (4) browser connects to the phishing server. The tight timing window between file creation and outbound request is a strong indicator.

**Step 3 — Inspect the HTML content:**
The file contains `<meta http-equiv="refresh" content="0;url=http://10.10.40.10/portal-login">` — an immediate redirect with zero-second delay. There is no legitimate business reason for an HTML "invoice" to contain a meta-refresh redirect. This is a deliberate phishing technique.

**Step 4 — Cross-reference destination:**
The redirect target `10.10.40.10/portal-login` is the same credential-harvesting infrastructure used in AGC-001 through AGC-005. Same campaign, different delivery vector.

### Report

**Verdict: True Positive** — Confirmed phishing attempt via HTML attachment with meta-refresh redirect to credential harvester.

**Confidence: High** — The full chain is confirmed:
1. HTML file written to user Downloads folder (Sysmon EID 11, RuleName: Downloads)
2. File contains meta-refresh redirect to `http://10.10.40.10/portal-login` (zero delay)
3. Redirect destination is the same credential-harvesting page from prior campaign scenarios
4. No legitimate business reason for an HTML "invoice" to contain a browser redirect

**Response recommendation:**
1. **Quarantine the attachment** and any copies in other users' mailboxes (search for Subject/hash match).
2. **Detection engineering:** Create a Wazuh rule that alerts on Sysmon EID 11 where `TargetFilename` matches `*.html` or `*.htm` in `Downloads`, `AppData\Local\Temp`, or `Desktop` — these are uncommon for legitimate business use.
3. **Email policy:** Block or sandbox `.html`/`.htm` attachments at the email gateway. These file types are rarely needed as legitimate attachments and are commonly used for phishing.
4. **Enhanced rule:** Correlate EID 11 (`.html` file write to Downloads) with EID 3 (outbound connection to external IP) within a 30-second window — this two-event pattern is characteristic of HTML smuggling attacks.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Initial Access (TA0001) | T1566.001 | Phishing: Spearphishing Attachment | HTML attachment `Invoice-2026-Q3.html` saved to Downloads; meta-refresh redirect to `http://10.10.40.10/portal-login`; Sysmon EID 11 file write (RuleName: Downloads) + EID 1 process create; HTTP 200 credential harvester | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
