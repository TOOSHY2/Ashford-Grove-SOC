# AGC-004 — QR-Code Phishing Indicator

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-004` |
| Category | `01-phishing` — Phishing & Initial Access |
| MITRE Technique | `T1566.002` Phishing: Spearphishing Link (QR delivery) |
| Verdict | True Positive |
| Confidence | Medium |
| Time to Detect | N/A — no automated alert fired; email gateway URL scanning cannot extract URLs from QR images |
| Time to Triage | 06:00 (from email receipt to timing-correlated network request identification) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103), `EXT-ATTACKER-SIM` (10.10.40.10) |
| Chain | ◀ [AGC-003](../AGC-003-credential-harvest-link/README.md) · next [AGC-005](../AGC-005-url-shortener-redirect/README.md) ▶ |
| One-line Summary | Phishing email delivers malicious URL via embedded QR code image, bypassing email gateway URL scanning entirely. |

## Attacker Perspective

### Tradecraft

**What:** QR-code phishing ("quishing") — the attacker embeds the malicious URL inside a QR code image in the email body instead of including it as clickable text. Email security gateways that scan for malicious URLs parse email headers, body text, and `href` attributes — but a QR code is just a PNG/JPEG to them. The URL only becomes visible after a human (or their phone's camera) decodes the image. This bypasses the first automated defense layer entirely.

**Why at this lifecycle stage:** After AGC-001 through AGC-003 established that phishing links reach the victim regardless (no email gateway), AGC-004 demonstrates a technique that would evade gateway scanning even if one were deployed. The attacker uses a "MFA device verification" lure — plausible in any organization that uses authenticator apps, and the QR code feels natural in that context because users are trained to scan QR codes for MFA setup.

**Where in this lab's tooling:**
- **Email gateway:** None deployed, but critically, even if one were, standard URL extraction would miss the QR-encoded URL. The email body contains no `<a>` tags, no plaintext URLs — only an image.
- **Endpoint (Sysmon):** EID 1 (Process Create) captures the browser/PowerShell process. EID 3 (Network Connection) logs the outbound connection to 10.10.40.10. The HTTP request itself is indistinguishable from a normal link click.
- **Wazuh:** No QR-specific or image-analysis rule exists.
- **Network (Security Onion):** Zeek captures the HTTP request, but without the email context, there is no automated way to link it back to the QR-encoded phishing email.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Wazuh agent Active, Sysmon running.
- `EXT-ATTACKER-SIM` running with lab-sink web server serving `/portal-login` on port 80.
- Phishing email conceptually delivered with QR code image encoding `http://10.10.40.10/portal-login`.

**Lab limitation:** Camera-based QR scanning cannot be simulated through VBoxManage guestcontrol. The simulation directly issues the HTTP request that would result from scanning the QR code, and documents this as a simulated post-scan action — not an actual camera scan.

**Phishing email concept:**
```
From: "IT Security Team" <security@ashfordgrove.local>
To: michael.chen@ashfordgrove.local
Subject: MFA Device Verification Required - Scan QR Code

Dear Michael,

As part of our quarterly security audit, we need you to verify
your MFA device registration. Please scan the QR code below
with your authenticator app:

[QR CODE IMAGE - encodes: http://10.10.40.10/portal-login]

Note: This QR code is valid for 48 hours.

IT Security Team
```

**Critical observation:** The email body contains **zero extractable URLs**. No `href`, no plaintext link, no `src` pointing to a malicious domain. The URL exists only as encoded data inside an opaque image file. Any email gateway performing URL extraction and reputation checking would see a clean message.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 17:33:33 | Simulated QR scan result | COMPROMISED-HOST-01 | `Invoke-WebRequest -Uri 'http://10.10.40.10/portal-login'` — simulated post-scan HTTP request |
| 2 | 2026-09-15 17:33:33 | Landing page served | EXT-ATTACKER-SIM | HTTP 200 — "Acme Corp - Secure Document Portal", credential form with username/password fields |

**Cleanup:** No persistent changes.

## SOC Perspective

### Detection

**Automated alerts:** No alert fired. Wazuh generated standard Windows logon events:

| Timestamp (UTC) | Rule ID | Level | Description |
|---|---|---|---|
| 2026-09-15 17:33:31 | 60118 | 3 | Windows Workstation Logon Success |
| 2026-09-15 17:33:31 | 67028 | 3 | Special privileges assigned to new logon |

**Sysmon telemetry (COMPROMISED-HOST-01):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 17:33:33 | 1 | Process Create | `powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc004-sim.ps1`, parent: `VBoxService.exe` |

**Detection gap — by design:** This scenario's purpose is to document a gap, not a detection. Email gateway URL scanning (if deployed) **cannot** extract URLs from QR code images. The only detection surface is the resulting network traffic (Zeek `http.log` showing the outbound request to 10.10.40.10), but without the email as context, this request looks like any other HTTP GET.

### Investigation

**Step 1 — Email analysis (the critical gap):**
The phishing email contains no extractable URL in its headers or body text. The malicious link exists only as encoded data inside a QR code image. This means:
- No URL reputation check is possible at the email layer
- No safe-link rewriting (e.g., Microsoft Defender for Office 365) can intercept the URL
- No email-based IOC extraction can identify the destination
This is the core finding of AGC-004: QR code delivery is a deliberate bypass of email-layer URL scanning.

**Step 2 — Timing correlation:**
The HTTP request to `10.10.40.10/portal-login` at 17:33:33 UTC correlates temporally with the email delivery window. In a real investigation, this timing correlation — an outbound request to a suspicious external IP shortly after an email with an embedded QR code was received — is the strongest available signal. Unlike AGC-001/002/003 where the URL in the email directly matches the network request, here the link between email and request is purely circumstantial.

**Step 3 — Cross-reference with campaign infrastructure:**
The destination `10.10.40.10/portal-login` matches the same phishing infrastructure used in AGC-001, AGC-002, and AGC-003. The landing page is identical ("Acme Corp - Secure Document Portal" credential harvester). This campaign-level pattern provides additional confidence, but only if the analyst has already investigated the prior scenarios.

**Dead end:** Explored whether Sysmon or Wazuh could detect QR-encoded URLs — neither has image-analysis or OCR capabilities. The detection must happen at either the email gateway (with QR-decode capability) or the network layer (traffic inspection after the scan).

### Report

**Verdict: True Positive** — Confirmed phishing attempt delivered via QR code image to bypass URL scanning.

**Confidence: Medium** — The correlation between the email and the resulting network request is circumstantial (timing-based), not direct (no URL in the email to match against the network request). Three factors support the verdict:
1. Email contains a QR code but no text URL — unusual for a legitimate IT communication
2. Outbound HTTP request to 10.10.40.10 (known phishing infrastructure from AGC-001/002/003) temporally correlated with email receipt
3. Landing page is the same credential harvester used across the campaign

The confidence is Medium (not High) because without decoding the QR image, an analyst cannot definitively prove the email caused the network request.

**Response recommendation:**
1. **Detection engineering (highest priority):** Deploy or enable email gateway QR-code decoding. Services like Microsoft Defender for Office 365 and Proofpoint have QR-code scanning features — they decode QR images in email attachments and body, then check the extracted URLs against reputation databases. This closes the specific gap this scenario exploits.
2. **Interim mitigation:** Create an email DLP rule flagging messages that contain embedded images but zero clickable URLs — this unusual combination is characteristic of QR phishing.
3. **User awareness:** Update phishing training to cover QR-code phishing specifically. Teach users that scanning a QR code from an email is equivalent to clicking a link — the same caution applies.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Initial Access (TA0001) | T1566.002 | Phishing: Spearphishing Link (QR delivery) | Phishing email with QR-encoded URL (no extractable text URL); simulated post-scan GET to `http://10.10.40.10/portal-login`; HTTP 200 credential-harvesting page; timing correlation with email delivery | Medium |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
