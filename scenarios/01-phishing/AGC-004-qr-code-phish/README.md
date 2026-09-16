# AGC-004 — QR-Code Phishing Indicator

> **Disclosure:** Executed & documented by Claude Code under direction and review by Ali.

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

**What:** QR-code phishing ("quishing"). The attacker embeds the URL in a QR code image in the email body instead of a clickable link. Gateway URL scanners parse headers, body text, and `href` attributes; a QR code is just a PNG or JPEG to them. The URL only exists once a phone camera decodes the image, so the first automated layer never sees it.

**Why at this lifecycle stage:** AGC-001 through AGC-003 showed that links reach the victim because there is no gateway. AGC-004 uses a technique that would get past a gateway if one existed. The "MFA device verification" lure fits any organization with authenticator apps, and a QR code looks natural there because users already scan them for MFA enrollment.

**Where in this lab's tooling:**
- **Email gateway:** None. Even with one, standard URL extraction would miss the QR-encoded URL: the body has no `<a>` tags and no plaintext URLs, only an image.
- **Endpoint (Sysmon):** Sysmon EID 1 (Process Create) captures the browser or PowerShell process. EID 3 (Network Connection) captures the outbound connection to 10.10.40.10. The HTTP request looks the same as any link click.
- **Wazuh:** No QR-specific or image-analysis rule exists.
- **Network (Security Onion):** Zeek captures the HTTP request, but nothing automated ties it back to the email that carried the QR code.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Wazuh agent Active, Sysmon running.
- `EXT-ATTACKER-SIM` running with lab-sink web server serving `/portal-login` on port 80.
- Phishing email conceptually delivered with QR code image encoding `http://10.10.40.10/portal-login`.

**Lab limitation:** Camera-based QR scanning cannot be simulated through VBoxManage guestcontrol. The simulation issues the HTTP request that a scan would produce and records it as a simulated post-scan action, not a camera scan.

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

**Critical observation:** The email body contains **zero extractable URLs**: no `href`, no plaintext link, no `src` pointing at a malicious domain. The URL exists only as data encoded in an image. A gateway doing URL extraction and reputation checks would pass the message as clean.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 17:33:33 | Simulated QR scan result | COMPROMISED-HOST-01 | `Invoke-WebRequest -Uri 'http://10.10.40.10/portal-login'` — simulated post-scan HTTP request |
| 2 | 2026-09-15 17:33:33 | Landing page served | EXT-ATTACKER-SIM | HTTP 200 — "Acme Corp - Secure Document Portal", credential form with username/password fields |

**Cleanup:** No persistent changes.

## SOC Perspective

### Detection

**Automated alerts:** No alert fired. Wazuh logged only the standard Windows logon events:

| Timestamp (UTC) | Rule ID | Level | Description |
|---|---|---|---|
| 2026-09-15 17:33:31 | 60118 | 3 | Windows Workstation Logon Success |
| 2026-09-15 17:33:31 | 67028 | 3 | Special privileges assigned to new logon |

**Sysmon telemetry (COMPROMISED-HOST-01):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 17:33:33 | 1 | Process Create | `powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc004-sim.ps1`, parent: `VBoxService.exe` |

**Detection gap — by design:** This scenario documents a gap, not a detection. Gateway URL scanning, if deployed, **cannot** extract URLs from QR images. The only surface left is the network traffic — Zeek `http.log` showing the outbound request to 10.10.40.10 — and without the email for context that request looks like any other HTTP GET.

### Investigation

**Step 1 — Email analysis (the critical gap):**
The email carries no extractable URL in headers or body; the link exists only inside the QR image. So:
- No URL reputation check is possible at the email layer
- No safe-link rewriting (e.g., Microsoft Defender for Office 365) can intercept the URL
- No email-based IOC extraction can identify the destination
That is the finding: QR delivery is a deliberate bypass of email-layer URL scanning.

**Step 2 — Timing correlation:**
The HTTP request to `10.10.40.10/portal-login` at 17:33:33 UTC falls inside the email delivery window. That timing — an outbound request to a suspicious external IP shortly after an email with an embedded QR code arrived — is the strongest signal available. In AGC-001/002/003 the URL in the email matched the network request directly; here the link between email and request is circumstantial.

**Step 3 — Cross-reference with campaign infrastructure:**
The destination `10.10.40.10/portal-login` is the same infrastructure used in AGC-001, AGC-002, and AGC-003, and the landing page is the same "Acme Corp - Secure Document Portal" credential harvester. That campaign pattern adds confidence, but only to an analyst who has already worked the earlier cases.

**Dead end:** Checked whether Sysmon or Wazuh could detect QR-encoded URLs — neither does image analysis or OCR. Detection has to happen at a gateway that decodes QR images or on the network after the scan.

### Report

**Verdict: True Positive** — Confirmed phishing attempt delivered via QR code image to bypass URL scanning.

**Confidence: Medium** — The link between the email and the network request rests on timing, not on a URL in the email that matches the request. Three factors support the verdict:
1. Email contains a QR code but no text URL — unusual for a legitimate IT communication
2. Outbound HTTP request to 10.10.40.10 (known phishing infrastructure from AGC-001/002/003) within the email receipt window
3. Landing page is the same credential harvester used across the campaign

Confidence stays at Medium rather than High because, without decoding the QR image, the analyst cannot prove the email caused the request.

**Response recommendation:**
1. **Detection engineering (highest priority):** Deploy or enable gateway QR-code decoding. Microsoft Defender for Office 365 and Proofpoint both decode QR images in the body and attachments and run the extracted URLs through reputation checks. That closes the gap this scenario exploits.
2. **Interim mitigation:** Create an email DLP rule that flags messages with an embedded image and zero clickable URLs — the combination that marks QR phishing.
3. **User awareness:** Update phishing training to cover QR codes. Scanning a QR code from an email is the same as clicking a link and deserves the same caution.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Initial Access (TA0001) | T1566.002 | Phishing: Spearphishing Link (QR delivery) | Phishing email with QR-encoded URL (no extractable text URL); simulated post-scan GET to `http://10.10.40.10/portal-login`; HTTP 200 credential-harvesting page; timing correlation with email delivery | Medium |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
