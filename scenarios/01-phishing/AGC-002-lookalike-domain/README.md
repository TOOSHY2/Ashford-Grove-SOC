# AGC-002 — Lookalike-Domain Phishing

> **Disclosure:** Executed & documented by Claude Code under direction and review by Ali.

## Card

| Field | Value |
|---|---|
| ID | `AGC-002` |
| Category | `01-phishing` — Phishing & Initial Access |
| MITRE Technique | `T1566.002` Phishing: Spearphishing Link |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | N/A — no automated phishing alert fired |
| Time to Triage | 05:00 (from email header inspection to verdict) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103), `EXT-ATTACKER-SIM` (10.10.40.10) |
| Chain | ◀ [AGC-001](../AGC-001-spoofed-display-name/README.md) · next [AGC-003](../AGC-003-credential-harvest-link/README.md) ▶ |
| One-line Summary | Lookalike domain `ashfordgr0ve.local` (zero for 'o') delivers credential-harvesting link to an employee. |

## Attacker Perspective

### Tradecraft

**What:** Lookalike-domain (homoglyph) phishing. The attacker swaps the letter 'o' in `ashfordgrove.local` for the digit '0' and sends from `ashfordgr0ve.local`. At mail-client font sizes, '0' and 'o' are nearly indistinguishable. Unlike AGC-001's display-name spoof, this survives a check of the sender address — the reader sees a domain that looks right.

**Why at this lifecycle stage:** Initial access (TA0001), as in AGC-001. The attacker is refining the approach: AGC-001 relied on the mail client hiding the sender address behind a display name; AGC-002 makes the sender domain itself deceptive. That defeats the first line of user training ("check the sender address") because the address *looks* correct.

**Where in this lab's tooling:**
- **Email gateway:** None. No MTA, no SPF/DKIM/DMARC. `ashfordgr0ve.local` has no DNS record in the lab, so resolution fails, but the email is pre-staged as a `.eml` file and never passes through delivery. A real attacker would register the lookalike with working MX and SPF records.
- **Endpoint (Sysmon):** Sysmon EID 22 (DNS Query) captures the failed lookup of `ashfordgr0ve.local` with QueryStatus 9003 (NXDOMAIN). EID 3 (Network Connection) captures the outbound HTTP request to the phishing server. EID 1 (Process Create) captures the PowerShell process.
- **Wazuh:** No phishing-specific rule. Wazuh rules 60118, 67028, and 67023 fire for the guestcontrol session that runs the simulation.
- **Network (Security Onion):** Zeek `conn.log` and `http.log` should hold the connection from 10.10.10.103 to 10.10.40.10:80.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Wazuh agent 004 Active, Sysmon running.
- `EXT-ATTACKER-SIM` running with lab-sink web server serving `/portal-login` on port 80.
- Pre-staged `.eml` file at `C:\PhishingDelivery\AGC-002-lookalike-domain.eml` on COMPROMISED-HOST-01.

**Phishing email content** (`C:\PhishingDelivery\AGC-002-lookalike-domain.eml`):
```
From: "HR Department" <hr@ashfordgr0ve.local>
To: michael.chen@ashfordgrove.local
Subject: Updated Employee Benefits Portal - Action Required
Date: Mon, 15 Sep 2026 13:00:00 +0000
MIME-Version: 1.0
Content-Type: text/plain; charset="utf-8"

Dear Michael,

Your benefits enrollment window closes this Friday. Please review and
confirm your selections at the link below:

http://10.10.40.10/portal-login

If you have questions, contact HR at hr@ashfordgr0ve.local.

Best regards,
Ashford Grove HR Team
```

**Key evidence — the homoglyph:**
- Sender domain: `ashfordgr0ve.local` (digit zero '0' replacing letter 'o')
- Legitimate domain: `ashfordgrove.local` (letter 'o')
- The substitution is the 10th character — easy to miss by eye

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 16:56:02 | Stage .eml | COMPROMISED-HOST-01 | Copied `AGC-002-lookalike-domain.eml` to `C:\PhishingDelivery\` |
| 2 | 2026-09-15 17:00:31 | DNS query attempt | COMPROMISED-HOST-01 | `Resolve-DnsName ashfordgr0ve.local` — NXDOMAIN (no lab DNS record) |
| 3 | 2026-09-15 17:00:32 | Phishing link click | COMPROMISED-HOST-01 | `Invoke-WebRequest -Uri 'http://10.10.40.10/portal-login'` as Administrator |
| 4 | 2026-09-15 17:00:32 | Response received | COMPROMISED-HOST-01 | HTTP 200 — "Acme Corp - Secure Document Portal" credential harvesting form |

**Cleanup:** No persistent changes. PowerShell requests were stateless.

## SOC Perspective

### Detection

**Automated alerts:** No phishing-specific alert fired. Wazuh logged only the standard Windows logon events from the guestcontrol session:

| Timestamp (UTC) | Rule ID | Level | Description |
|---|---|---|---|
| 2026-09-15 17:00:30 | 60118 | 3 | Windows Workstation Logon Success |
| 2026-09-15 17:00:30 | 67028 | 3 | Special privileges assigned to new logon |
| 2026-09-15 17:00:40 | 67023 | 3 | Non service account logged off |

**Sysmon telemetry (COMPROMISED-HOST-01):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 17:00:31 | 1 | Process Create | `powershell.exe` executed via VBoxService.exe |
| 2026-09-15 17:00:32 | 22 | DNS Query | `QueryName: ashfordgr0ve.local`, `QueryStatus: 9003` (NXDOMAIN) |
| 2026-09-15 17:00:32 | 3 | Network Connection | PowerShell → 10.10.40.10:80 (HTTP) |
| 2026-09-15 17:00:32 | 11 | File Create | Temp files from PowerShell execution |

**Detection gap:** As in AGC-001, nothing flags homoglyph or lookalike domains automatically. Sysmon EID 22 captured the NXDOMAIN lookup for `ashfordgr0ve.local`, but no rule ties that to a near-miss of the organization's domain. The NXDOMAIN itself is a usable signal: a host that tries to resolve a domain one character off `ashfordgrove.local`, and fails, has most likely received a phish pointing at an unregistered lookalike.

### Investigation

**Step 1 — Email header analysis:**
Inspected the `.eml` file raw headers. The `From` header shows:
- Display name: `HR Department` (generic, trusted)
- Actual address: `hr@ashfordgr0ve.local`

The sender domain `ashfordgr0ve.local` is a homoglyph of the legitimate `ashfordgrove.local`: '0' (zero, U+0030) replaces 'o' (lowercase O, U+006F) at position 10. The attacker is counting on visual similarity to pass both the reader's eye and any allowlist that only checks for an exact domain match.

**Step 2 — DNS investigation:**
Sysmon EID 22 captured the query for `ashfordgr0ve.local` with QueryStatus 9003 (NXDOMAIN); the domain has no record in the lab. A real attacker would register it so the whole chain resolves. The NXDOMAIN is a lab artifact, which is why the link uses the raw IP `10.10.40.10`.

**Step 3 — Link and network analysis:**
The body links to `http://10.10.40.10/portal-login`. Sysmon EID 3 captured the connection from COMPROMISED-HOST-01 to 10.10.40.10:80. The server returned HTTP 200 with the same "Acme Corp - Secure Document Portal" credential page as AGC-001 — one set of infrastructure, several lures, one target.

**Step 4 — Comparison with AGC-001:**
AGC-001 used display-name spoofing (`IT Support` display name, `ashford-grove-support.local` sender). AGC-002 uses a homoglyph domain (`ashfordgr0ve.local`). Both target `michael.chen`, both link to `10.10.40.10/portal-login`, both serve the same credential page. One attacker is running a multi-lure campaign and testing which lure gets past the user.

**Dead end:** Checked Wazuh for DNS-based detection rules — none correlate NXDOMAIN responses with potential homoglyph patterns or near-misses of the organization's domain.

### Report

**Verdict: True Positive** — Confirmed phishing attempt via homoglyph/lookalike domain targeting employee `michael.chen`.

**Confidence: High** — Four independent indicators confirm malicious intent:
1. Sender domain `ashfordgr0ve.local` is a homoglyph of legitimate `ashfordgrove.local` (zero-for-O substitution)
2. DNS query for the lookalike domain returned NXDOMAIN — domain is not registered/legitimate
3. Link destination (10.10.40.10) is on the external EXT-SIM-NET, outside trusted network zones
4. Landing page is the same credential harvesting form seen in AGC-001 — consistent campaign infrastructure

**Response recommendation:**
1. **Immediate:** Add `ashfordgr0ve.local` to DNS blocklist. Block `10.10.40.10` at OPNsense-FW (if not already blocked from AGC-001).
2. **Detection engineering:** Create a Sysmon or Wazuh rule that flags DNS queries (EID 22) where the queried domain is within edit distance 1-2 of `ashfordgrove.local` and returns NXDOMAIN. This catches homoglyph attacks at the DNS resolution stage.
3. **Pattern alert:** Implement a Wazuh decoder that computes Levenshtein distance between queried domains and the organization's domain — flag any query where distance is 1-3 and QueryStatus is not 0.
4. **User awareness:** Update phishing training to cover homoglyph domains, using this email as the worked example. Make the point that checking the sender address is not enough once the attacker owns a near-identical domain.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Initial Access (TA0001) | T1566.002 | Phishing: Spearphishing Link | .eml with homoglyph domain `ashfordgr0ve.local`; link to `http://10.10.40.10/portal-login`; HTTP 200 credential harvesting page; Sysmon EID 22 DNS query + EID 3 network connection | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
