# AGC-005 — URL-Shortener Redirect Chain

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-005` |
| Category | `01-phishing` — Phishing & Initial Access |
| MITRE Technique | `T1566.002` Phishing: Spearphishing Link (redirect chain) |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | N/A — no automated alert; the shortener URL appears benign in isolation |
| Time to Triage | 05:00 (from initial link click to full chain reconstruction) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103), `EXT-ATTACKER-SIM` (10.10.40.10) |
| Chain | ◀ [AGC-004](../AGC-004-qr-code-phish/README.md) · next [AGC-006](../AGC-006-html-attachment-redirect/README.md) ▶ |
| One-line Summary | Phishing email contains a shortener-style URL (`/go/abc123`) that 302-redirects to the credential-harvesting page — the initial link appears innocent. |

## Attacker Perspective

### Tradecraft

**What:** URL shortener/redirect chain — the attacker places an intermediate hop between the phishing link and the malicious destination. The email contains a URL like `http://10.10.40.10/go/abc123` which looks like a shortened or tracking link (benign in appearance). The server responds with HTTP 302 Found, redirecting the browser to `/portal-login` — the actual credential harvester. The victim's browser follows the redirect automatically and transparently.

**Why at this lifecycle stage:** URL shorteners and redirect chains serve two purposes for the attacker: (1) the initial URL survives basic reputation checks because it is newly generated and has no history, and (2) the destination can be changed post-delivery by updating the redirect target — meaning the link can point to a benign page during email scanning and switch to the phishing page after delivery. In this lab, both hops are on the same server (10.10.40.10), but in a real attack, the shortener would typically be a legitimate service (bit.ly, t.co) or an attacker-controlled domain separate from the final destination.

**Where in this lab's tooling:**
- **Email gateway:** None. Even with one, a reputation check on `/go/abc123` would likely pass — the URL itself has no malicious content, and the 302 destination isn't visible until the redirect is followed.
- **Endpoint (Sysmon):** EID 1 (Process Create) logs the browser/PowerShell process. EID 3 (Network Connection) logs connections to 10.10.40.10. Both the initial request and the redirected request go to the same server — in a real attack, they might hit different IPs, creating two separate EID 3 events.
- **Network (Security Onion):** Zeek `http.log` captures both requests as separate entries: the first showing the 302 response with `Location` header, the second showing the 200 response from the final destination. This is the strongest detection surface.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Wazuh agent Active, Sysmon running.
- `EXT-ATTACKER-SIM` HTTP sink patched to return 302 for `/go/*` paths, redirecting to `/portal-login`.
- Lab-sink verified: `curl -D - http://127.0.0.1/go/abc123` returns `HTTP/1.0 302 Found` with `Location: /portal-login`.

**Phishing email concept:**
```
From: "Document Sharing" <docs@ashfordgrove.local>
To: michael.chen@ashfordgrove.local
Subject: Shared Document: Q3 Budget Review

Michael, the Q3 budget review has been shared with you:
http://10.10.40.10/go/abc123

This link expires in 72 hours.
```

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 17:37:36 | Click shortener URL (no follow) | COMPROMISED-HOST-01 | `GET http://10.10.40.10/go/abc123` with MaximumRedirection 0 — server returned 302 |
| 2 | 2026-09-15 17:37:37 | Direct GET to final destination | COMPROMISED-HOST-01 | `GET http://10.10.40.10/portal-login` — HTTP 200, credential form |
| 3 | 2026-09-15 17:37:37 | Full chain with redirect follow | COMPROMISED-HOST-01 | `GET /go/abc123` → 302 → `/portal-login` — HTTP 200, "Acme Corp - Secure Document Portal" |

**Cleanup:** No persistent changes. HTTP requests were stateless.

## SOC Perspective

### Detection

**Automated alerts:** No alert fired. Wazuh logged standard Windows logon events:

| Timestamp (UTC) | Rule ID | Level | Description |
|---|---|---|---|
| 2026-09-15 17:37:35 | 60118 | 3 | Windows Workstation Logon Success |
| 2026-09-15 17:37:35 | 67028 | 3 | Special privileges assigned to new logon |

**Sysmon telemetry (COMPROMISED-HOST-01):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 17:37:36 | 1 | Process Create | `powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc005-sim.ps1`, parent: `VBoxService.exe` |

**Detection gap:** No rule correlates HTTP 302 redirects with known-bad final destinations. The initial URL `/go/abc123` has no malicious reputation. The redirect chain is only visible in network logs (Zeek `http.log`), not at the endpoint or Wazuh level.

### Investigation

**Step 1 — Do not stop at the first hop:**
The initial request to `/go/abc123` returns HTTP 302 — this is a redirect, not the payload. An analyst who checks only this URL would see a benign-looking shortener endpoint and might dismiss the alert. The critical step is pulling the full session/connection history to find the follow-on request that the 302 triggered.

**Step 2 — Evaluate the final destination:**
The `Location: /portal-login` header in the 302 response points to the credential harvester on the same server (10.10.40.10). The final page is "Acme Corp - Secure Document Portal" with username/password form fields — the same phishing infrastructure used in AGC-001 through AGC-004. The final destination, not the shortener URL, is where the malicious intent lives.

**Step 3 — Explicitly identify each hop:**
- **Hop 1:** `http://10.10.40.10/go/abc123` — shortener/redirect endpoint. HTTP 302. No malicious content at this stage.
- **Hop 2:** `http://10.10.40.10/portal-login` — credential harvester. HTTP 200. This is the malicious endpoint.
An analyst seeing only hop 1 would reach the wrong conclusion. The redirect chain must be reconstructed.

**Step 4 — Cross-reference with prior scenarios:**
The final destination `10.10.40.10/portal-login` matches AGC-001/002/003/004 — same campaign infrastructure. The redirect chain is a new delivery technique (obfuscation of the final URL), not a new payload.

### Report

**Verdict: True Positive** — Confirmed phishing attack using a URL redirect chain to obscure the final malicious destination.

**Confidence: High** — After reconstructing the full redirect chain, the evidence is strong:
1. Initial URL `/go/abc123` returns HTTP 302 redirect
2. Redirect target `/portal-login` is a known credential-harvesting page
3. Final destination matches campaign infrastructure from AGC-001 through AGC-004
4. The redirect chain is a deliberate obfuscation technique — the email URL bears no visual resemblance to the phishing page

**Response recommendation:**
1. **Block the final destination** (`10.10.40.10/portal-login`), not just the shortener URL. Blocking only `/go/abc123` is ineffective — the attacker can generate new shortener paths instantly.
2. **Detection engineering:** Create a Zeek/Security Onion rule that flags HTTP 302 redirects where: (a) the initial URL matches a shortener pattern (`/go/`, `/r/`, `/l/`, `/click/`, or known shortener domains), AND (b) the `Location` header points to a different domain or an IP address rather than the same site.
3. **URL detonation:** Implement sandbox-based URL following at the email gateway — scan the final destination after following all redirects, not just the initial URL.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Initial Access (TA0001) | T1566.002 | Phishing: Spearphishing Link (redirect chain) | Email link to `http://10.10.40.10/go/abc123`; HTTP 302 redirect to `/portal-login`; final page is credential harvester; two-hop chain confirmed via separate GET requests | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
