# AGC-005 — URL-Shortener Redirect Chain

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

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

**What:** URL-shortener redirect chain. The attacker puts one hop between the phishing link and the destination. The email carries `http://10.10.40.10/go/abc123`, which reads like a shortened or tracking link. The server answers HTTP 302 Found with a redirect to `/portal-login`, the credential harvester, and the browser follows it without showing the user anything.

**Why at this lifecycle stage:** The redirect buys the attacker two things: (1) the first URL is freshly minted with no history, so it passes basic reputation checks, and (2) the destination can be swapped after delivery, so the link can point at a harmless page while the email is scanned and at the phishing page afterwards. In the lab both hops sit on 10.10.40.10; a real attacker would use a public shortener (bit.ly, t.co) or a separate domain for the first hop.

**Where in this lab's tooling:**
- **Email gateway:** None. Even with one, a reputation check on `/go/abc123` would likely pass: the URL carries nothing malicious, and the 302 target is invisible until something follows it.
- **Endpoint (Sysmon):** Sysmon EID 1 (Process Create) captures the browser or PowerShell process. EID 3 (Network Connection) captures connections to 10.10.40.10. Here both requests hit the same server; in a real attack they might hit two IPs and produce two EID 3 events.
- **Network (Security Onion):** Zeek `http.log` records the two requests as separate entries: the first with the 302 and its `Location` header, the second with the 200 from the final page. That is the strongest detection surface.

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

**Automated alerts:** No alert fired. Wazuh logged only the standard Windows logon events:

| Timestamp (UTC) | Rule ID | Level | Description |
|---|---|---|---|
| 2026-09-15 17:37:35 | 60118 | 3 | Windows Workstation Logon Success |
| 2026-09-15 17:37:35 | 67028 | 3 | Special privileges assigned to new logon |

**Sysmon telemetry (COMPROMISED-HOST-01):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 17:37:36 | 1 | Process Create | `powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc005-sim.ps1`, parent: `VBoxService.exe` |

**Detection gap:** No rule ties an HTTP 302 to a known-bad final destination. `/go/abc123` has no reputation at all. The chain is visible only in Zeek `http.log`, not on the endpoint or in Wazuh.

### Investigation

**Step 1 — Do not stop at the first hop:**
The request to `/go/abc123` returns HTTP 302 — a redirect, not the payload. Checking that URL alone shows a harmless-looking shortener endpoint, and it would be easy to close the ticket there. The step that matters is pulling the full connection history to find the request the 302 triggered.

**Step 2 — Evaluate the final destination:**
The `Location: /portal-login` header in the 302 response points to the credential harvester on the same server (10.10.40.10). The final page is "Acme Corp - Secure Document Portal" with username and password fields — the infrastructure from AGC-001 through AGC-004. The malicious intent lives at the final destination, not the shortener URL.

**Step 3 — Explicitly identify each hop:**
- **Hop 1:** `http://10.10.40.10/go/abc123` — shortener/redirect endpoint. HTTP 302. No malicious content at this stage.
- **Hop 2:** `http://10.10.40.10/portal-login` — credential harvester. HTTP 200. This is the malicious endpoint.
Hop 1 alone leads to the wrong verdict; the chain has to be rebuilt through to hop 2.

**Step 4 — Cross-reference with prior scenarios:**
The final destination `10.10.40.10/portal-login` matches AGC-001/002/003/004 — same campaign infrastructure. The redirect is a new way to hide the URL, not a new payload.

### Report

**Verdict: True Positive** — Confirmed phishing attack using a URL redirect chain to obscure the final malicious destination.

**Confidence: High** — With the chain rebuilt, four points support the verdict:
1. Initial URL `/go/abc123` returns HTTP 302 redirect
2. Redirect target `/portal-login` is a known credential-harvesting page
3. Final destination matches campaign infrastructure from AGC-001 through AGC-004
4. The redirect exists to hide the destination — the email URL looks nothing like the phishing page

**Response recommendation:**
1. **Block the final destination** (`10.10.40.10/portal-login`), not just the shortener URL. Blocking only `/go/abc123` achieves nothing — the attacker can mint a new path in seconds.
2. **Detection engineering:** Create a Zeek/Security Onion rule that flags HTTP 302 redirects where: (a) the initial URL matches a shortener pattern (`/go/`, `/r/`, `/l/`, `/click/`, or known shortener domains), AND (b) the `Location` header points to a different domain or an IP address rather than the same site.
3. **URL detonation:** Add sandboxed URL following at the gateway so the scan covers the final destination after every redirect, not the first URL.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Initial Access (TA0001) | T1566.002 | Phishing: Spearphishing Link (redirect chain) | Email link to `http://10.10.40.10/go/abc123`; HTTP 302 redirect to `/portal-login`; final page is credential harvester; two-hop chain confirmed via separate GET requests | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
