# AGC-024 — Malicious Browser-Extension Persistence

> **Disclosure:** Executed & documented by Claude Code under direction and review by Ali.

## Card

| Field | Value |
|---|---|
| ID | `AGC-024` |
| Category | `03-persistence` — Persistence |
| MITRE Technique | `T1176` Browser Extensions |
| Verdict | True Positive |
| Confidence | Medium |
| Time to Detect | Manual only — no automated Wazuh/Sysmon detection path in this lab configuration |
| Time to Triage | N/A (requires manual browser inspection per endpoint) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ [AGC-023](../AGC-023-new-local-admin/README.md) · next [AGC-025](../../04-privilege-escalation/AGC-025-privileged-group-add/README.md) (Privilege Escalation category) ▶ |
| One-line Summary | Simulated malicious browser extension with broad permissions (all URLs, cookies, webRequest) deployed. **Primary finding: complete detection gap** — no automated monitoring for browser extension persistence in this environment. |

## Attacker Perspective

### Tradecraft

**What:** The attacker deploys a browser extension (Chrome, Edge, or Firefox) with broad permissions that allow it to:
- **Intercept all web traffic** (`webRequest` + `<all_urls>`) — read/modify HTTP requests and responses, steal session tokens, inject content.
- **Access cookies** (`cookies`) — steal authentication cookies for any domain.
- **Monitor tabs** (`tabs`) — track browsing activity, detect when the user visits banking/corporate portals.
- **Persist across sessions** — a browser extension survives browser restarts, reboots, and even password changes.

The extension carries a benign name ("Helper Extension") and asks for permissions that many legitimate extensions also need, so it is hard to tell from an authorized tool.

The attacker gets:

1. **Session-level persistence** — the extension runs inside the browser, with reach into every web session the user has open, SSO tokens and financial portals included.
2. **Credential harvesting** — the extension can read form data, inject fake login pages, or lift cookies without endpoint detection firing.
3. **Cross-site access** — `<all_urls>` lets the extension operate on every website, not a fixed set of domains.
4. **Detection gap** — standard endpoint tooling (Sysmon, Wazuh, most EDR) does not watch browser extension installs or permissions.

**Why at this lifecycle stage:** With system-level persistence in place (services, scheduled tasks, WMI), the attacker moves to the browser for application-level persistence. The browser gives direct access to web-based corporate resources (email, SaaS portals, financial systems) with no need to break encrypted traffic on the wire.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 19:17:48 | Create extension dir | COMPROMISED-HOST-01 | Created `C:\Windows\Temp\agc024-ext\` |
| 2 | 2026-09-15 19:17:48 | Write manifest.json | COMPROMISED-HOST-01 | Manifest V3 with permissions: `tabs`, `webRequest`, `cookies`, `storage`, host_permissions: `<all_urls>` |
| 3 | 2026-09-15 19:17:48 | Write background.js | COMPROMISED-HOST-01 | Benign marker script (console.log only) |
| 4 | 2026-09-15 19:17:48 | Verify | COMPROMISED-HOST-01 | Files confirmed on disk (manifest.json: 326 bytes, background.js: 156 bytes) |
| 5 | 2026-09-15 19:18:16 | Cleanup | COMPROMISED-HOST-01 | Extension directory removed |

**Lab limitation:** No Chrome or Edge browser profiles exist on COMPROMISED-HOST-01 (browsers not installed in this VM image). The simulation wrote the extension artifacts to a staging location to show the filesystem footprint and document the detection gap. In production the extension would sit inside an active browser profile.

**Cleanup:** Extension directory and all files removed after evidence collection.

## SOC Perspective

### Detection

**DETECTION GAP: No automated detection path exists in this lab configuration.**

| Detection Source | Coverage | Detail |
|---|---|---|
| Sysmon EID 11 (File Create) | Partial | SwiftOnSecurity config filtered the .json/.js file writes in Temp. Even if captured, file creation events in browser profile directories are not distinguished from normal browser activity. |
| Sysmon EID 1 (Process Create) | None | Browser extension loading does not create a separate process visible to Sysmon. Extensions run within the browser's existing process. |
| Wazuh Rules | None | No built-in rules for browser extension installation monitoring. |
| Security Event Log | None | Windows Security audit does not cover browser extension events. |
| Browser Logs | Not forwarded | Chrome/Edge have internal extension logs, but these are not forwarded to Wazuh or any SIEM in this configuration. |

**What WAS captured:**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 19:17:43 | 11 | File Create | Sysmon captured the simulation script being copied to the VM (`agc024-sim.ps1`), but the actual extension file writes (`manifest.json`, `background.js`) were filtered. |

### Investigation

**Step 1 — Confirm detection coverage:**
Neither Sysmon nor Wazuh fires on a browser extension install. The SwiftOnSecurity Sysmon config has no rule for writes to browser extension directories (`%LOCALAPPDATA%\Google\Chrome\User Data\*\Extensions\` or the equivalent Edge/Firefox paths).

**Step 2 — Manual browser inspection required:**
With no automated path, finding a malicious extension means inspecting each endpoint by hand:
- Navigate to `chrome://extensions` (Chrome) or `edge://extensions` (Edge) and review installed extensions.
- For each unknown extension, examine the manifest permissions — `<all_urls>`, `webRequest`, `cookies`, `webRequestBlocking` are high-risk permissions.
- Check if the extension is from the official store or loaded as "unpacked" (developer mode) — unpacked extensions bypass store review.

**Step 3 — Filesystem forensics (alternative):**
If the browser GUI is unavailable, inspect the extension directories on disk:
- Chrome: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions\`
- Edge: `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Extensions\`
- Firefox: `%APPDATA%\Mozilla\Firefox\Profiles\*\extensions\`

Each extension directory holds a `manifest.json` listing the permissions it requested. Parse those across the fleet as a compensating control.

**Step 4 — Cross-reference with social engineering:**
Malicious browser extensions usually arrive by:
- Fake "install required extension" prompts on compromised or phishing websites.
- Malicious OAuth consent flows (see AGC-009).
- Sideloading via Group Policy or registry-based force-install.

### Report

**Verdict: True Positive** — A simulated malicious browser extension with broad permissions was deployed on the endpoint.

**Confidence: Medium** — The Medium confidence rating reflects the detection methodology, not the analysis quality:
- The extension artifacts were created and verified on disk.
- Manifest permissions (`<all_urls>`, `webRequest`, `cookies`) are excessive for an unknown extension.
- Detection rested on manual inspection alone; with no automated alerting path, confidence in fleet-wide coverage is lower.

**Primary finding — Detection gap:**
Browser extension persistence is a detection gap in this SOC stack, and the gap is actionable:
1. **No Sysmon rule** monitors writes to browser extension directories.
2. **No Wazuh decoder/rule** parses browser extension events.
3. **No browser management tool** enforces an extension allowlist.

**Response recommendation:**
1. **Remove the extension** from the browser and delete its files from disk.
2. **Add Sysmon monitoring** for extension directory writes:
   ```xml
   <FileCreate onmatch="include">
     <TargetFilename condition="contains">\Extensions\</TargetFilename>
     <TargetFilename condition="contains">manifest.json</TargetFilename>
   </FileCreate>
   ```
3. **Deploy browser management** — use Chrome Enterprise policies or Edge Group Policy to enforce an extension allowlist and prevent unpacked extension loading.
4. **Fleet-wide audit** — script a one-time scan of all endpoints' browser extension directories, parsing `manifest.json` files for high-risk permissions.
5. **User awareness** — train users to recognize fake "install extension" prompts.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Persistence (TA0003) | T1176 | Browser Extensions | Extension artifacts created with manifest.json requesting broad permissions (`<all_urls>`, `webRequest`, `cookies`, `tabs`). **Detection gap documented:** no automated Wazuh/Sysmon monitoring for browser extension installations in this lab configuration. | Medium |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
