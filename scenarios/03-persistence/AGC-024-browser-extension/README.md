# AGC-024 -- Malicious Browser-Extension Persistence

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-024` |
| Category | `03-persistence` -- Persistence |
| MITRE Technique | `T1176` Browser Extensions |
| Verdict | True Positive |
| Confidence | Medium |
| Time to Detect | Manual only -- no automated Wazuh/Sysmon detection path in this lab configuration |
| Time to Triage | N/A (requires manual browser inspection per endpoint) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | < AGC-023 . next AGC-025 (Privilege Escalation category) > |
| One-line Summary | Simulated malicious browser extension with broad permissions (all URLs, cookies, webRequest) deployed. **Primary finding: complete detection gap** -- no automated monitoring for browser extension persistence in this environment. |

## Attacker Perspective

### Tradecraft

**What:** The attacker deploys a browser extension (Chrome, Edge, or Firefox) with broad permissions that allow it to:
- **Intercept all web traffic** (`webRequest` + `<all_urls>`) -- read/modify HTTP requests and responses, steal session tokens, inject content.
- **Access cookies** (`cookies`) -- steal authentication cookies for any domain.
- **Monitor tabs** (`tabs`) -- track browsing activity, detect when the user visits banking/corporate portals.
- **Persist across sessions** -- browser extensions survive browser restarts, system reboots, and even password changes.

The extension uses a benign-sounding name ("Helper Extension") and requests permissions that many legitimate extensions also require, making it difficult to distinguish from authorized tools.

This provides:

1. **Session-level persistence** -- the extension runs in the browser's context, with access to all web sessions the user has open, including SSO tokens and financial portals.
2. **Credential harvesting** -- the extension can read form data, inject fake login pages, or steal cookies without triggering endpoint detection.
3. **Cross-site access** -- `<all_urls>` permission means the extension can operate on every website, not just specific domains.
4. **Detection blind spot** -- standard endpoint security tools (Sysmon, Wazuh, most EDR) do not monitor browser extension installations or permissions.

**Why at this lifecycle stage:** After establishing system-level persistence (services, scheduled tasks, WMI), the attacker targets the browser for application-level persistence. This is especially valuable because it provides direct access to web-based corporate resources (email, SaaS portals, financial systems) without needing to intercept encrypted network traffic.

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

**Lab limitation:** No Chrome or Edge browser profiles exist on COMPROMISED-HOST-01 (browsers not installed in this VM image). The simulation created the extension artifacts at a staging location to demonstrate the technique's filesystem footprint and document the detection gap. In a production environment, the extension would be loaded into an active browser profile.

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

**Step 1 -- Confirm detection coverage:**
This is the most important step for this scenario. Neither Sysmon nor Wazuh provide automated detection for browser extension installations. The SwiftOnSecurity Sysmon config does not include rules to specifically flag writes to browser extension directories (`%LOCALAPPDATA%\Google\Chrome\User Data\*\Extensions\` or equivalent Edge/Firefox paths).

**Step 2 -- Manual browser inspection required:**
Without automated detection, identifying malicious browser extensions requires manual endpoint inspection:
- Navigate to `chrome://extensions` (Chrome) or `edge://extensions` (Edge) and review installed extensions.
- For each unknown extension, examine the manifest permissions -- `<all_urls>`, `webRequest`, `cookies`, `webRequestBlocking` are high-risk permissions.
- Check if the extension is from the official store or loaded as "unpacked" (developer mode) -- unpacked extensions bypass store review.

**Step 3 -- Filesystem forensics (alternative):**
If browser GUI is unavailable, inspect extension directories on disk:
- Chrome: `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Extensions\`
- Edge: `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Extensions\`
- Firefox: `%APPDATA%\Mozilla\Firefox\Profiles\*\extensions\`

Each extension directory contains a `manifest.json` that reveals the extension's requested permissions. Parse these programmatically across the fleet as a compensating control.

**Step 4 -- Cross-reference with social engineering:**
Malicious browser extensions are typically delivered via:
- Fake "install required extension" prompts on compromised or phishing websites.
- Malicious OAuth consent flows (see AGC-009).
- Sideloading via Group Policy or registry-based force-install.

### Report

**Verdict: True Positive** -- A simulated malicious browser extension with broad permissions was deployed on the endpoint.

**Confidence: Medium** -- The Medium confidence rating reflects the detection methodology, not the analysis quality:
- The extension artifacts were created and verified on disk.
- Manifest permissions (`<all_urls>`, `webRequest`, `cookies`) are clearly excessive for an unknown extension.
- However, detection relied entirely on manual inspection -- there is no automated alerting path, so confidence in fleet-wide detection coverage is inherently lower.

**Primary finding -- Detection gap:**
Browser extension persistence is a blind spot in this SOC infrastructure. This gap is actionable:
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
3. **Deploy browser management** -- use Chrome Enterprise policies or Edge Group Policy to enforce an extension allowlist and prevent unpacked extension loading.
4. **Fleet-wide audit** -- script a one-time scan of all endpoints' browser extension directories, parsing `manifest.json` files for high-risk permissions.
5. **User awareness** -- train users to recognize fake "install extension" prompts.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Persistence (TA0003) | T1176 | Browser Extensions | Extension artifacts created with manifest.json requesting broad permissions (`<all_urls>`, `webRequest`, `cookies`, `tabs`). **Detection gap documented:** no automated Wazuh/Sysmon monitoring for browser extension installations in this lab configuration. | Medium |

## Evidence

Screenshots: not applicable (text-based evidence collection only).
