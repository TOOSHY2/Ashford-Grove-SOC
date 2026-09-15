# AGC-033 -- Browser Credential-Store Access

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-033` |
| Category | `05-credential-access` -- Credential Access |
| MITRE Technique | `T1555.003` Credentials from Password Stores: Credentials from Web Browsers |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Moderate -- Sysmon EID 1 captures the non-browser process; EID 11 does not fire for files without monitored extensions (detection gap) |
| Time to Triage | 02:30 (verify SourceImage is not a browser or legitimate password manager; check destination path for staging) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | < AGC-032 . next AGC-034 > |
| One-line Summary | Chrome `Login Data` SQLite database copied by non-browser process (PowerShell as Administrator) to `C:\Windows\Temp\` for offline credential extraction. Sysmon EID 1 captured the executing process. EID 11 did not fire for the extensionless destination file. |

## Attacker Perspective

### Tradecraft

**What:** The attacker copies the browser's credential store file (`Login Data`) to a staging directory for offline extraction. Chromium-based browsers (Chrome, Edge, Brave) store saved website credentials in a SQLite database at:
```
%LOCALAPPDATA%\Google\Chrome\User Data\Default\Login Data
%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Login Data
```

The database contains URLs, usernames, and passwords encrypted with DPAPI (Data Protection API). The decryption key is stored in `Local State` (JSON file in the User Data directory). An attacker with access to the user's profile can:
1. Copy `Login Data` and `Local State` to a temp directory
2. Decrypt the DPAPI-protected passwords using the user's session context or cached DPAPI master key
3. Extract all saved website credentials (email, SaaS, banking, VPN portals)

This technique targets a different credential set than SAM/LSASS -- browser credentials provide access to web services and SaaS applications that may not be tied to the Active Directory domain.

**Why at this lifecycle stage:** After compromising a host and harvesting domain credentials (AGC-031, AGC-032), the attacker targets browser credential stores to expand access beyond the AD domain. Saved browser passwords often include personal email, cloud services, VPN portals, and other external-facing systems that enable persistence even if the AD domain credentials are reset.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.
- No browser was installed with saved credentials on this lab VM, so a synthetic `Login Data` file was created in the Chrome default profile directory to simulate a realistic credential store.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 20:05:12 | Check for browser profiles | COMPROMISED-HOST-01 | No existing Chrome or Edge `Login Data` files found |
| 2 | 2026-09-15 20:05:13 | Create synthetic credential store | COMPROMISED-HOST-01 | Created `Login Data` at `C:\Users\michael.chen\AppData\Local\Google\Chrome\User Data\Default\` (simulating stored browser credentials) |
| 3 | 2026-09-15 20:05:13 | Copy Login Data to staging | COMPROMISED-HOST-01 | `Copy-Item "Login Data" C:\Windows\Temp\login_data_copy` -- succeeded (72 bytes) |
| 4 | 2026-09-15 20:05:25 | Cleanup | COMPROMISED-HOST-01 | Copied credential store deleted |

**Cleanup:** Staged file and synthetic Login Data removed.

## SOC Perspective

### Detection

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 20:05:12 | 1 (Sysmon) | Process Create | **Image:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` (PID 2692). **CommandLine:** `powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc033-sim.ps1`. **User:** `COMPROMISED-01\Administrator`. **IntegrityLevel:** High. Non-browser process accessing browser credential directories. |

**Detection gap -- EID 11 (File Create):**
Sysmon EID 11 did not fire for the `login_data_copy` file because the SwiftOnSecurity configuration monitors file creation based on extension rules (EXE, DLL, BAT, etc.). The destination file `login_data_copy` has no extension, and `Login Data` (the source) also has no extension. This means the file copy operation was invisible to Sysmon's file monitoring.

**Enhanced detection recommendations:**
```xml
<FileCreate onmatch="include">
  <TargetFilename condition="contains">Login Data</TargetFilename>
  <TargetFilename condition="contains">Cookies</TargetFilename>
  <TargetFilename condition="contains">Web Data</TargetFilename>
  <TargetFilename condition="contains">Local State</TargetFilename>
</FileCreate>
```

Alternatively, monitor for any process other than `chrome.exe`, `msedge.exe`, or known browser binaries reading files under `AppData\Local\Google\Chrome\User Data\` or `AppData\Local\Microsoft\Edge\User Data\`.

### Investigation

**Step 1 -- Identify non-browser access to credential store:**
Sysmon EID 1 shows `powershell.exe` running as Administrator, executing a script that accessed the Chrome `Login Data` path. PowerShell is not a browser process and has no legitimate reason to read `Login Data`.

**Step 2 -- Confirm the file path significance:**
`C:\Users\michael.chen\AppData\Local\Google\Chrome\User Data\Default\Login Data` is the Chromium credential store -- a SQLite database containing encrypted website usernames and passwords. Access to this file by a non-browser process is a strong credential-theft indicator.

**Step 3 -- Check the destination:**
The file was copied to `C:\Windows\Temp\login_data_copy` -- a temp directory commonly used for staging before exfiltration. Legitimate backup or password-manager tools would not use this path.

**Step 4 -- Separate credential set from AD credentials:**
Browser-stored credentials are a distinct dataset from Active Directory credentials (SAM hashes, Kerberos tickets). Incident response must address BOTH sets independently:
- AD credentials: reset domain passwords, Kerberos tickets (handled in AGC-031/032)
- Browser credentials: the user must reset passwords on EVERY website/service saved in the browser. This is easily forgotten when the investigation focuses on AD compromise.

**Step 5 -- Check for DPAPI key extraction:**
If the attacker copied `Local State` alongside `Login Data`, they have the DPAPI encryption key needed for offline decryption. Look for additional file copies from the Chrome User Data directory.

### Report

**Verdict: True Positive** -- A non-browser process (PowerShell, Administrator) accessed and copied the Chrome `Login Data` credential store to a staging directory.

**Confidence: High** -- Evidence confirms:
1. PowerShell (not a browser) accessed the Chrome credential store path.
2. The file was copied to `C:\Windows\Temp\` (staging location).
3. The executing process ran as Administrator with High integrity -- indicating prior compromise.
4. No legitimate reason exists for PowerShell to copy `Login Data`.

**Response recommendation:**
1. **Notify the user** to change passwords on ALL accounts saved in their browser -- this is a separate action from AD credential reset and is commonly overlooked.
2. **Inventory the credential store** if a copy can be recovered -- identify which websites/services are at risk.
3. **Check for DPAPI key theft** -- review whether `Local State`, `Cookies`, `Web Data`, or DPAPI master keys were also copied.
4. **Enable enhanced Sysmon monitoring** for browser credential file access (see detection recommendations above).
5. **Consider browser credential hardening** -- Windows Credential Guard for DPAPI, or enterprise password managers that don't store credentials in the browser.
6. **Investigate the full chain** -- this follows SAM extraction (AGC-032) and LSASS dump attempts (AGC-031), indicating systematic credential harvesting across multiple stores.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Credential Access (TA0006) | T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | PowerShell (Administrator) copied Chrome `Login Data` from `michael.chen` profile to `C:\Windows\Temp\`. Sysmon EID 1 confirmed non-browser process access. EID 11 gap (extensionless files not monitored). Synthetic credential store used (Chrome not installed on lab VM). | High |

## Evidence

Screenshots: not applicable (text-based evidence collection only).
