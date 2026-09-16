# AGC-059 — Browser Data Staging (Cookies / History / Web Data)

> **Disclosure:** Executed & documented by Claude Code under direction and review by Ali.

## Card

| Field | Value |
|---|---|
| ID | `AGC-059` |
| Category | `09-collection` — Collection |
| MITRE Technique | `T1074.001` Data Staged: Local Data Staging + `T1539` Steal Web Session Cookie |
| Verdict | True Positive |
| Confidence | Critical |
| Time to Detect | File access auditing on browser profile directories, or PowerShell Script Block Logging |
| Time to Triage | 05:00 (identify which browser files were staged, check if Cookies included, assess session hijack risk) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ [AGC-058](../AGC-058-screenshot-collection/README.md) · next [AGC-060](../AGC-060-sensitive-share-burst/README.md) ▶ |
| One-line Summary | 4 Chrome browser data files (Cookies, History, Web Data, Login Data) copied from `michael.chen`'s profile to staging directory `C:\Windows\Temp\agc059_staged\` in a single operation. The inclusion of Cookies specifically elevates this to Critical — a stolen session cookie enables immediate account hijack without password or MFA, and an AD password reset does NOT invalidate web session cookies. Sysmon EID 11 did NOT capture the file copies (no EXE/DLL extension). Detection relies on file access auditing or PowerShell logging. |

## Attacker Perspective

### Tradecraft

**What:** Browser data files contain the most immediately actionable credentials on a compromised host:
1. **Cookies** (SQLite DB) — holds the live session tokens for every web service the user is signed into. A stolen cookie walks past password and MFA because the session already passed both
2. **Login Data** (SQLite DB) — holds saved passwords encrypted with DPAPI. In the user's context, or with the DPAPI master key, they decrypt to plaintext
3. **History** (SQLite DB) — shows which services the user visits (internal portals, banking, SaaS), so the attacker knows which sessions to hijack
4. **Web Data** (SQLite DB) — holds autofill entries, which can include card numbers, addresses, and form data

**Why Cookies are Critical severity:**
- A password can be changed (remediation: AD password reset)
- An MFA token can be revoked (remediation: MFA re-enrollment)
- A session cookie grants access right now and keeps working until it expires or the service kills the session
- **AD password reset does NOT invalidate web session cookies** — the attacker keeps SaaS, email, banking, and the rest until each service's session is terminated on its own
- Office 365, Gmail, Slack, and banking portals commonly issue cookies that live for days

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.
- Chrome profile exists at `C:\Users\michael.chen\AppData\Local\Google\Chrome\User Data\Default`.
- Login Data (72 bytes) present from Chrome installation; Cookies, History, Web Data seeded to simulate populated browser state.

**Files staged (all at 22:30:37 UTC):**

| File | Size | Content Type | Sensitivity |
|---|---|---|---|
| Cookies | 2,102 B | Session tokens | **Critical** — immediate session hijack |
| History | 2,111 B | Visited URLs | High — reveals target services |
| Web Data | 2,097 B | Autofill / credit cards | High — PII / financial |
| Login Data | 72 B | Encrypted passwords | High — decryptable with DPAPI |

**Staging command:**
```powershell
Copy-Item "C:\Users\michael.chen\AppData\Local\Google\Chrome\User Data\Default\Cookies" "C:\Windows\Temp\agc059_staged\"
Copy-Item "...\History" "C:\Windows\Temp\agc059_staged\"
Copy-Item "...\Web Data" "C:\Windows\Temp\agc059_staged\"
Copy-Item "...\Login Data" "C:\Windows\Temp\agc059_staged\"
```

## SOC Perspective

### Detection

**Sysmon EID 11 — File Create: 0 events (DETECTION GAP)**

Same gap as AGC-057 and AGC-058: the SwiftOnSecurity config only logs EID 11 for EXE/DLL extensions. Chrome's Cookies, History, Web Data, and Login Data files have no extension at all, so the default EID 11 filter never sees them.

**Sysmon EID 1 — Process Create (primary detection):**
```
Process Create:
UtcTime: 2026-09-15 22:30:37.102
ProcessGuid: {eb65e329-c70d-6aa9-8b04-000000001400}
ProcessId: 2280
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc059-sim3.ps1
User: COMPROMISED-01\Administrator
```

**Detection gap analysis:**

| Detection Method | Captures Browser Staging? | What It Shows |
|---|---|---|
| Sysmon EID 11 | NO (no extension match) | Nothing |
| Sysmon EID 1 | Partial (process only) | PowerShell script execution |
| PS Script Block (EID 4104) | YES | Copy-Item with browser profile paths |
| Windows File Audit (4663) | YES | Read access to Chrome profile files |
| Custom SACL on Chrome profile | YES | Any access to browser data directory |

### Investigation

**Step 1 — File breadth assessment:**
4 distinct browser data files staged in one operation. Cookies + passwords + history + form data together is targeted collection, not incidental file access:
- A backup tool copies the whole profile directory; it does not cherry-pick four files
- The attacker took exactly the high-value set: Cookies (sessions), Login Data (passwords), History (targets), Web Data (autofill)

**Step 2 — Staging location analysis:**
`C:\Windows\Temp\agc059_staged\` — dedicated staging subdirectory in system temp:
- Not the browser profile directory itself (not a backup/restore operation)
- Not a user-accessible location (not user-initiated organization)
- Temp directory with a specific staging folder name = exfiltration preparation

**Step 3 — Cookie urgency assessment:**
`Cookies` in the staged set is what makes this Critical:
- Live session cookies drop straight into an attacker-controlled browser
- The attacker inherits the user's authenticated sessions with no password and no MFA prompt
- **Time-critical:** session cookies have an expiry window (often 7-30 days for SaaS services)
- **AD password reset is NOT sufficient remediation** — web session cookies are managed by each individual service, not Active Directory

**Step 4 — Cross-reference with AGC-033 (credential access):**
AGC-033 focused on individual credential access (narrower scope). AGC-059 escalates by:
- Staging multiple file types simultaneously (broader collection)
- Including Cookies specifically (immediate account takeover)
- Writing to a dedicated staging directory (exfiltration preparation)

### Report

**Verdict: True Positive** — Browser data staged for exfiltration including session cookies.

**Confidence: Critical** — rated at the top because:
1. **Cookies file staged** — live session tokens, so account hijack needs no authentication step at all.
2. 4 browser data files copied in a single operation — the whole credential store, not a single-file grab.
3. Dedicated staging directory in system temp — exfiltration preparation pattern.
4. **AD password reset does NOT remediate cookie theft** — each web service has to terminate its own sessions.
5. Time-critical: every hour the cookies stay valid is another hour of live sessions for the attacker.

**Response recommendation:**
1. **IMMEDIATELY invalidate all web sessions** for michael.chen across ALL services (Office 365, email, SaaS, banking, internal portals). This is the single most time-critical action, and it is not the password reset.
2. **Then reset the AD password** and re-enroll MFA — after session invalidation, not instead of it.
3. **Audit session logs** on each service the user accesses (from browser History) for unauthorized access from unfamiliar IPs during the exposure window.
4. **Enable file access auditing** (SACL) on browser profile directories for all endpoints — with Sysmon EID 11 blind to these files, the SACL is the only reliable detection.
5. **Alert on access to browser data paths** — `*\Chrome\User Data\Default\Cookies`, `*\Edge\User Data\Default\Cookies`, etc. from any process other than the browser itself.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Collection (TA0009) | T1074.001 | Data Staged: Local Data Staging | 4 Chrome browser files (Cookies, History, Web Data, Login Data) copied to C:\Windows\Temp\agc059_staged\. Dedicated staging directory. EID 11 missed (no extension match). | Critical |
| Credential Access (TA0006) | T1539 | Steal Web Session Cookie | Cookies file specifically targeted and staged. Session cookies enable immediate account hijack bypassing password + MFA. AD password reset does NOT invalidate. | Critical |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### Browser data staging summary

```
Source:     C:\Users\michael.chen\AppData\Local\Google\Chrome\User Data\Default\
Dest:       C:\Windows\Temp\agc059_staged\
Process:    powershell.exe (PID 2280)
User:       COMPROMISED-01\Administrator
Time:       22:30:37 UTC

Staged File    | Size     | Risk Level | Impact
---------------|----------|------------|----------------------------------
Cookies        | 2,102 B  | CRITICAL   | Session hijack (no auth needed)
History        | 2,111 B  | HIGH       | Reveals target services
Web Data       | 2,097 B  | HIGH       | Autofill / credit cards / PII
Login Data     | 72 B     | HIGH       | DPAPI-encrypted passwords

Key insight: AD password reset does NOT invalidate web session cookies.
Remediation: Invalidate all web sessions FIRST, then reset password.
```

### Detection gap: Extensionless files invisible to EID 11

```
Browser data files have NO file extension:
  Cookies     -> No extension (not .db, not .sqlite)
  History     -> No extension
  Web Data    -> No extension
  Login Data  -> No extension

Sysmon EID 11 with SwiftOnSecurity config:
  Matches RuleName: EXE, DLL (extension-based)
  Extensionless files: NOT matched

Recommendation: File access auditing (SACL) on browser profile directories.
```
