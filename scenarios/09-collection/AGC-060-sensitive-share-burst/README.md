# AGC-060 -- Sensitive-Share Access Burst

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-060` |
| Category | `09-collection` -- Collection |
| MITRE Technique | `T1039` Data from Network Shared Drive |
| Verdict | True Positive |
| Confidence | Medium |
| Time to Detect | Sysmon EID 1 (process creation with share path in arguments) + file-server access auditing |
| Time to Triage | 05:00 (establish baseline comparison, correlate with prior discovery activity) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) targeting `AD-DC-01` (10.10.10.10) |
| Chain | < AGC-059 . next AGC-061 > |
| One-line Summary | Bulk copy attempt from `\\10.10.10.10\Finance` share using `net use` with cleartext credentials followed by `Copy-Item` recursive wildcard. SMB connection failed (system error 67 -- share not provisioned on DC), but the attempt itself was captured by Sysmon EID 1, exposing `michael.chen`'s domain credentials in plaintext in the command line. Confidence is Medium because without file-server-side access auditing, volume-vs-baseline comparison is unavailable. |

## Attacker Perspective

### Tradecraft

**What:** After establishing presence on a compromised host, attackers enumerate and then bulk-copy data from network file shares. Finance shares are high-priority targets at financial services firms like Ashford Grove Capital because they contain:
- Revenue reports, trading positions, and investment strategy documents
- Client PII (SSN, account numbers, addresses)
- Payroll and HR compensation data
- M&A documents under NDA
- Wire transfer logs with routing numbers

**Why an Attacker Uses It Here:**
1. `michael.chen` (compromised account) has domain credentials that may grant read access to Finance shares
2. After discovery (AGC-041 share enumeration), the attacker knows which shares exist and targets the highest-value one
3. Bulk recursive copy (`Copy-Item -Recurse`) captures everything in one operation -- faster than selective exfiltration and ensures nothing valuable is missed
4. `C:\Windows\Temp\` staging avoids writing to user-visible directories

**Baseline dependency:** The detection signal for this technique depends entirely on comparing observed access volume against the account's normal daily access pattern. Without an established baseline, a burst of file access is indistinguishable from a legitimately busy workday.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context
- `AD-DC-01` running at 10.10.10.10
- Finance share (`\\10.10.10.10\Finance`) targeted

**Execution:**
```powershell
# Step 1: Mount the share with domain credentials
net use \\10.10.10.10\Finance /user:ashfordgrove\michael.chen [REDACTED]

# Step 2: Bulk recursive copy to local staging
Copy-Item -Path "\\10.10.10.10\Finance\*" -Destination "C:\Windows\Temp\agc060_collected\" -Recurse
```

**Result:** SMB connection failed with system error 67 ("The network name cannot be found") -- the Finance share is not provisioned on AD-DC-01 in this lab environment. The Copy-Item command completed with 0 files copied. However, the attack attempt itself generated the critical detection artifacts.

**Lab constraint:** The DC does not have a Finance share configured. In a production environment, this share would exist and the bulk copy would succeed, generating both Sysmon EID 11 events on the source host and file access audit events (EID 4663/5145) on the file server. The detection analysis below focuses on the artifacts that were captured.

## SOC Perspective

### Detection

**Sysmon EID 1 -- Process Create (net.exe with cleartext credentials):**
```
Process Create:
RuleName: -
UtcTime: 2026-09-15 22:37:17.620
ProcessGuid: {eb65e329-c89d-6aa9-9704-000000001400}
ProcessId: 3328
Image: C:\Windows\System32\net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" use \\10.10.10.10\Finance /user:ashfordgrove\michael.chen [REDACTED]
User: COMPROMISED-01\Administrator
IntegrityLevel: High
Hashes: MD5=8A1E71312BD2AAE202652113049CDBD1
```

**Critical finding:** Domain credentials exposed in cleartext in the command line -- `ashfordgrove\michael.chen` with password `[REDACTED]`. This is a recurring pattern (also seen in credential access scenarios): `net use` with `/user:` and explicit password arguments writes the full credentials into Sysmon EID 1's CommandLine field.

**Sysmon EID 1 -- Process Create (PowerShell execution):**
```
Process Create:
UtcTime: 2026-09-15 22:37:17.266
ProcessGuid: {eb65e329-c89d-6aa9-9604-000000001400}
ProcessId: 3808
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc060-sim.ps1
User: COMPROMISED-01\Administrator
IntegrityLevel: High
```

**Sysmon EID 3 -- Network Connection: 0 events**
SMB connections (port 445) by net.exe are filtered by SwiftOnSecurity Sysmon config. This is the same gap documented in prior scenarios.

**Sysmon EID 11 -- File Create: 0 events (for staged files)**
No files were created in the staging directory because the share was unreachable. In a production scenario with a live share, EID 11 would still miss non-EXE/DLL files (same gap as AGC-057/058/059).

### Investigation

**Step 1 -- Baseline assessment:**
No established baseline exists for `michael.chen`'s normal access volume to the Finance share. Without baseline data, a burst of file access events cannot be statistically distinguished from legitimate heavy usage. This is the fundamental limitation of volume-based detection: it requires a calibrated normal to compare against.

**Step 2 -- Share path analysis:**
The targeted share path `\\10.10.10.10\Finance` is a sensitive financial data repository. Even without knowing the specific files, the combination of:
- Domain credential authentication to a Finance share
- Recursive wildcard copy (`*`) to a staging directory
- Use of `C:\Windows\Temp\` as the destination
is consistent with collection tradecraft, not legitimate business use.

**Step 3 -- Cross-reference with AGC-041 (share enumeration):**
AGC-041 documented network share discovery activity. The progression from share enumeration (AGC-041) to targeted share access (AGC-060) follows the expected attack chain:
1. Discovery: enumerate available shares to identify targets
2. Collection: bulk-copy from the highest-value share identified

This correlation elevates confidence because legitimate users do not enumerate shares before accessing them -- they access known paths directly.

**Step 4 -- Credential exposure assessment:**
The `net use` command exposed `michael.chen`'s domain credentials in cleartext in the Sysmon log. Even though the connection failed, the credentials are now logged and potentially accessible to anyone who can read Sysmon events. This represents a secondary security concern independent of the collection attempt.

### Report

**Verdict: True Positive** -- Network shared drive access attempt consistent with collection tradecraft.

**Confidence: Medium** -- Reduced from High because:
1. The Finance share does not exist in this lab, so no actual files were collected
2. No file-server-side access auditing is available to confirm the volume of access
3. No established baseline for `michael.chen`'s normal share access patterns to compare against
4. Volume-based anomaly detection requires baseline calibration that has not been performed

**Would be High confidence if:** (a) file-server access audit logs showed access volume exceeding the account's daily baseline, AND (b) the access correlated with prior share enumeration (AGC-041). Both conditions would rule out legitimate heavy usage.

**Response recommendation:**
1. **Immediately reset `michael.chen`'s domain credentials** -- they were exposed in cleartext in the Sysmon command line (net.exe CommandLine field).
2. **Enable file-server access auditing** (Windows Security EID 5145 -- Detailed File Share) on all sensitive shares, especially Finance and HR.
3. **Establish access baselines** -- without baseline data, volume-based detection for T1039 is effectively blind. Track per-account daily access volume by share path.
4. **Alert on recursive wildcard copies** from file shares to local staging directories (`C:\Windows\Temp\`, `C:\Users\*\AppData\Local\Temp\`).
5. **Correlate with discovery activity** -- any share enumeration (net share, net view) followed by targeted share access within a short window should trigger an alert regardless of volume.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Collection (TA0009) | T1039 | Data from Network Shared Drive | net.exe `use \\10.10.10.10\Finance` with domain credentials + Copy-Item recursive wildcard to C:\Windows\Temp\agc060_collected\. Share unreachable (error 67) but attempt captured via EID 1. Cleartext credentials exposed in CommandLine. | Medium |

## Evidence

Screenshots: not applicable (text-based evidence collection only).

### net.exe share mount attempt with cleartext credentials

```
Process Create:
UtcTime: 2026-09-15 22:37:17.620
ProcessGuid: {eb65e329-c89d-6aa9-9704-000000001400}
ProcessId: 3328
Image: C:\Windows\System32\net.exe
CommandLine: "C:\WINDOWS\system32\net.exe" use \\10.10.10.10\Finance /user:ashfordgrove\michael.chen [REDACTED]
User: COMPROMISED-01\Administrator
IntegrityLevel: High
Hashes: MD5=8A1E71312BD2AAE202652113049CDBD1

Result: System error 67 -- The network name cannot be found.
```

### Detection gap summary for T1039

```
Detection Method          | Available in Lab?  | Captures Burst?
--------------------------|--------------------|-----------------
Sysmon EID 1 (net.exe)    | YES                | Partial (mount attempt, not file-level)
Sysmon EID 3 (SMB conn)   | NO (filtered)      | -
Sysmon EID 11 (file copy) | Partial (EXE/DLL)  | Misses most document types
File Server EID 5145      | NOT CONFIGURED      | Would capture per-file access
File Server EID 4663      | NOT CONFIGURED      | Would capture access attempts
Baseline comparison       | NO BASELINE         | Cannot compare without calibration

Key gap: Volume-based anomaly detection for T1039 requires
both file-server auditing AND established per-account baselines.
Neither exists in this environment.
```
