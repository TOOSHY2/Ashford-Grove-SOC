# AGC-060 — Sensitive-Share Access Burst

> **Disclosure:** Executed & documented by Claude Code under direction and review by Ali.

## Card

| Field | Value |
|---|---|
| ID | `AGC-060` |
| Category | `09-collection` — Collection |
| MITRE Technique | `T1039` Data from Network Shared Drive |
| Verdict | True Positive |
| Confidence | Medium |
| Time to Detect | Sysmon EID 1 (process creation with share path in arguments) + file-server access auditing |
| Time to Triage | 05:00 (establish baseline comparison, correlate with prior discovery activity) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) targeting `AD-DC-01` (10.10.10.10) |
| Chain | ◀ [AGC-059](../AGC-059-browser-data-staging/README.md) · next [AGC-061](../AGC-061-ad-export-collection/README.md) ▶ |
| One-line Summary | Bulk copy attempt from `\\10.10.10.10\Finance` share using `net use` with cleartext credentials followed by `Copy-Item` recursive wildcard. SMB connection failed (system error 67 — share not provisioned on DC), but the attempt itself was captured by Sysmon EID 1, exposing `michael.chen`'s domain credentials in plaintext in the command line. Confidence is Medium because without file-server-side access auditing, volume-vs-baseline comparison is unavailable. |

## Attacker Perspective

### Tradecraft

**What:** Once on a host, the attacker enumerates network shares and bulk-copies the one worth having. At a financial services firm like Ashford Grove Capital that is the Finance share, because it holds:
- Revenue reports, trading positions, and investment strategy documents
- Client PII (SSN, account numbers, addresses)
- Payroll and HR compensation data
- M&A documents under NDA
- Wire transfer logs with routing numbers

**Why an Attacker Uses It Here:**
1. `michael.chen` (compromised account) has domain credentials that may grant read access to Finance shares
2. After discovery (AGC-041 share enumeration), the attacker knows which shares exist and targets the highest-value one
3. Bulk recursive copy (`Copy-Item -Recurse`) grabs everything in one operation — faster than picking files, and nothing valuable gets left behind
4. `C:\Windows\Temp\` staging keeps the copy out of user-visible directories

**Baseline dependency:** The signal here is access volume measured against the account's normal daily pattern. Without a baseline, a burst of share reads looks the same as a busy workday.

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

**Result:** The SMB connection failed with system error 67 ("The network name cannot be found") — the Finance share is not provisioned on AD-DC-01 in the lab. Copy-Item completed with 0 files copied. The attempt still left the artifacts that matter.

**Lab constraint:** The DC has no Finance share configured. With a live share the copy would succeed and produce Sysmon EID 11 events on the source host plus file access audit events (EID 4663/5145) on the file server. The analysis below works from what was captured.

## SOC Perspective

### Detection

**Sysmon EID 1 — Process Create (net.exe with cleartext credentials):**
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

**Critical finding:** The command line carries the domain credentials in cleartext — `ashfordgrove\michael.chen` with password `[REDACTED]`. The credential access scenarios showed the same thing: `net use` with `/user:` and an explicit password writes both into Sysmon EID 1's CommandLine field.

**Sysmon EID 1 — Process Create (PowerShell execution):**
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

**Sysmon EID 3 — Network Connection: 0 events**
The SwiftOnSecurity config filters SMB (port 445) connections from net.exe, the same gap earlier scenarios hit.

**Sysmon EID 11 — File Create: 0 events (for staged files)**
Nothing landed in the staging directory because the share was unreachable. Even with a live share, EID 11 would still miss non-EXE/DLL files (same gap as AGC-057/058/059).

### Investigation

**Step 1 — Baseline assessment:**
There is no baseline for `michael.chen`'s normal access volume to the Finance share. Without one, a burst of file access cannot be separated from a heavy but legitimate day. Volume-based detection needs a calibrated normal, and the lab has none.

**Step 2 — Share path analysis:**
`\\10.10.10.10\Finance` is where the firm's financial data lives. Even without knowing which files were in scope, the combination of:
- Domain credential authentication to a Finance share
- Recursive wildcard copy (`*`) to a staging directory
- Use of `C:\Windows\Temp\` as the destination
is consistent with collection tradecraft, not legitimate business use.

**Step 3 — Cross-reference with AGC-041 (share enumeration):**
AGC-041 documented the share enumeration. Enumeration (AGC-041) followed by targeted share access (AGC-060) is the expected chain:
1. Discovery: enumerate available shares to identify targets
2. Collection: bulk-copy from the highest-value share identified

That correlation raises confidence: a user who needs the Finance share opens the path they already know; they do not enumerate first.

**Step 4 — Credential exposure assessment:**
The `net use` command wrote `michael.chen`'s domain credentials in cleartext into the Sysmon log. Even though the connection failed, the credentials now sit where anyone with read access to Sysmon events can see them. That is a second problem, separate from the collection attempt.

### Report

**Verdict: True Positive** — Network shared drive access attempt consistent with collection tradecraft.

**Confidence: Medium** — Reduced from High because:
1. The Finance share does not exist in this lab, so no actual files were collected
2. No file-server-side access auditing is available to confirm the volume of access
3. No established baseline for `michael.chen`'s normal share access patterns to compare against
4. Nobody has calibrated a volume baseline, so anomaly scoring cannot run

**Would be High confidence if:** (a) file-server access audit logs showed access volume exceeding the account's daily baseline, AND (b) the access correlated with prior share enumeration (AGC-041). Both conditions would rule out legitimate heavy usage.

**Response recommendation:**
1. **Immediately reset `michael.chen`'s domain credentials** — they were exposed in cleartext in the Sysmon command line (net.exe CommandLine field).
2. **Enable file-server access auditing** (Windows Security EID 5145 — Detailed File Share) on all sensitive shares, especially Finance and HR.
3. **Establish access baselines** — without them, volume-based detection for T1039 has nothing to compare against. Track per-account daily access volume by share path.
4. **Alert on recursive wildcard copies** from file shares to local staging directories (`C:\Windows\Temp\`, `C:\Users\*\AppData\Local\Temp\`).
5. **Correlate with discovery activity** — any share enumeration (net share, net view) followed by targeted share access within a short window should trigger an alert regardless of volume.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Collection (TA0009) | T1039 | Data from Network Shared Drive | net.exe `use \\10.10.10.10\Finance` with domain credentials + Copy-Item recursive wildcard to C:\Windows\Temp\agc060_collected\. Share unreachable (error 67) but attempt captured via EID 1. Cleartext credentials exposed in CommandLine. | Medium |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

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
