# AGC-057 — Bulk Archive Creation (Staging for Exfiltration)

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-057` |
| Category | `09-collection` — Collection |
| MITRE Technique | `T1560.001` Archive Collected Data: Archive via Utility |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Sysmon EID 1 (PowerShell with Compress-Archive cmdlet) — note: Sysmon EID 11 does NOT capture .zip creation under SwiftOnSecurity config |
| Time to Triage | 03:00 (verify archive location is temp/staging, check source file breadth, correlate with prior enumeration activity) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ [AGC-056](../../08-command-control/AGC-056-c2-process-tree/README.md) (C2 category) · next [AGC-058](../AGC-058-screenshot-collection/README.md) ▶ |
| One-line Summary | 8 sensitive Finance documents (salary data, board minutes, M&A NDA, banking credentials, tax returns, executive compensation) archived into `C:\Windows\Temp\staged.zip` (1,775 bytes) using PowerShell `Compress-Archive`. The archive location (`C:\Windows\Temp`) is a staging path, not a user workspace — legitimate archiving targets user document folders. Sysmon EID 11 did NOT capture the .zip creation because SwiftOnSecurity config filters EID 11 to EXE/DLL file types only — a critical detection gap for collection/exfiltration staging. Detection relies on EID 1 (PowerShell process with -ExecutionPolicy Bypass) and PowerShell Script Block Logging (EID 4104) for the Compress-Archive cmdlet. |

## Attacker Perspective

### Tradecraft

**What:** Before exfiltrating, the attacker packs the collected files into one compressed archive. That buys four things:
1. **Reduces transfer volume:** Compression shrinks the payload, so the transfer spends less time on the wire
2. **Single operation:** One file transfer draws less attention than dozens of individual downloads
3. **Staging location:** Writing to `C:\Windows\Temp` (or `%TEMP%`) keeps the archive out of user-visible directories like Documents or Desktop
4. **Built-in tools:** `Compress-Archive` is a native PowerShell cmdlet — nothing to drop on disk (living-off-the-land)

**Why the archive location matters:**
- `C:\Windows\Temp` — system temp, writable by elevated processes, never looked at by users, cleaned automatically
- vs. `C:\Users\michael.chen\Documents\archive.zip` — visible in the user's file browser, normal archiving behavior
- Where the archive lands is the first thing that separates collection from routine archiving

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.
- `C:\Shares\Finance\` directory created with 8 seed documents.

**Seed documents created:**

| File | Size | Sensitivity |
|---|---|---|
| Q3-2026-Revenue-Report.xlsx | 4,557 B | Financial - Revenue |
| Employee-Salary-Data-2026.csv | 3,259 B | PII - Compensation |
| Board-Meeting-Minutes-Sep2026.docx | 2,864 B | Governance - Confidential |
| Merger-Acquisition-Draft-NDA.pdf | 5,162 B | Legal - M&A |
| Banking-Credentials-Internal.txt | 862 B | Credentials - Critical |
| Tax-Returns-2025-Corporate.pdf | 6,260 B | Financial - Tax |
| Vendor-Payment-Schedule-Q4.xlsx | 2,161 B | Financial - Payments |
| Executive-Compensation-Review.docx | 3,464 B | PII - Executive |

**Archive command executed (22:21:07 UTC):**
```powershell
Compress-Archive -Path "C:\Shares\Finance\*" -DestinationPath "C:\Windows\Temp\staged.zip" -Force
```

**Result:**
- Archive created: `C:\Windows\Temp\staged.zip` (1,775 bytes)
- All 8 files from `C:\Shares\Finance\` went into the one archive
- Archive deleted after evidence capture

## SOC Perspective

### Detection

**Sysmon EID 11 — File Create: 0 events (DETECTION GAP)**

Sysmon EID 11 did not log the creation of `staged.zip`. The SwiftOnSecurity config only includes EID 11 events that match the `EXE` or `DLL` RuleName, so archive files (.zip, .7z, .rar) never reach the log.

**Detection gap impact:**
```
File Extension | EID 11 Captured | RuleName Match
---------------|-----------------|----------------
.exe           | Yes             | EXE
.dll           | Yes             | DLL
.sys           | Yes             | EXE
.zip           | NO              | (no match)
.7z            | NO              | (no match)
.rar           | NO              | (no match)
```

Under the default config, archive staging never produces an EID 11 event. The detection has to come from somewhere else.

**Sysmon EID 1 — Process Create (primary detection):**
```
Process Create:
UtcTime: 2026-09-15 22:21:06.999
ProcessGuid: {eb65e329-c4d2-6aa9-6f04-000000001400}
ProcessId: 4440
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc057-sim.ps1
User: COMPROMISED-01\Administrator
```

**Supplementary detection methods (not captured in this lab):**
1. **PowerShell Script Block Logging (EID 4104):** Would capture the full `Compress-Archive` cmdlet with source path and destination
2. **Windows File Audit (Security EID 4663):** Would capture file reads on the source Finance documents
3. **Custom Sysmon EID 11 rules:** Adding `.zip|.7z|.rar|.tar|.gz` to the EID 11 TargetFilename filter

### Investigation

**Step 1 — Archive location analysis:**
`C:\Windows\Temp\staged.zip` — staging indicators:
- `C:\Windows\Temp` is a system-level temp directory, not a user workspace
- The name "staged" gives the intent away; a real attacker would pick something blander
- A user archiving their own work writes to `Documents`, `Desktop`, or a project folder

**Step 2 — Source file breadth analysis:**
8 files from `C:\Shares\Finance\` spanning:
- Revenue reports, salary data, board minutes, M&A NDAs, banking credentials, tax returns, vendor payments, executive compensation
- That breadth (financial + PII + legal + credentials) does not look like "archive this project folder"
- A user zipping up a project takes one topic; grabbing every sensitivity category at once is opportunistic collection

**Step 3 — Cross-reference with prior activity:**
Correlate with AGC-041 (share enumeration) if present in the same timeline:
- Enumeration of available shares -> selection of Finance share -> archive of contents = complete collection chain
- The sequence maps to T1135 (Network Share Discovery) -> T1560.001 (Archive Collected Data)

**Step 4 — Detection gap assessment:**
Sysmon EID 11 missing this archive is the finding the SOC has to act on:
- An attacker can stage archives in temp directories without a single file-creation event
- Detection rests entirely on PowerShell logging (EID 1 CommandLine or EID 4104 Script Block)
- If the attacker switches to a non-PowerShell archiver (7z.exe, WinRAR), even that layer fails unless the binary is monitored by name

### Report

**Verdict: True Positive** — Bulk archive creation staging sensitive data for exfiltration.

**Confidence: High** — Calibrated assessment:
1. Archive created in system temp directory (`C:\Windows\Temp`) — staging location, not user workspace.
2. Source files span four sensitivity categories (financial, PII, legal, credentials) — no routine archiving job looks like that.
3. 8 files from a single share archived in one operation — bulk collection pattern.
4. PowerShell with -ExecutionPolicy Bypass — deliberate policy override.
5. Detection gap: Sysmon EID 11 does not capture .zip creation under the default config.

**Response recommendation:**
1. **Isolate the host** before the archive moves — caught at staging, the exfiltration never happens.
2. **Identify archive contents** to scope the exposure — the 8 files here hold salary data, credentials, and M&A material.
3. **Add archive extensions to Sysmon EID 11:** Include `.zip|.7z|.rar|.tar|.gz` in the TargetFilename filter to close the detection gap.
4. **Enable PowerShell Script Block Logging** (EID 4104) — it records `Compress-Archive` with full source and destination paths even when EID 11 misses the file.
5. **Monitor C:\Windows\Temp for new files** — user-context processes rarely have a legitimate reason to write there.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Collection (TA0009) | T1560.001 | Archive Collected Data: Archive via Utility | PowerShell Compress-Archive archived 8 Finance documents to C:\Windows\Temp\staged.zip (1,775 bytes). Sysmon EID 1 captured process. EID 11 missed .zip creation (SwiftOnSecurity config gap). Staging location + source breadth = collection pattern. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### Archive creation summary

```
Source:      C:\Shares\Finance\ (8 files, 28,589 bytes total)
Destination: C:\Windows\Temp\staged.zip (1,775 bytes compressed)
Method:      PowerShell Compress-Archive (native cmdlet)
User:        COMPROMISED-01\Administrator
Time:        22:21:07 UTC

Files archived:
  Q3-2026-Revenue-Report.xlsx        (4,557 B) - Financial
  Employee-Salary-Data-2026.csv      (3,259 B) - PII
  Board-Meeting-Minutes-Sep2026.docx (2,864 B) - Governance
  Merger-Acquisition-Draft-NDA.pdf   (5,162 B) - Legal/M&A
  Banking-Credentials-Internal.txt   (862 B)   - Credentials
  Tax-Returns-2025-Corporate.pdf     (6,260 B) - Financial
  Vendor-Payment-Schedule-Q4.xlsx    (2,161 B) - Financial
  Executive-Compensation-Review.docx (3,464 B) - PII
```

### Detection gap: Sysmon EID 11 misses archive creation

```
SwiftOnSecurity Sysmon EID 11 Configuration:
  - Filters to RuleName: EXE, DLL
  - Archive extensions (.zip, .7z, .rar) NOT included
  - Result: 0 EID 11 events for staged.zip

Recommendation: Add custom EID 11 rule:
  <FileCreate onmatch="include">
    <TargetFilename condition="end with">.zip</TargetFilename>
    <TargetFilename condition="end with">.7z</TargetFilename>
    <TargetFilename condition="end with">.rar</TargetFilename>
    <TargetFilename condition="end with">.tar</TargetFilename>
    <TargetFilename condition="end with">.gz</TargetFilename>
  </FileCreate>
```
