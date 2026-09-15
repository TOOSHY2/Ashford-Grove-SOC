# AGC-072 -- Ransomware Simulation (Safe XOR + Rename)

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-072` |
| Category | `12-impact-recovery` -- Impact & Recovery |
| MITRE Technique | `T1486` Data Encrypted for Impact |
| Verdict | True Positive |
| Confidence | Critical |
| Time to Detect | Sysmon EID 1 (powershell.exe executing encryption script) |
| Time to Triage | 03:00 (rapid file transformation burst, clear ransomware behavioral pattern) |
| Affected Systems | `COMPROMISED-HOST-01` (10.10.10.103) |
| Chain | < AGC-071 . next AGC-073 > |
| One-line Summary | Ransomware behavioral simulation: 10 synthetic financial documents (3KB each) XOR-encrypted with static key (0x42) and renamed to `.agc072locked` extension in under 200 milliseconds. Sysmon EID 11 captured only the script file copy (not the `.agc072locked` files) due to SwiftOnSecurity EXE/DLL-only file creation filter -- a critical detection gap for ransomware file transformation artifacts. Sysmon EID 1 captured the orchestrating PowerShell process with full command line. No live malware used; reversible XOR with known key. |

## Attacker Perspective

### Tradecraft

**What:** Encrypt victim files using a symmetric cipher and rename them with a distinctive extension, rendering the originals inaccessible. In real ransomware, the key would be asymmetrically encrypted and only the attacker holds the decryption key. This simulation uses XOR with a known static key (0x42) for safe, reversible execution.

**Why an Attacker Uses It Here:**
- Culmination of the attack chain: after establishing persistence (AGC-019-024), escalating privileges (AGC-025-030), harvesting credentials (AGC-031-036), discovering targets (AGC-037-042), moving laterally (AGC-043-050), establishing C2 (AGC-051-056), collecting data (AGC-057-061), exfiltrating (AGC-062-066), and evading defenses (AGC-067-071)
- Maximum business impact: encrypted financial documents directly threaten operations
- Ransomware operators typically encrypt files rapidly (seconds to minutes) to minimize the window for detection and response
- The `.agc072locked` extension serves as the ransom note equivalent, signaling compromise to the victim

**Simulation Safety:**
- XOR cipher with known key (0x42) -- trivially reversible, not cryptographically secure
- Synthetic test files only -- no real data at risk
- Isolated test directory (`C:\Windows\Temp\agc072_test_data`) -- no system files touched
- Automatic cleanup after evidence collection

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context
- Sysmon operational with SwiftOnSecurity configuration

**Execution:**
```powershell
# Create 10 synthetic financial documents (3KB each with padding)
$testDir = "C:\Windows\Temp\agc072_test_data"
New-Item -ItemType Directory -Path $testDir -Force

# Files: Financial-Report-Q3.xlsx, Client-List-September.csv,
#   Board-Minutes-2026-09.docx, Investment-Strategy.pptx,
#   Payroll-Export.csv, Tax-Returns-2025.pdf,
#   Wire-Transfers-Sep.xlsx, Merger-Analysis.docx,
#   Risk-Assessment.xlsx, Compliance-Audit.pdf

# XOR encrypt each file and rename to .agc072locked
$key = 0x42
Get-ChildItem "$testDir\*" | ForEach-Object {
    $bytes = [System.IO.File]::ReadAllBytes($_.FullName)
    $xored = New-Object byte[] $bytes.Length
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        $xored[$i] = $bytes[$i] -bxor $key
    }
    [System.IO.File]::WriteAllBytes("$($_.FullName).agc072locked", $xored)
    Remove-Item $_.FullName -Force
}
```

**Result:** All 10 files encrypted and renamed in under 200ms (23:27:27.001 to 23:27:27.200 UTC). Each original file replaced by its `.agc072locked` counterpart. Test directory cleaned up after evidence collection.

## SOC Perspective

### Detection

**Sysmon EID 1 -- Orchestrating PowerShell process:**
```
Process Create:
UtcTime: 2026-09-15 23:27:18.750
ProcessGuid: {eb65e329-d45c-6aa9-7805-000000001400}
ProcessId: 3800
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc072-sim.ps1
User: COMPROMISED-01\Administrator
LogonId: 0x722BE0
IntegrityLevel: High
ParentImage: C:\Windows\System32\VBoxService.exe
```

**Sysmon EID 11 -- File creation (script copy only):**
```
File created:
UtcTime: 2026-09-15 23:27:17.218
ProcessGuid: {eb65e329-d45b-6aa9-7705-000000001400}
ProcessId: 3180
Image: C:\Windows\System32\VBoxService.exe
TargetFilename: C:\Temp\agc072-sim.ps1
```

**DETECTION GAP -- EID 11 NOT triggered for .agc072locked files:**
The SwiftOnSecurity Sysmon configuration filters EID 11 (FileCreate) to only capture EXE and DLL extensions (`RuleName: EXE` / `RuleName: DLL`). The 10 `.agc072locked` files created during the ransomware simulation did NOT generate EID 11 events. This is a significant detection gap: ransomware file transformations that use non-executable extensions are invisible to this Sysmon configuration's file creation monitoring.

**Ransomware execution timeline (from simulation output):**
```
[2026-09-15 23:27:27.001] Starting file transformation
  [1] Financial-Report-Q3.xlsx -> Financial-Report-Q3.xlsx.agc072locked (3067 bytes)
  [2] Client-List-September.csv -> Client-List-September.csv.agc072locked (3080 bytes)
  [3] Board-Minutes-2026-09.docx -> Board-Minutes-2026-09.docx.agc072locked (3065 bytes)
  [4] Investment-Strategy.pptx -> Investment-Strategy.pptx.agc072locked (3063 bytes)
  [5] Payroll-Export.csv -> Payroll-Export.csv.agc072locked (3083 bytes)
  [6] Tax-Returns-2025.pdf -> Tax-Returns-2025.pdf.agc072locked (3068 bytes)
  [7] Wire-Transfers-Sep.xlsx -> Wire-Transfers-Sep.xlsx.agc072locked (3070 bytes)
  [8] Merger-Analysis.docx -> Merger-Analysis.docx.agc072locked (3066 bytes)
  [9] Risk-Assessment.xlsx -> Risk-Assessment.xlsx.agc072locked (3057 bytes)
  [10] Compliance-Audit.pdf -> Compliance-Audit.pdf.agc072locked (3070 bytes)
[2026-09-15 23:27:27.200] Transformation complete: 10 files encrypted
```

### Investigation

**Step 1 -- Identify the ransomware behavioral pattern:**
The EID 1 event shows PowerShell executing `agc072-sim.ps1` under Administrator context from `C:\Temp\`. Key ransomware indicators:
- Script execution from a staging directory (not a standard application path)
- Administrator privileges (required for system-wide encryption)
- Parent process is VBoxService.exe (guestcontrol execution -- in production, this would typically be a compromised application or exploit chain)
- The `-ExecutionPolicy Bypass` flag indicates deliberate policy circumvention

**Step 2 -- Assess the encryption burst:**
10 files transformed in 199 milliseconds -- this rapid-fire pattern is characteristic of ransomware:
- Real ransomware like LockBit 3.0 can encrypt thousands of files per second using multi-threaded I/O
- The burst pattern (many file operations in sub-second intervals) is detectable by behavioral analytics even when individual file operations are not logged
- The consistent `.agc072locked` extension rename is a ransomware hallmark (cf. `.encrypted`, `.locked`, `.crypt`)

**Step 3 -- Evaluate detection coverage gaps:**

| Detection Layer | Status | Notes |
|---|---|---|
| Sysmon EID 1 (Process Create) | CAPTURED | PowerShell with script path in CommandLine |
| Sysmon EID 11 (File Create) | NOT CAPTURED | SwiftOnSecurity config: EXE/DLL only |
| Sysmon EID 23 (File Delete) | NOT ENABLED | Would have captured original file deletions |
| Sysmon EID 26 (File Delete Detected) | NOT ENABLED | Alternative to EID 23 |
| Windows Defender | ALLOWED | XOR is not a known malware signature |
| Wazuh SIEM | PARTIAL | Would alert on EID 1 if rule exists for script execution |

**Step 4 -- Cross-reference with attack chain:**
This is the culmination of the full kill chain simulated across AGC-001 through AGC-071. The ransomware execution represents the "impact" phase where all prior tradecraft (initial access, persistence, privilege escalation, lateral movement, defense evasion) converges into the attacker's ultimate objective: denying the victim access to their data for extortion.

### Report

**Verdict: True Positive** -- Ransomware behavioral pattern: bulk file encryption with extension rename.

**Confidence: Critical** -- Despite the simulation using safe XOR encryption:
1. The behavioral pattern (rapid bulk encryption + extension rename) is unambiguous ransomware activity
2. The orchestrating process was captured by Sysmon EID 1 with full command line
3. 10 financial documents encrypted in under 200ms demonstrates the speed of real ransomware
4. The detection gap (EID 11 missing for non-EXE/DLL files) is a genuine and significant finding
5. Administrator-context execution from a staging directory matches real-world ransomware deployment

**Response recommendation:**
1. **Expand Sysmon EID 11 filtering** to capture file creation for common ransomware extensions (`.locked`, `.encrypted`, `.crypt`, and any anomalous new extensions appearing in burst patterns) -- the current EXE/DLL-only filter misses the entire ransomware file transformation
2. **Enable Sysmon EID 23 or EID 26** (FileDelete / FileDeleteDetected) to capture original file deletion during encryption -- this provides a second detection opportunity
3. **Implement behavioral analytics** for rapid file I/O bursts: 10+ file operations within 1 second to the same directory should trigger a high-severity alert regardless of file extension
4. **Deploy canary files** (honeypot documents) in sensitive directories -- any modification of these files triggers an immediate alert, independent of Sysmon configuration
5. **Network isolation** upon ransomware detection -- automated host quarantine to prevent lateral spread of encryption
6. **Verify backup integrity** -- ransomware operators often target backup systems before encrypting primary data; ensure offline/immutable backups exist

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Impact (TA0040) | T1486 | Data Encrypted for Impact | 10 synthetic financial documents XOR-encrypted (key 0x42) and renamed to .agc072locked in 199ms. Sysmon EID 1 captured powershell.exe PID 3800 executing agc072-sim.ps1. EID 11 gap: .agc072locked files not captured (EXE/DLL-only filter). | Critical |

## Evidence

Screenshots: not applicable (text-based evidence collection only).

### File transformation summary

```
RANSOMWARE SIMULATION RESULTS
==============================
Start: 2026-09-15 23:27:27.001 UTC
End:   2026-09-15 23:27:27.200 UTC
Duration: 199 milliseconds
Files encrypted: 10/10
Encryption method: XOR (key: 0x42)
Extension: .agc072locked
Average file size: 3,069 bytes

Sysmon EID 1: CAPTURED (PID 3800, ProcessGuid {eb65e329-d45c-6aa9-7805-000000001400})
Sysmon EID 11: 1 event (script file only -- NOT the encrypted output files)
Sysmon EID 23: NOT ENABLED
Sysmon EID 26: NOT ENABLED

DETECTION GAP: SwiftOnSecurity Sysmon config EID 11 rule filters
to EXE/DLL extensions only. Ransomware output files (.agc072locked)
are invisible to file creation monitoring. This gap applies to ALL
ransomware families that use non-executable extensions for encrypted
output (which is virtually all of them).
```

### Attack chain position

```
AGC-001-010: Initial Access (Phishing)
AGC-011-018: Execution
AGC-019-024: Persistence
AGC-025-030: Privilege Escalation
AGC-031-036: Credential Access
AGC-037-042: Discovery
AGC-043-050: Lateral Movement
AGC-051-056: Command & Control
AGC-057-061: Collection
AGC-062-066: Exfiltration
AGC-067-071: Defense Evasion
AGC-072: >>> DATA ENCRYPTED FOR IMPACT <<< (this scenario)
```
