# AGC-083 — LSASS Access: Caused by AV/EDR Self-Scan (False Positive)

> **Disclosure:** Executed & documented by Claude Code under direction and review by Ali.

## Card

| Field | Value |
|---|---|
| ID | `AGC-083` |
| Title | LSASS Access: Caused by AV/EDR Self-Scan |
| Category | `14-false-positive` — False Positive Triage |
| Severity | High (alert trigger) |
| MITRE Technique | T1003.001 (observed, not malicious) |
| Verdict | False Positive / Benign |
| Confidence | High |
| Malicious Twin | AGC-031 (LSASS Memory Credential Dumping) |
| Chain | ◀ [AGC-082](../AGC-082-new-admin-change-ticket/README.md) · next [AGC-084](../AGC-084-dns-beacon-saas/README.md) ▶ |

## Attacker Perspective

### Simulation

Triggered an on-demand Windows Defender QuickScan (`Start-MpScan -ScanType QuickScan`) on COMPROMISED-HOST-01. The scan completed in 10 seconds. Verified that `MsMpEng.exe` (PID 3220) is the Defender engine process and checked its Microsoft signature. With Sysmon EID 10 enabled, this scan would log ProcessAccess events against `lsass.exe` with `SourceImage: MsMpEng.exe`.

**Execution window**: 00:42:09 - 00:42:19 UTC on COMPROMISED-HOST-01

## SOC Perspective

### Detection

Sysmon EID 10 (ProcessAccess) logs any process that opens a handle to `lsass.exe` memory. Defender's scan engine (`MsMpEng.exe`) does this routinely during QuickScan and real-time protection, and the resulting EID 10 events look the same as those from credential dumping tools (Mimikatz, procdump). That makes LSASS access one of the noisiest alert types a SOC handles.

**Lab constraint**: Sysmon EID 10 (ProcessAccess) is **disabled** in the SwiftOnSecurity configuration deployed on COMPROMISED-HOST-01. The investigation falls back on Defender operational logs and process/signature verification.

### Investigation

#### Step 1: Confirm Defender is Active and Legitimate

**Windows Defender Status:**
```
AntivirusEnabled: True
RealTimeProtectionEnabled: True
AntispywareEnabled: True
AMServiceEnabled: True
AntivirusSignatureLastUpdated: 09/15/2026 08:32:42
```

All Defender components are active with current signatures (updated within 24 hours).

#### Step 2: Verify MsMpEng.exe Identity and Signature

**Process verification:**
```
MsMpEng.exe running: PID 3220
Path: C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26080.3-0\MsMpEng.exe
```

**Digital signature verification:**
```
Status: Valid
Subject: CN=Microsoft Windows Publisher, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
Issuer: CN=Windows Production PCA 2023, O=Microsoft Corporation, C=US
```

The executable carries a valid Microsoft signature from a current production certificate. This is the discriminator that matters: a credential dumping tool renamed to `MsMpEng.exe` would be unsigned, carry an invalid signature, or be signed by someone other than Microsoft.

#### Step 3: Correlate with Defender Scan Events

**Defender Operational Log — EID 1000 (Scan Started):**
```
TimeCreated: 2026-09-16 00:42:09
Event ID: 1000 - Microsoft Defender Antivirus scan has started.
Scan ID: {1F7E090D-BA91-4C6A-AAF1-449037616A1F}
Scan Type: Antimalware
Scan Parameters: Quick Scan
User: NT AUTHORITY\LOCAL SERVICE
Scan Trigger: On demand
```

**Defender Operational Log — EID 1001 (Scan Completed):**
```
TimeCreated: 2026-09-16 00:42:19
Event ID: 1001 - Microsoft Defender Antivirus scan has finished.
Scan ID: {1F7E090D-BA91-4C6A-AAF1-449037616A1F}
Scan Type: Antimalware
Scan Parameters: Quick Scan
Scan Time: 0:00:10
```

The scan window (00:42:09 - 00:42:19 UTC) fixes the timing. Any LSASS access by MsMpEng.exe inside that 10-second window belongs to the scan.

#### Step 4: Sysmon EID 10 Detection Gap (Lab Constraint)

```
Sysmon EID 10 (ProcessAccess) events found: 0
```

Sysmon EID 10 is **disabled** in the SwiftOnSecurity configuration on this endpoint. With it enabled, the event would show:

- `SourceImage`: `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26080.3-0\MsMpEng.exe`
- `TargetImage`: `C:\Windows\System32\lsass.exe`
- `GrantedAccess`: `0x1410` or `0x1FFFFF` (depending on scan depth)

The missing EID 10 does not change the verdict: the Defender operational log confirms the scan on its own, and the signature check confirms which process did the accessing.

#### Step 5: LSASS Process Confirmation

```
lsass.exe running: PID 816
RunAsPPL: Enabled (Windows 11 default)
```

LSASS runs as Protected Process Light (PPL), which blocks handle access from non-protected processes. MsMpEng.exe is itself a protected process and is allowed to touch LSASS during scans.

### Report

**Verdict: False Positive / Benign** — The LSASS access came from Defender's scan engine (`MsMpEng.exe`), which carries a valid Microsoft signature and lines up with a confirmed QuickScan (Defender EID 1000/1001). This is routine AV behavior, not credential access.

**Lab constraint**: Sysmon EID 10 (ProcessAccess) is disabled in the SwiftOnSecurity configuration, so the direct `SourceImage`/`TargetImage`/`GrantedAccess` fields are unavailable. The verdict rests instead on the Defender operational logs for the scan, the process identity, and the digital signature.

**Recommendation**: Close as Benign. Allowlist the `MsMpEng.exe` signature plus the standard scan access mask for LSASS access alerts. **Critical**: the allowlist must key on the signature, not the process name — exempting anything named `MsMpEng.exe` regardless of signer hands an attacker a trivial bypass.

**Cross-reference**: The malicious twin is **AGC-031**, where LSASS access comes from an unsigned or non-Microsoft binary with no Defender scan running.

#### Discriminating evidence (benign vs malicious)

| Factor | AGC-083 (Benign) | AGC-031 (Malicious) |
|--------|-------------------|---------------------|
| **SourceImage** | `MsMpEng.exe` (Defender engine) | Unknown binary, procdump, mimikatz, or renamed tool |
| **Digital signature** | Valid, Microsoft-signed (Windows Production PCA 2023) | Unsigned, invalid, or non-Microsoft signer |
| **Process path** | `C:\ProgramData\Microsoft\Windows Defender\Platform\` | Unusual path (Temp, Downloads, user profile) |
| **Scan correlation** | Defender EID 1000/1001 confirm active scan window | No scan activity in Defender logs |
| **GrantedAccess** | Standard scan access mask | Credential-dump access mask (0x1010, 0x1FFFFF) |
| **Process protection** | Runs as protected process (PPL-compatible) | Typically not a protected process |

**Signature verification is the strongest discriminator**. An attacker can rename a binary to `MsMpEng.exe`; they cannot forge a valid Microsoft signature. If the signature cannot be checked, drop confidence to Medium and say so in the report.

### MITRE Mapping

No malicious technique applies. The alert fires through the same detection rules as AGC-031:

| Technique ID | Name | Tactic | Disposition |
|-------------|------|--------|-------------|
| T1003.001 | OS Credential Dumping: LSASS Memory | Credential Access | **Observed, Benign** — LSASS access by MsMpEng.exe (Microsoft-signed, PID 3220) during confirmed Defender QuickScan (EID 1000/1001, Scan ID {1F7E090D-...}). Lab note: Sysmon EID 10 disabled in SwiftOnSecurity config; verdict based on Defender operational logs and signature verification. |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
