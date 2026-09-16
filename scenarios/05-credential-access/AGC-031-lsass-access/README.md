# AGC-031 — LSASS Memory Access

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-031` |
| Category | `05-credential-access` — Credential Access |
| MITRE Technique | `T1003.001` OS Credential Dumping: LSASS Memory |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Immediate — Windows Defender (EID 1116) blocked the dump attempt in real time; detected `HackTool:Win32/DumpLsass.H` and `HackTool:PowerShell/Lsassdump.A` via AMSI |
| Time to Triage | 02:00 (verify Defender alert, confirm LSASS was the target, check if dump file was created) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ [AGC-030](../../04-privilege-escalation/AGC-030-domain-admin-logon-workstation/README.md) (Privilege Escalation category) · next [AGC-032](../AGC-032-sam-security-hive/README.md) ▶ |
| FP Twin | AGC-083 |
| Full Chain | AGC-077 |
| One-line Summary | LSASS memory dump attempted via `comsvcs.dll MiniDump` technique. Windows Defender blocked all attempts (`HackTool:Win32/DumpLsass.H`). LSASS Protected Process Light (PPL) also denied direct handle access. **Critical detection gap:** Sysmon EID 10 (ProcessAccess) is DISABLED — if Defender is bypassed, no Sysmon fallback detection exists. |

## Attacker Perspective

### Tradecraft

**What:** The attacker attempts to dump the memory of the Local Security Authority Subsystem Service (LSASS) process to extract credentials. LSASS holds:
- NTLM password hashes for all logged-on users
- Kerberos tickets (TGTs and service tickets)
- Cleartext passwords (if WDigest is enabled or credentials were recently entered)
- Cached domain credentials

The classic technique uses `rundll32.exe` to call `comsvcs.dll`'s `MiniDump` export function:
```
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_PID> <output.dmp> full
```

This creates a full memory dump of LSASS that can be exfiltrated and parsed offline with tools like Mimikatz (`sekurlsa::minidump`). The technique uses only built-in Windows binaries (Living off the Land), avoiding the need to drop a custom tool on disk.

**Why at this lifecycle stage:** After gaining local administrator access (via the privilege escalation techniques in AGC-025 through AGC-030), credential harvesting from LSASS is the standard next step. The extracted credentials enable lateral movement (AGC-043+) by providing valid authentication material for other hosts in the domain.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context (RID-500).
- Windows 11 with Windows Defender real-time protection enabled.
- LSASS running as PID 816 (Protected Process Light).

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 19:57:09 | Script-based attempt | COMPROMISED-HOST-01 | PowerShell script containing LSASS dump code blocked by AMSI: `HackTool:PowerShell/Lsassdump.A` (Threat ID 2147807171) |
| 2 | 2026-09-15 19:57:25 | Direct rundll32 attempt | COMPROMISED-HOST-01 | `rundll32.exe comsvcs.dll, MiniDump 816 ... full` blocked by Defender: `HackTool:Win32/DumpLsass.H` (Threat ID 2147786203) |
| 3 | 2026-09-15 19:58:06 | OpenProcess API attempt | COMPROMISED-HOST-01 | Direct `OpenProcess` with PROCESS_VM_READ returned Access Denied (error 5) — LSASS PPL protection active |
| 4 | 2026-09-15 19:58:44 | Second rundll32 attempt | COMPROMISED-HOST-01 | Blocked again: `HackTool:Win32/DumpLsass.H` |
| 5 | 2026-09-15 19:59:28 | Third rundll32 attempt | COMPROMISED-HOST-01 | Blocked again: `HackTool:Win32/DumpLsass.H` |

**Result:** All dump attempts were blocked. No dump file was created. Three layers of defense engaged:
1. **AMSI** — detected the PowerShell script content before execution
2. **Windows Defender real-time protection** — detected the comsvcs.dll MiniDump command line signature
3. **LSASS PPL** — denied OpenProcess handle requests for memory read access

**Cleanup:** No dump file to clean up (all attempts blocked).

## SOC Perspective

### Detection

**Primary detection: Windows Defender (EID 1116)**

| Timestamp (UTC) | EID | Source | Detail |
|---|---|---|---|
| 2026-09-15 19:57:09 | 1116 | Windows Defender | **Name:** `HackTool:PowerShell/Lsassdump.A`. **ID:** 2147807171. **Severity:** High. **Category:** Tool. **Path:** `amsi:_C:\Temp\agc031-sim.ps1`. **Detection Source:** AMSI. **User:** `COMPROMISED-01\Administrator`. PowerShell AMSI scan detected LSASS dump keywords in script content. |
| 2026-09-15 19:57:25 | 1116 | Windows Defender | **Name:** `HackTool:Win32/DumpLsass.H`. **ID:** 2147786203. **Severity:** High. **Category:** Tool. **Path:** `CmdLine:_C:\Windows\System32\rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 816 C:\Windows\Temp\lsass_dump.dmp full`. **Detection Source:** System. **User:** `NT AUTHORITY\SYSTEM`. |
| 2026-09-15 19:58:44 | 1116 | Windows Defender | Same detection. **Path:** `CmdLine:_C:\Windows\System32\cmd.exe /c rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 816 C:\Windows\Temp\agc031.dmp full`. Second attempt also blocked. |
| 2026-09-15 19:59:28 | 1116 | Windows Defender | Third attempt also blocked. Same signature match on comsvcs.dll MiniDump command line. |

**CRITICAL DETECTION GAP: Sysmon EID 10 (ProcessAccess) is DISABLED.**

Zero EID 10 events found in the last 300 Sysmon entries. The SwiftOnSecurity Sysmon configuration does not enable EID 10, which is the primary Sysmon detection source for LSASS access. This creates a defense-in-depth gap:

- If Windows Defender is disabled, bypassed (e.g., `Set-MpPreference -DisableRealtimeMonitoring $true`), or the attacker uses an AMSI bypass + an unsigned/novel dump tool, there is **no Sysmon fallback detection** for LSASS access.
- Combined with the EID 7 gap (discovered in AGC-028), this means DLL injection into LSASS (T1055.001) — an alternative credential-dumping technique — is also invisible to Sysmon.

### Investigation

**Step 1 — Assess the detection source:**
Windows Defender EID 1116 identified `HackTool:Win32/DumpLsass.H` targeting LSASS via the `comsvcs.dll MiniDump` technique. The detection was signature-based (command-line pattern matching), which is effective against known tools but can be evaded by obfuscation, renamed binaries, or custom dump utilities.

**Step 2 — Confirm LSASS was the target:**
The Defender alert path shows `MiniDump 816` where PID 816 is `lsass.exe` (confirmed via `tasklist`). The intent is unambiguous: extracting LSASS process memory for offline credential parsing.

**Step 3 — Verify dump was blocked:**
No dump file exists at `C:\Windows\Temp\lsass_dump.dmp` or `C:\Windows\Temp\agc031.dmp`. Additionally, LSASS PPL (Protected Process Light) independently blocked `OpenProcess` calls with PROCESS_VM_READ access (error 5). Two independent defenses prevented credential extraction.

**Step 4 — Identify the attacker context:**
The Defender alerts show two user contexts:
- `COMPROMISED-01\Administrator` (for the AMSI/PowerShell detection) — the attacker has local admin access
- `NT AUTHORITY\SYSTEM` (for the command-line detections) — the rundll32 process ran with SYSTEM privileges

An attacker with Administrator/SYSTEM access who is attempting LSASS dumping has already achieved significant compromise. The investigation should shift from "was the dump successful?" to "how did the attacker get admin access, and what else have they done?"

**Step 5 — Distinguish from False Positive (cross-reference AGC-083):**
The key differentiator for this True Positive vs. the FP twin (AGC-083):
- **SourceImage matters**: This alert was triggered by `rundll32.exe` calling `comsvcs.dll` — a known LSASS dump technique. In AGC-083, the SourceImage would be a legitimate security product (AV/EDR self-scan), which routinely accesses LSASS for monitoring purposes.
- **comsvcs.dll MiniDump is never legitimate**: No normal Windows operation or security tool uses `comsvcs.dll MiniDump` against LSASS. This command-line pattern is exclusively an attack technique.

**Step 6 — Chain context (cross-reference AGC-077):**
In the full attack chain (AGC-077), LSASS dumping follows initial access, execution, and privilege escalation. As an isolated finding, the severity is High (the attempt was blocked). In a chain context with preceding indicators, it would escalate to Critical as part of a confirmed multi-stage compromise.

### Report

**Verdict: True Positive** — An LSASS memory dump was attempted using the `comsvcs.dll MiniDump` Living-off-the-Land technique. Windows Defender blocked all attempts, and LSASS PPL prevented direct process memory access.

**Confidence: High** — Evidence is conclusive:
1. Windows Defender EID 1116 identified `HackTool:Win32/DumpLsass.H` with exact command-line match (three separate detections).
2. PowerShell AMSI detected `HackTool:PowerShell/Lsassdump.A` in the attack script.
3. LSASS was confirmed as PID 816 (`NT AUTHORITY\SYSTEM`).
4. The attacker had Administrator/SYSTEM access, indicating prior compromise.
5. Confidence is High (not Critical) because the dump was blocked — credentials were not actually extracted. In the full chain context (AGC-077), a successful dump escalates to Critical.

**Response recommendation:**
1. **Investigate how Administrator access was obtained** — the LSASS dump attempt confirms the host is compromised with admin-level access. Trace back through EID 4624 and Sysmon EID 1 to identify the initial access vector.
2. **Assume credentials may still be at risk** — the blocked dump does not mean the attacker has stopped. They may attempt alternative techniques (PPL bypass, unsigned tools, direct SAM extraction).
3. **Reset all credentials** that were cached in LSASS on this host at the time of compromise — any user who logged on interactively, any Kerberos tickets in memory.
4. **Enable Sysmon EID 10** with targeted LSASS monitoring to provide defense-in-depth:
   ```xml
   <ProcessAccess onmatch="include">
     <TargetImage condition="end with">lsass.exe</TargetImage>
   </ProcessAccess>
   ```
5. **Verify LSASS PPL is enabled** on all Windows endpoints (`RunAsPPL` registry key under `HKLM\SYSTEM\CurrentControlSet\Control\Lsa`).
6. **Deploy Credential Guard** where hardware supports it, to isolate credentials from LSASS entirely.
7. **Monitor for Defender bypass attempts** — `Set-MpPreference -DisableRealtimeMonitoring` or tamper protection events.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Credential Access (TA0006) | T1003.001 | OS Credential Dumping: LSASS Memory | Windows Defender EID 1116: `HackTool:Win32/DumpLsass.H` blocked `rundll32.exe comsvcs.dll, MiniDump 816 <path> full` targeting lsass.exe. AMSI also detected `HackTool:PowerShell/Lsassdump.A`. LSASS PPL denied OpenProcess. Sysmon EID 10 DISABLED (detection gap). | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
