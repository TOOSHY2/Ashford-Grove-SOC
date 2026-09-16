# AGC-032 — SAM / SECURITY Hive Extraction

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-032` |
| Category | `05-credential-access` — Credential Access |
| MITRE Technique | `T1003.002` OS Credential Dumping: Security Account Manager |
| Verdict | True Positive |
| Confidence | Critical |
| Time to Detect | Immediate — Sysmon EID 1 captures `reg.exe save HKLM\SAM` with exact target and destination path |
| Time to Triage | 01:30 (check if all three hives saved together to a non-standard location) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ [AGC-031](../AGC-031-lsass-access/README.md) · next [AGC-033](../AGC-033-browser-credential-store/README.md) ▶ |
| One-line Summary | SAM registry hive extracted via `reg save` to `C:\Windows\Temp\`. SECURITY and SYSTEM hives blocked by access controls. Sysmon EID 1 captured the full `reg.exe` command line including target hive and destination path. |

## Attacker Perspective

### Tradecraft

**What:** The attacker uses the built-in `reg.exe` tool to save copies of critical Windows registry hives:
- **SAM** (Security Account Manager): Contains NTLM password hashes for all local user accounts.
- **SECURITY**: Contains LSA secrets, cached domain credentials, and security policy data.
- **SYSTEM**: Contains the boot key (SYSKEY) needed to decrypt the SAM and SECURITY hives offline.

An attacker extracts all three hives together because SAM hashes are encrypted with the SYSKEY stored in SYSTEM. With all three files, offline tools like `secretsdump.py` (Impacket) or `mimikatz lsadump::sam` can extract every local account password hash.

This is a Living-off-the-Land technique: `reg.exe` is a legitimate Windows utility, and `reg save` is its intended function. The malicious indicator is the context: saving SAM/SECURITY/SYSTEM to a temp directory rather than through an authorized backup tool.

**Why at this lifecycle stage:** After gaining local admin access, the attacker needs credentials for lateral movement. If LSASS dumping fails (as in AGC-031, where Defender and PPL blocked it), SAM extraction is the fallback. SAM hive extraction is an offline technique — it does not require opening a handle to LSASS, bypassing PPL, or evading AMSI.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator (RID-500) context.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 20:02:24 | Save SAM hive | COMPROMISED-HOST-01 | `reg save HKLM\SAM C:\Windows\Temp\sam.save /y` — succeeded (53,248 bytes) |
| 2 | 2026-09-15 20:02:29 | Save SECURITY hive | COMPROMISED-HOST-01 | `reg save HKLM\SECURITY C:\Windows\Temp\security.save /y` — Access Denied (insufficient backup privileges in session) |
| 3 | 2026-09-15 20:02:29 | Save SYSTEM hive | COMPROMISED-HOST-01 | `reg save HKLM\SYSTEM C:\Windows\Temp\system.save /y` — Access Denied |
| 4 | 2026-09-15 20:02:44 | Cleanup | COMPROMISED-HOST-01 | SAM file deleted |

**Partial execution note:** The SECURITY and SYSTEM hives require SeBackupPrivilege, which was not available in the guestcontrol session despite Administrator context. In an interactive desktop session (Logon Type 2/10), all three hives are accessible with a standard Administrator token. The SAM extraction alone still provides all local account password hashes (they can be cracked offline without the SYSKEY, though SYSKEY decryption is faster).

**Cleanup:** SAM hive file deleted. SECURITY and SYSTEM were never created.

## SOC Perspective

### Detection

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 20:02:24 | 1 (Sysmon) | Process Create | **Image:** `C:\Windows\System32\reg.exe` (PID 1364). **CommandLine:** `reg save HKLM\SAM C:\Windows\Temp\sam.save /y`. **User:** `COMPROMISED-01\Administrator`. **IntegrityLevel:** High. **OriginalFileName:** `reg.exe`. **ParentImage:** `powershell.exe`. |

**Detection rule logic:**
```
Sysmon EID 1
  WHERE Image ends with "reg.exe"
  AND CommandLine contains "save"
  AND CommandLine matches ANY ("SAM", "SECURITY", "SYSTEM")
```

The detection fires on the `reg save` command itself — even when the operation fails (as with SECURITY/SYSTEM), Sysmon EID 1 captures the process creation and full command line. Failed attempts are equally valuable as detection evidence because they reveal attacker intent.

### Investigation

**Step 1 — Identify the `reg save` targets:**
Sysmon EID 1 shows `reg.exe save HKLM\SAM C:\Windows\Temp\sam.save /y`. The SAM hive is the primary target for local credential extraction. Cross-reference with other recent `reg.exe` invocations to check whether SECURITY and SYSTEM were also attempted (they were, but the process create events may have been captured as separate EID 1 entries).

**Step 2 — Assess the combination pattern:**
All three hives being saved together (SAM + SECURITY + SYSTEM) is the strongest indicator of malicious intent. SAM alone has narrow legitimate uses (system backup utilities), but the trio together is exclusively an attack pattern — the attacker needs SYSTEM for the boot key to decrypt SAM offline. In this simulation, the combination intent was present even though only SAM succeeded.

**Step 3 — Examine the destination path:**
The hive files were saved to `C:\Windows\Temp\` — a world-writable directory commonly used by attackers for staging. Legitimate backup tools (Windows Server Backup, ntdsutil) save to dedicated backup locations, not temp directories.

**Step 4 — Check for exfiltration indicators:**
After hive extraction, the attacker typically exfiltrates the files. Look for:
- Sysmon EID 3 (Network Connection) from processes accessing the saved files
- Sysmon EID 11 (File Create) at archive/staging locations
- PowerShell compress or encode operations targeting the saved files
- SMB file copy to attacker-controlled hosts

**Step 5 — Cross-reference with AGC-031:**
The LSASS dump attempt (AGC-031) was blocked by Windows Defender and PPL. SAM extraction is the natural fallback — it achieves the same credential harvesting goal through a different vector. This progression (LSASS blocked -> SAM extraction) is a common attack pattern and increases confidence that this is a real attack, not a coincidence.

### Report

**Verdict: True Positive** — The SAM registry hive was extracted via `reg save` to `C:\Windows\Temp\`. The command was executed by Administrator from PowerShell, targeting the primary credential store on the system.

**Confidence: Critical** — The combination of indicators is near-conclusive:
1. `reg save HKLM\SAM` to a temp directory has no legitimate use outside authorized backup tools.
2. The attempts to also save SECURITY and SYSTEM (even though they failed) confirm the attacker's intent to extract the full credential set.
3. This follows a blocked LSASS dump attempt (AGC-031), showing the attacker pivoting to alternative credential access techniques.
4. The Administrator context on an already-compromised host (COMPROMISED-HOST-01) confirms this is part of an ongoing attack.

**Response recommendation:**
1. **Isolate the host** immediately — the attacker has already extracted SAM hashes.
2. **Assume all local account passwords are compromised** — reset every local account password on this host (Administrator, wadmin, michael.chen, any service accounts).
3. **Delete the saved hive files** if they still exist on the host or any staging locations.
4. **Check for exfiltration** — review network connections from the host during and after the extraction window.
5. **Reset credentials domain-wide** if cached domain credentials were also at risk (SECURITY hive was blocked in this case, but assume the worst if the attacker had interactive desktop access).
6. **Investigate the attack chain** — trace how Administrator access was obtained (AGC-025 through AGC-030) and how the attacker plans to use the extracted credentials (AGC-043+ lateral movement).
7. **Deploy registry auditing** — Windows Security EID 4657 (Registry value modification) can provide additional coverage for registry hive access.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Credential Access (TA0006) | T1003.002 | OS Credential Dumping: Security Account Manager | Sysmon EID 1: `reg.exe save HKLM\SAM C:\Windows\Temp\sam.save /y` by Administrator. SAM hive (53,248 bytes) successfully extracted to temp directory. SECURITY/SYSTEM attempts blocked but captured. Follows blocked LSASS dump (AGC-031). | Critical |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
