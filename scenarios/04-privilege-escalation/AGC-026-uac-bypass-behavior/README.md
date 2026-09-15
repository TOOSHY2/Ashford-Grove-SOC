# AGC-026 -- UAC-Bypass Behavior (fodhelper)

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-026` |
| Category | `04-privilege-escalation` -- Privilege Escalation |
| MITRE Technique | `T1548.002` Abuse Elevation Control Mechanism: Bypass User Account Control |
| Verdict | True Positive |
| Confidence | Critical |
| Time to Detect | Immediate -- Sysmon EID 13 captures `ms-settings\Shell\Open\command` registry writes; EID 1 captures fodhelper.exe launch |
| Time to Triage | 00:30 (registry path + binary combination is near-conclusive) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | < AGC-025 . next AGC-027 > |
| One-line Summary | fodhelper.exe UAC bypass via ms-settings registry hijack. Sysmon EID 13 (RuleName: T1042) captured both registry writes; EID 1 captured fodhelper.exe launch at High integrity. The registry path + auto-elevating binary combination has no legitimate use. |

## Attacker Perspective

### Tradecraft

**What:** The attacker exploits Windows auto-elevation behavior via `fodhelper.exe` (Features On Demand Helper). This binary is marked as auto-elevate in its manifest, meaning Windows will run it at High integrity without showing a UAC prompt. Before launching it, the attacker writes a malicious command to `HKCU\Software\Classes\ms-settings\Shell\Open\command` and sets the `DelegateExecute` value. When fodhelper.exe runs and attempts to open the `ms-settings:` URI handler, it finds the hijacked registry key and executes the attacker's command at High integrity.

This provides:
1. **Silent elevation** -- no UAC prompt is shown to the user. The absence of a consent dialog is the core of the technique.
2. **HKCU-based** -- the hijack is in the current user's registry hive (HKCU), not HKLM. This means no admin rights are needed to set up the bypass -- any standard user can write to their own HKCU.
3. **Trusted binary** -- fodhelper.exe is a Microsoft-signed system binary, so application whitelisting does not block it.
4. **Minimal footprint** -- the registry write is small and transient; the attacker cleans up immediately after the elevated command executes.

**Why at this lifecycle stage:** After gaining initial access to a standard user's session, the attacker needs to escalate to High integrity (admin) to disable security tools, install persistence mechanisms, or access protected resources. This bypass bridges the gap between standard-user access and admin-level execution without triggering any user-visible prompt.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context via guestcontrol.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 19:31:45 | Registry hijack | COMPROMISED-HOST-01 | `HKCU\Software\Classes\ms-settings\Shell\Open\command\(Default)` set to `cmd.exe /c echo AGC026-UAC-BYPASS > C:\Windows\Temp\agc026.txt` |
| 2 | 2026-09-15 19:31:45 | DelegateExecute | COMPROMISED-HOST-01 | `HKCU\Software\Classes\ms-settings\Shell\Open\command\DelegateExecute` set to empty string |
| 3 | 2026-09-15 19:31:47 | Launch fodhelper.exe | COMPROMISED-HOST-01 | `Start-Process fodhelper.exe` -- auto-elevate trigger |
| 4 | 2026-09-15 19:31:55 | Verify marker | COMPROMISED-HOST-01 | Marker file not created (session 0 limitation -- see below) |
| 5 | 2026-09-15 19:32:21 | Cleanup | COMPROMISED-HOST-01 | Registry key tree and marker file removed |

**Lab limitation:** The guestcontrol session runs in session 0 (non-interactive). fodhelper.exe launched successfully and Sysmon captured it, but the COM-based shell handler invocation that reads the hijacked registry key requires an interactive desktop session to fully execute the elevated child process. In a real attack targeting an interactive user session, `cmd.exe` would spawn at High integrity and create the marker file. The detection evidence (registry writes + fodhelper.exe launch) is complete regardless.

**Cleanup:** Registry key tree deleted and marker file removed.

## SOC Perspective

### Detection

**Sysmon EID 13 -- Registry Value Set (ms-settings hijack):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 19:31:45 | 13 | Registry Value Set | **RuleName:** `T1042`. **Image:** `powershell.exe` (PID 5228). **TargetObject:** `HKU\.DEFAULT\Software\Classes\ms-settings\Shell\Open\command\(Default)`. **Details:** `cmd.exe /c echo AGC026-UAC-BYPASS > C:\Windows\Temp\agc026.txt`. **User:** `COMPROMISED-01\Administrator`. |
| 2026-09-15 19:31:45 | 13 | Registry Value Set | **RuleName:** `T1042`. **Image:** `powershell.exe` (PID 5228). **TargetObject:** `HKU\.DEFAULT\Software\Classes\ms-settings\Shell\Open\command\DelegateExecute`. **Details:** (Empty). **User:** `COMPROMISED-01\Administrator`. |

**Sysmon EID 1 -- Process Create (fodhelper.exe):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 19:31:47 | 1 | Process Create | **Image:** `C:\Windows\System32\fodhelper.exe` (PID 3200). **IntegrityLevel:** High. **ParentImage:** `powershell.exe` (PID 5228). **User:** `COMPROMISED-01\Administrator`. |

**Key detection signals:**
1. **Sysmon EID 13 RuleName: T1042** -- SwiftOnSecurity config specifically tags writes to `ms-settings\Shell\Open\command` as a known technique indicator.
2. **Registry path is near-conclusive** -- `HKCU\Software\Classes\ms-settings\Shell\Open\command` has essentially no legitimate use. No standard application writes here. The presence of ANY value under this key is suspicious.
3. **Temporal correlation** -- registry writes at 19:31:45 immediately followed by fodhelper.exe launch at 19:31:47 (2-second gap). This tight sequence is the attack pattern.
4. **DelegateExecute value** -- the empty DelegateExecute value is specifically needed to redirect the shell handler. Its presence alongside a command in the Default value is the complete bypass signature.

### Investigation

**Step 1 -- Identify the registry hijack:**
Sysmon EID 13 with RuleName T1042 flagged writes to `ms-settings\Shell\Open\command`. The Default value contains `cmd.exe /c echo AGC026-UAC-BYPASS > C:\Windows\Temp\agc026.txt` -- a command designed to execute at elevated integrity. The companion `DelegateExecute` empty value completes the bypass setup.

**Step 2 -- Correlate with auto-elevating binary:**
Two seconds after the registry writes, Sysmon EID 1 shows `fodhelper.exe` launching at High integrity. fodhelper.exe is a known auto-elevating binary that opens the `ms-settings:` URI handler -- exactly what the registry hijack targets.

**Step 3 -- Confirm no UAC prompt (the silence is the evidence):**
In a UAC bypass, the absence of a UAC consent event is itself evidence. There is no Security EID 4688 with TokenElevationType showing a consent prompt, no `consent.exe` process creation. The elevation happened silently via the auto-elevate manifest -- this is the core of the technique.

**Step 4 -- Assess the attack chain:**
This bypass is commonly used as a stepping stone:
- **Before:** Attacker has standard-user shell (e.g., from phishing via AGC-001).
- **During:** fodhelper bypass grants High integrity without user interaction.
- **After:** Attacker can disable Defender, install services (AGC-021), create admin accounts (AGC-023/025), or deploy persistence mechanisms.

**Step 5 -- Known variants:**
The `ms-settings` handler hijack via fodhelper.exe is one of many UAC bypass variants. The same detection logic applies to:
- `computerdefaults.exe` (same `ms-settings` handler)
- `sdclt.exe` (uses `shell\open\command` in `Folder` class)
- `eventvwr.exe` (uses `mscfile\shell\open\command`)
Each variant writes to a different HKCU registry path but follows the same pattern: hijack handler + launch auto-elevating binary.

### Report

**Verdict: True Positive** -- A UAC bypass was attempted via the fodhelper.exe technique. Registry writes to `ms-settings\Shell\Open\command` were followed by fodhelper.exe execution. The combination of this specific registry path and auto-elevating binary has no legitimate use.

**Confidence: Critical** -- This is a near-conclusive indicator:
- The registry path `HKCU\Software\Classes\ms-settings\Shell\Open\command` has no legitimate applications.
- Sysmon EID 13 tagged the writes with RuleName T1042 (known technique).
- fodhelper.exe launched 2 seconds after the registry hijack.
- No single legitimate scenario explains this event sequence.
- A single corroborating source is sufficient when the indicator is this specific; confidence is not lowered by absence of a second source.

**Response recommendation:**
1. **Delete the malicious registry key** immediately: `reg delete "HKCU\Software\Classes\ms-settings" /f`.
2. **Investigate what the elevated command executed** -- the payload in the Default value reveals the attacker's next step.
3. **Enforce UAC "Always Notify"** via Group Policy -- this blocks auto-elevation for all binaries, defeating this class of bypass entirely.
4. **Detection rule (high-fidelity):** Alert on Sysmon EID 13 where TargetObject contains `ms-settings\Shell\Open\command` -- near-zero false positive rate.
5. **Broader detection:** Alert on any EID 13 writes to `HKCU\Software\Classes\*\Shell\Open\command` for known auto-elevate handlers (ms-settings, Folder, mscfile).
6. **Investigate the parent process** -- PowerShell (PID 5228) performed the registry writes. Determine how this PowerShell session was established.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Privilege Escalation (TA0004) | T1548.002 | Abuse Elevation Control Mechanism: Bypass User Account Control | Sysmon EID 13 (RuleName: T1042): `ms-settings\Shell\Open\command\(Default)` set to `cmd.exe /c echo AGC026-UAC-BYPASS...` and `DelegateExecute` set to empty. Sysmon EID 1: `fodhelper.exe` (PID 3200) launched 2s later at High integrity. | Critical |
| Defense Evasion (TA0005) | T1548.002 | Abuse Elevation Control Mechanism: Bypass User Account Control | Same evidence. UAC bypass is both privilege escalation (gains High integrity) and defense evasion (avoids UAC consent prompt). | Critical |

## Evidence

Screenshots: not applicable (text-based evidence collection only).
