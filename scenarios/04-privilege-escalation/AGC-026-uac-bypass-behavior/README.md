# AGC-026 — UAC-Bypass Behavior (fodhelper)

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-026` |
| Category | `04-privilege-escalation` — Privilege Escalation |
| MITRE Technique | `T1548.002` Abuse Elevation Control Mechanism: Bypass User Account Control |
| Verdict | True Positive |
| Confidence | Critical |
| Time to Detect | Immediate — Sysmon EID 13 captures `ms-settings\Shell\Open\command` registry writes; EID 1 captures fodhelper.exe launch |
| Time to Triage | 00:30 (registry path + binary combination is near-conclusive) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ [AGC-025](../AGC-025-privileged-group-add/README.md) · next [AGC-027](../AGC-027-service-misconfig/README.md) ▶ |
| One-line Summary | fodhelper.exe UAC bypass via ms-settings registry hijack. Sysmon EID 13 (RuleName: T1042) captured both registry writes; EID 1 captured fodhelper.exe launch at High integrity. The registry path + auto-elevating binary combination has no legitimate use. |

## Attacker Perspective

### Tradecraft

**What:** The attacker abuses Windows auto-elevation through `fodhelper.exe` (Features On Demand Helper). Its manifest marks it auto-elevate, so Windows runs it at High integrity with no UAC prompt. First the attacker writes a command to `HKCU\Software\Classes\ms-settings\Shell\Open\command` and sets `DelegateExecute`. When fodhelper.exe opens the `ms-settings:` URI handler, it reads the hijacked key and runs the attacker's command at High integrity.

This provides:
1. **Silent elevation** — the user sees no UAC prompt. That missing consent dialog is the core of the technique.
2. **HKCU-based** — the hijack sits in the current user's hive (HKCU), not HKLM, so no admin rights are needed to set it up. Any standard user can write their own HKCU.
3. **Trusted binary** — fodhelper.exe is Microsoft-signed, so application allowlisting does not block it.
4. **Minimal footprint** — the registry write is small and short-lived; the attacker removes it the moment the elevated command runs.

**Why at this lifecycle stage:** Holding a standard user's session, the attacker needs High integrity to disable security tools, plant persistence, or reach protected resources. This bypass carries them from standard-user access to admin execution with no prompt the user could see.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context via guestcontrol.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 19:31:45 | Registry hijack | COMPROMISED-HOST-01 | `HKCU\Software\Classes\ms-settings\Shell\Open\command\(Default)` set to `cmd.exe /c echo AGC026-UAC-BYPASS > C:\Windows\Temp\agc026.txt` |
| 2 | 2026-09-15 19:31:45 | DelegateExecute | COMPROMISED-HOST-01 | `HKCU\Software\Classes\ms-settings\Shell\Open\command\DelegateExecute` set to empty string |
| 3 | 2026-09-15 19:31:47 | Launch fodhelper.exe | COMPROMISED-HOST-01 | `Start-Process fodhelper.exe` — auto-elevate trigger |
| 4 | 2026-09-15 19:31:55 | Verify marker | COMPROMISED-HOST-01 | Marker file not created (session 0 limitation — see below) |
| 5 | 2026-09-15 19:32:21 | Cleanup | COMPROMISED-HOST-01 | Registry key tree and marker file removed |

**Lab limitation:** The guestcontrol session runs in session 0 (non-interactive). fodhelper.exe launched and Sysmon captured it, but the COM shell-handler call that reads the hijacked key needs an interactive desktop to spawn the elevated child. Against an interactive user session, `cmd.exe` would spawn at High integrity and write the marker file. The detection evidence — registry writes plus fodhelper.exe launch — is complete either way.

**Cleanup:** Registry key tree deleted and marker file removed.

## SOC Perspective

### Detection

**Sysmon EID 13 — Registry Value Set (ms-settings hijack):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 19:31:45 | 13 | Registry Value Set | **RuleName:** `T1042`. **Image:** `powershell.exe` (PID 5228). **TargetObject:** `HKU\.DEFAULT\Software\Classes\ms-settings\Shell\Open\command\(Default)`. **Details:** `cmd.exe /c echo AGC026-UAC-BYPASS > C:\Windows\Temp\agc026.txt`. **User:** `COMPROMISED-01\Administrator`. |
| 2026-09-15 19:31:45 | 13 | Registry Value Set | **RuleName:** `T1042`. **Image:** `powershell.exe` (PID 5228). **TargetObject:** `HKU\.DEFAULT\Software\Classes\ms-settings\Shell\Open\command\DelegateExecute`. **Details:** (Empty). **User:** `COMPROMISED-01\Administrator`. |

**Sysmon EID 1 — Process Create (fodhelper.exe):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 19:31:47 | 1 | Process Create | **Image:** `C:\Windows\System32\fodhelper.exe` (PID 3200). **IntegrityLevel:** High. **ParentImage:** `powershell.exe` (PID 5228). **User:** `COMPROMISED-01\Administrator`. |

**Key detection signals:**
1. **Sysmon EID 13 RuleName: T1042** — the SwiftOnSecurity config tags writes to `ms-settings\Shell\Open\command` as a known technique indicator.
2. **Registry path is near-conclusive** — no standard application writes to `HKCU\Software\Classes\ms-settings\Shell\Open\command`. Any value under this key is suspicious.
3. **Temporal correlation** — registry writes at 19:31:45, fodhelper.exe launch at 19:31:47, a 2-second gap. That tight sequence is the attack.
4. **DelegateExecute value** — the empty DelegateExecute value redirects the shell handler. Paired with a command in the Default value, it is the full bypass signature.

### Investigation

**Step 1 — Identify the registry hijack:**
Sysmon EID 13 with RuleName T1042 flagged writes to `ms-settings\Shell\Open\command`. The Default value holds `cmd.exe /c echo AGC026-UAC-BYPASS > C:\Windows\Temp\agc026.txt`, set to run at elevated integrity. The companion empty `DelegateExecute` value completes the setup.

**Step 2 — Correlate with auto-elevating binary:**
Two seconds after the writes, Sysmon EID 1 shows `fodhelper.exe` launching at High integrity. fodhelper.exe auto-elevates and opens the `ms-settings:` URI handler, exactly the handler the hijack targets.

**Step 3 — Confirm no UAC prompt (the silence is the evidence):**
In a UAC bypass the missing consent event is the evidence. No Security EID 4688 with a consent-prompt TokenElevationType, no `consent.exe` process. The auto-elevate manifest elevated the binary silently, which is the technique.

**Step 4 — Assess the attack chain:**
The bypass serves as a stepping stone:
- **Before:** Attacker holds a standard-user shell, e.g. from phishing in AGC-001.
- **During:** fodhelper grants High integrity with no user interaction.
- **After:** Attacker can disable Defender, install services (AGC-021), create admin accounts (AGC-023/025), or plant persistence.

**Step 5 — Known variants:**
The `ms-settings` handler hijack via fodhelper.exe is one of several UAC bypass variants. The same detection logic covers:
- `computerdefaults.exe` (same `ms-settings` handler)
- `sdclt.exe` (uses `shell\open\command` in `Folder` class)
- `eventvwr.exe` (uses `mscfile\shell\open\command`)
Each writes to a different HKCU path but follows the same pattern: hijack the handler, then launch the auto-elevating binary.

### Report

**Verdict: True Positive** — The attacker attempted a fodhelper.exe UAC bypass. Registry writes to `ms-settings\Shell\Open\command` were followed by fodhelper.exe. This registry path paired with an auto-elevating binary has no legitimate use.

**Confidence: Critical** — A near-conclusive indicator:
- No legitimate application writes to `HKCU\Software\Classes\ms-settings\Shell\Open\command`.
- Sysmon EID 13 tagged the writes with RuleName T1042.
- fodhelper.exe launched 2 seconds after the hijack.
- No legitimate sequence produces these events.
- When the indicator is this specific, one source is enough; a missing second source does not lower confidence.

**Response recommendation:**
1. **Delete the malicious registry key** immediately: `reg delete "HKCU\Software\Classes\ms-settings" /f`.
2. **Investigate what the elevated command ran** — the payload in the Default value shows the attacker's next step.
3. **Enforce UAC "Always Notify"** via Group Policy — this blocks auto-elevation for every binary and defeats the whole bypass class.
4. **Detection rule (high-fidelity):** Alert on Sysmon EID 13 where TargetObject contains `ms-settings\Shell\Open\command`; near-zero false positive rate.
5. **Broader detection:** Alert on any EID 13 write to `HKCU\Software\Classes\*\Shell\Open\command` for known auto-elevate handlers (ms-settings, Folder, mscfile).
6. **Investigate the parent process** — PowerShell (PID 5228) made the registry writes. Trace how that PowerShell session started.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Privilege Escalation (TA0004) | T1548.002 | Abuse Elevation Control Mechanism: Bypass User Account Control | Sysmon EID 13 (RuleName: T1042): `ms-settings\Shell\Open\command\(Default)` set to `cmd.exe /c echo AGC026-UAC-BYPASS...` and `DelegateExecute` set to empty. Sysmon EID 1: `fodhelper.exe` (PID 3200) launched 2s later at High integrity. | Critical |
| Defense Evasion (TA0005) | T1548.002 | Abuse Elevation Control Mechanism: Bypass User Account Control | Same evidence. UAC bypass is both privilege escalation (gains High integrity) and defense evasion (avoids UAC consent prompt). | Critical |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
