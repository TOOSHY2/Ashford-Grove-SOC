# AGC-019 — Registry Run-Key Persistence

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-019` |
| Category | `03-persistence` — Persistence |
| MITRE Technique | `T1547.001` Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Immediate — Sysmon EID 13 captures registry value write with RuleName tag `T1060,RunKey` |
| Time to Triage | 01:30 (from alert to value-data analysis and software inventory comparison) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ [AGC-018](../../02-execution/AGC-018-eicar-detection-test/README.md) (Execution category) · next [AGC-020](../AGC-020-scheduled-task/README.md) ▶ |
| One-line Summary | Unknown registry Run key `WindowsUpdateHelper` added pointing to `cmd.exe` — not associated with any known legitimate software. FP twin: AGC-082. |

## Attacker Perspective

### Tradecraft

**What:** The attacker adds a value to the `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` registry key. Every value under this key specifies a program that Windows executes automatically each time the user logs on. This provides:

1. **Automatic re-execution** — the payload runs every time the compromised user logs in, surviving reboots.
2. **No elevation required** — HKCU Run keys are writable by standard users (no admin needed).
3. **Legitimate cover** — many applications (browsers, updaters, chat clients) legitimately use Run keys, so the entries blend in.
4. **Name camouflage** — the attacker chooses names that mimic real software ("WindowsUpdateHelper", "OneDriveSync", "ChromeAutoUpdate") to pass cursory inspection.

**Why at this lifecycle stage:** After initial access and execution, the attacker needs to survive the user's next reboot or logoff. Registry Run keys are the simplest, most reliable persistence mechanism available without elevation.

**Key triage differentiator:** The **value data** (what command the key points to) is the primary indicator. The **value name** can be anything — attackers choose legitimate-sounding names. Cross-reference the command/executable against a known software inventory: a Run key pointing to an unknown executable or a suspicious command (cmd.exe, powershell.exe, a path under Temp) is high confidence malicious.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Sysmon active.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 18:59:11 | Add Run key | COMPROMISED-HOST-01 | `reg add "HKCU\...\Run" /v "WindowsUpdateHelper" /t REG_SZ /d "cmd.exe /c echo AGC019-marker > C:\Windows\Temp\agc019.txt" /f` |
| 2 | 2026-09-15 18:59:14 | Verify | COMPROMISED-HOST-01 | `Get-ItemProperty` confirms value exists with expected data |
| 3 | 2026-09-15 18:59:27 | Cleanup | COMPROMISED-HOST-01 | `reg delete` removes the value |

**Cleanup:** Registry value deleted after evidence collection.

## SOC Perspective

### Detection

**Sysmon telemetry (COMPROMISED-HOST-01):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 18:59:11 | 13 | Registry Value Set | **RuleName:** `T1060,RunKey`. **EventType:** SetValue. **Image:** `C:\WINDOWS\system32\reg.exe` (PID 4012). **TargetObject:** `HKU\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Run\WindowsUpdateHelper`. **Details:** `cmd.exe /c echo AGC019-marker > C:\Windows\Temp\agc019.txt`. **User:** `COMPROMISED-01\Administrator`. |

**Key detection signals:**
1. **RuleName `T1060,RunKey`** — SwiftOnSecurity's Sysmon config specifically tags writes to `...\CurrentVersion\Run` and `RunOnce` keys with this rule. This pre-categorizes the event for SIEM correlation.
2. **TargetObject** matches the Run key path pattern.
3. **Details** field contains the full command that will execute on logon — this is the most important field for triage.
4. **Image = reg.exe** — the process that performed the write. In a more sophisticated attack, this would be the malware dropper or a LOLBin.

### Investigation

**Step 1 — Identify Run key modifications:**
At 18:59:11 UTC, Sysmon EID 13 with RuleName `T1060,RunKey` recorded a SetValue event. The TargetObject shows a new value `WindowsUpdateHelper` was added under `HKCU\...\CurrentVersion\Run`.

**Step 2 — Analyze the value data:**
The Details field shows `cmd.exe /c echo AGC019-marker > C:\Windows\Temp\agc019.txt`. This is suspicious because:
- **cmd.exe** is not a typical Run key target. Legitimate software points to its own executable (e.g., `"C:\Program Files\OneDrive\OneDrive.exe" /background`).
- The command writes to `C:\Windows\Temp`, a known staging location.
- No known software in this environment has a "WindowsUpdateHelper" autostart entry.

**Step 3 — Identify the writing process:**
The Image field shows `reg.exe` (PID 4012) — the built-in registry editing tool. In this simulation, it was invoked directly from the command line. In a real attack, check the parent process of reg.exe to trace back to the infection vector.

**Step 4 — Cross-reference with FP twin AGC-082:**
AGC-082 simulates a legitimate software installer adding a Run key (expected, documented change with a change ticket). The differentiator: AGC-082's value data points to a known, documented application binary; AGC-019's value data points to cmd.exe with a suspicious command. The value NAME ("WindowsUpdateHelper") is intentionally deceptive and should never be trusted as an indicator of legitimacy.

### Report

**Verdict: True Positive** — An unknown Run key value was added pointing to a suspicious command (cmd.exe writing to Temp). Not associated with any known software in the environment.

**Confidence: High** — Sysmon EID 13 with the RunKey rule tag provides direct evidence:
- The TargetObject and Details fields are unambiguous.
- The value data (cmd.exe with redirect to Temp) has no legitimate use case as a logon autostart.
- No matching entry in the environment's software inventory.

**Response recommendation:**
1. **Immediately remove the value:** `reg delete "HKCU\...\Run" /v "WindowsUpdateHelper" /f`
2. **Check all Run key locations:**
   - `HKCU\...\Run` and `HKCU\...\RunOnce`
   - `HKLM\...\Run` and `HKLM\...\RunOnce`
   - User Startup folder: `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`
   - All-users Startup folder: `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup`
3. **Investigate the reg.exe parent** — trace back to determine how the attacker gained the ability to modify the registry.
4. **Detection rule:** Alert on Sysmon EID 13 where `RuleName LIKE '%RunKey%'` and `Details` does not match a whitelist of known application paths.
5. **Baseline Run keys** across the environment to establish a known-good state for anomaly detection.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Persistence (TA0003) | T1547.001 | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | Sysmon EID 13 (RuleName: T1060,RunKey) captured `reg.exe` adding `WindowsUpdateHelper` value to `HKCU\...\Run` with data `cmd.exe /c echo AGC019-marker > C:\Windows\Temp\agc019.txt`. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
