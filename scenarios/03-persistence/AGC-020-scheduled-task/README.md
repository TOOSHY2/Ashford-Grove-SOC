# AGC-020 — Scheduled-Task Persistence

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-020` |
| Category | `03-persistence` — Persistence |
| MITRE Technique | `T1053.005` Scheduled Task/Job: Scheduled Task |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Immediate — Sysmon EID 1 captures schtasks.exe /create with full CommandLine; Task Scheduler EID 106 confirms registration |
| Time to Triage | 01:30 (from alert to task-action and principal analysis) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ [AGC-019](../AGC-019-registry-run-key/README.md) · next [AGC-021](../AGC-021-new-autostart-service/README.md) ▶ |
| One-line Summary | Unknown scheduled task `AGC020Test` created to execute `cmd.exe` daily at 03:00 — not associated with any known IT maintenance or software update schedule. Execution companion: AGC-017. |

## Attacker Perspective

### Tradecraft

**What:** The attacker creates a Windows scheduled task using `schtasks.exe /create`. The task specifies:
- **Action:** a command to execute (`cmd.exe /c echo AGC-020 test > C:\Windows\Temp\agc020.txt`)
- **Trigger:** daily execution at 03:00 (off-hours, when monitoring is lightest)
- **Principal:** runs as the creating user (Administrator in this case)

This provides:

1. **Time-based persistence** — the payload executes on a schedule, surviving reboots without requiring user logon (unlike Run keys which need interactive logon).
2. **Off-hours execution** — scheduling at 03:00 reduces the chance of an analyst noticing the process in real-time.
3. **Legitimate cover** — Windows has hundreds of built-in scheduled tasks; one more blends in unless the SOC maintains a task baseline.
4. **Elevation potential** — tasks can be configured to run as SYSTEM even when created by a standard user (with appropriate privileges), providing privilege escalation alongside persistence.

**Why at this lifecycle stage:** After establishing initial persistence via registry Run keys (AGC-019), the attacker adds a second persistence mechanism. Scheduled tasks survive even if Run keys are cleaned, and they execute regardless of whether the user logs on interactively.

**Key triage differentiator vs AGC-017:** AGC-017 demonstrated the *execution* phase (creating and immediately running a task). AGC-020 demonstrates the *persistence* phase (creating a task with a future trigger for recurring execution). The detection focus shifts from "task was run" (EID 110) to "task was registered" (EID 106 / Sysmon EID 1 of schtasks.exe /create).

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Sysmon active.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 19:04:02 | Create task | COMPROMISED-HOST-01 | `schtasks /create /tn "AGC020Test" /tr "cmd.exe /c echo AGC-020 test > C:\Windows\Temp\agc020.txt" /sc daily /st 03:00 /f` |
| 2 | 2026-09-15 19:04:05 | Verify | COMPROMISED-HOST-01 | `schtasks /query /tn AGC020Test /v /fo LIST` — confirmed task exists, daily at 03:00, Author: COMPROMISED-01\Administrator |
| 3 | 2026-09-15 19:05:32 | Cleanup | COMPROMISED-HOST-01 | `schtasks /delete /tn "AGC020Test" /f` |

**Cleanup:** Scheduled task deleted after evidence collection.

## SOC Perspective

### Detection

**Sysmon telemetry (COMPROMISED-HOST-01):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 19:04:02 | 1 | Process Create | **Image:** `C:\Windows\System32\schtasks.exe` (PID 3744). **CommandLine:** `schtasks.exe /create /tn AGC020Test /tr "cmd.exe /c echo AGC-020 test > C:\Windows\Temp\agc020.txt" /sc daily /st 03:00 /f`. **User:** `COMPROMISED-01\Administrator`. **ParentImage:** `powershell.exe`. **IntegrityLevel:** High. |
| 2026-09-15 19:04:05 | 1 | Process Create | **Image:** `C:\Windows\System32\schtasks.exe` (PID 3600). **CommandLine:** `schtasks.exe /query /tn AGC020Test /v /fo LIST`. Verification query (informational). |

**Task Scheduler Operational log:**

| Timestamp | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 19:04:02 | 106 | Task Registered | User `COMPROMISED-01\Administrator` registered Task Scheduler task `\AGC020Test`. |
| 2026-09-15 19:04:02 | 140 | Task Updated | User `COMPROMISED-01\Administrator` updated Task Scheduler task `\AGC020Test`. |

**Security EID 4698:** Not generated. The default audit policy on this Windows 11 system does not log task creation events (Object Access > Other Object Access Events is not enabled). This is a detection gap — enabling this audit subcategory would provide the richest evidence source for scheduled task creation, including the full task XML definition.

**Key detection signals:**
1. **Sysmon EID 1 CommandLine** — the `/create` verb with `/tn`, `/tr`, and `/sc` flags directly exposes the task name, action, and schedule.
2. **Task action analysis** — the `/tr` parameter shows `cmd.exe /c echo ... > C:\Windows\Temp\...` which is suspicious: no legitimate scheduled task writes echo output to Temp.
3. **Off-hours schedule** — `/st 03:00` daily execution is a classic attacker pattern to avoid observation.
4. **Task Scheduler EID 106** confirms registration from the OS perspective, corroborating the Sysmon process telemetry.

### Investigation

**Step 1 — Identify new task creation:**
At 19:04:02 UTC, Sysmon EID 1 recorded `schtasks.exe` executing with the `/create` verb. The full CommandLine reveals the task name (`AGC020Test`), action (`cmd.exe /c echo AGC-020 test > C:\Windows\Temp\agc020.txt`), and schedule (`daily /st 03:00`). Task Scheduler EID 106 corroborates the registration at the same timestamp.

**Step 2 — Analyze the task action:**
The task action is `cmd.exe /c echo AGC-020 test > C:\Windows\Temp\agc020.txt`. This is suspicious because:
- **cmd.exe** as a scheduled task action is unusual for legitimate software. Real applications schedule their own executables.
- Writing to `C:\Windows\Temp` is a known staging pattern.
- The task name `AGC020Test` does not match any documented IT maintenance schedule.

**Step 3 — Analyze the principal and schedule:**
The task was created by `COMPROMISED-01\Administrator` and runs as `Administrator`. The task runs in "Interactive only" logon mode, meaning it executes only when Administrator is logged in. While this limits persistence effectiveness, it still provides recurring execution capability. A more sophisticated attacker would configure the task to run whether the user is logged on or not (`/ru SYSTEM`), which would be a stronger indicator.

**Step 4 — Cross-reference with AGC-017:**
AGC-017 demonstrated the *execution* side of scheduled tasks (creating and immediately triggering with `/run`). AGC-020 demonstrates the *persistence* side (creating with a future daily trigger). Both use `schtasks.exe` and generate identical Sysmon EID 1 artifacts for the `/create` verb. The difference is investigative focus: AGC-017 looked for Task Scheduler EID 110 (task launched); AGC-020 looks for EID 106 (task registered) and the schedule/action analysis.

**Step 5 — Detection gap identified:**
Security EID 4698 (scheduled task created) was not generated because the "Audit Other Object Access Events" subcategory is not enabled. This is the primary recommended audit source for scheduled task persistence detection per Microsoft's ATT&CK-aligned guidance. Enabling it would provide the complete task XML definition (Command, Arguments, Triggers, Principal, Settings) in a single event.

### Report

**Verdict: True Positive** — An unknown scheduled task was created with a suspicious action (cmd.exe writing to Temp) on a daily off-hours schedule. Not associated with any documented IT maintenance or software update process.

**Confidence: High** — Multiple corroborating evidence sources:
- Sysmon EID 1 with full CommandLine showing `/create` verb, task name, action, and schedule.
- Task Scheduler EID 106 confirming registration by `COMPROMISED-01\Administrator`.
- Task action (`cmd.exe` writing to Temp) has no legitimate use case as a scheduled task.
- Task name (`AGC020Test`) not in the environment's known task inventory.

**Response recommendation:**
1. **Immediately delete the task:** `schtasks /delete /tn "AGC020Test" /f`
2. **Audit all scheduled tasks** on the affected host: `schtasks /query /fo CSV /v > task_audit.csv` and compare against a known-good baseline.
3. **Enable audit policy:** Configure "Audit Other Object Access Events" (Success) to capture Security EID 4698 for future task creation monitoring.
4. **Check for related persistence:** The attacker may have established multiple persistence mechanisms (see AGC-019 for registry Run keys on the same host).
5. **Detection rule:** Alert on Sysmon EID 1 where `Image LIKE '%schtasks.exe%'` and `CommandLine CONTAINS '/create'` and the task action does not match a whitelist of known task executables.
6. **Investigate the creating process chain:** Trace `powershell.exe` parent to determine how the attacker obtained the ability to create tasks.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Persistence (TA0003) | T1053.005 | Scheduled Task/Job: Scheduled Task | Sysmon EID 1 captured `schtasks.exe /create /tn AGC020Test /tr "cmd.exe /c echo AGC-020 test > C:\Windows\Temp\agc020.txt" /sc daily /st 03:00`. Task Scheduler EID 106 confirmed registration by `COMPROMISED-01\Administrator`. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
