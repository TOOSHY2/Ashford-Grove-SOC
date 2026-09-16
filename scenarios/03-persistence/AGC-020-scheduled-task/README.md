# AGC-020 — Scheduled-Task Persistence

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

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

The attacker gets:

1. **Time-based persistence** — the payload runs on a schedule and survives reboots without a user logon, unlike a Run key.
2. **Off-hours execution** — a 03:00 schedule cuts the chance an analyst sees the process live.
3. **Legitimate cover** — Windows ships hundreds of built-in scheduled tasks; one more blends in unless the SOC keeps a task baseline.
4. **Elevation potential** — a task can be set to run as SYSTEM if the creator holds the right privileges, so persistence and escalation arrive together.

**Why at this lifecycle stage:** With a Run key already in place (AGC-019), the attacker adds a second persistence mechanism. A scheduled task survives a Run key cleanup and fires whether or not the user logs on interactively.

**Key triage differentiator vs AGC-017:** AGC-017 covered the *execution* phase: create a task and run it at once. AGC-020 covers the *persistence* phase: create a task with a future, recurring trigger. Detection focus shifts from "task was run" (EID 110) to "task was registered" (EID 106 / Sysmon EID 1 of schtasks.exe /create).

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

**Security EID 4698:** Not generated. The default audit policy on this Windows 11 system does not log task creation events (Object Access > Other Object Access Events is not enabled). That is a detection gap: with the subcategory enabled, EID 4698 carries the full task XML definition, the richest single source for task creation.

**Key detection signals:**
1. **Sysmon EID 1 CommandLine** — the `/create` verb with `/tn`, `/tr`, and `/sc` flags exposes the task name, action, and schedule in one line.
2. **Task action analysis** — the `/tr` parameter shows `cmd.exe /c echo ... > C:\Windows\Temp\...`; no legitimate scheduled task writes echo output to Temp.
3. **Off-hours schedule** — `/st 03:00` daily puts execution outside working hours, when fewer eyes are on the console.
4. **Task Scheduler EID 106** confirms registration from the OS side and corroborates the Sysmon process telemetry.

### Investigation

**Step 1 — Identify new task creation:**
At 19:04:02 UTC, Sysmon EID 1 recorded `schtasks.exe` executing with the `/create` verb. The CommandLine gives the task name (`AGC020Test`), action (`cmd.exe /c echo AGC-020 test > C:\Windows\Temp\agc020.txt`), and schedule (`daily /st 03:00`). Task Scheduler EID 106 corroborates the registration at the same timestamp.

**Step 2 — Analyze the task action:**
The task action is `cmd.exe /c echo AGC-020 test > C:\Windows\Temp\agc020.txt`. What makes it suspicious:
- **cmd.exe** is an unusual task action for legitimate software. Real applications schedule their own executables.
- Writing to `C:\Windows\Temp` is a common staging pattern.
- The task name `AGC020Test` matches no documented IT maintenance schedule.

**Step 3 — Analyze the principal and schedule:**
`COMPROMISED-01\Administrator` created the task, and it runs as `Administrator`. Its logon mode is "Interactive only", so it fires only while Administrator is logged in. That limits the persistence but still gives recurring execution. A more careful attacker would set the task to run whether the user is logged on or not (`/ru SYSTEM`), which would be a stronger indicator.

**Step 4 — Cross-reference with AGC-017:**
AGC-017 was the *execution* side of scheduled tasks: create, then fire at once with `/run`. AGC-020 is the *persistence* side: create with a future daily trigger. Both use `schtasks.exe` and leave identical Sysmon EID 1 artifacts for the `/create` verb. The difference is where the analyst looks: AGC-017 keyed on Task Scheduler EID 110 (task launched); AGC-020 keys on EID 106 (task registered) plus the schedule and action.

**Step 5 — Detection gap identified:**
Security EID 4698 (scheduled task created) never fired because the "Audit Other Object Access Events" subcategory is off. Microsoft's ATT&CK-aligned guidance names it the primary audit source for scheduled-task persistence. Enabled, it would deliver the complete task XML (Command, Arguments, Triggers, Principal, Settings) in a single event.

### Report

**Verdict: True Positive** — An unknown scheduled task was created with cmd.exe writing to Temp on a daily off-hours schedule, with no matching IT maintenance or software update process.

**Confidence: High** — Four sources corroborate:
- Sysmon EID 1 with full CommandLine showing the `/create` verb, task name, action, and schedule.
- Task Scheduler EID 106 confirming registration by `COMPROMISED-01\Administrator`.
- The task action (`cmd.exe` writing to Temp) has no legitimate use as a scheduled task.
- The task name (`AGC020Test`) is not in the lab's known task inventory.

**Response recommendation:**
1. **Immediately delete the task:** `schtasks /delete /tn "AGC020Test" /f`
2. **Audit all scheduled tasks** on the affected host: `schtasks /query /fo CSV /v > task_audit.csv` and compare against a known-good baseline.
3. **Enable audit policy:** Configure "Audit Other Object Access Events" (Success) to capture Security EID 4698 for future task creation monitoring.
4. **Check for related persistence:** The attacker may have established multiple persistence mechanisms (see AGC-019 for registry Run keys on the same host).
5. **Detection rule:** Alert on Sysmon EID 1 where `Image LIKE '%schtasks.exe%'` and `CommandLine CONTAINS '/create'` and the task action does not match an allowlist of known task executables.
6. **Investigate the creating process chain:** Trace the `powershell.exe` parent back to how the attacker got a shell on the host.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Persistence (TA0003) | T1053.005 | Scheduled Task/Job: Scheduled Task | Sysmon EID 1 captured `schtasks.exe /create /tn AGC020Test /tr "cmd.exe /c echo AGC-020 test > C:\Windows\Temp\agc020.txt" /sc daily /st 03:00`. Task Scheduler EID 106 confirmed registration by `COMPROMISED-01\Administrator`. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
