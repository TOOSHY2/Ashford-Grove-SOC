# AGC-017 — Task-Triggered Suspicious Execution

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-017` |
| Category | `02-execution` — Execution |
| MITRE Technique | `T1053.005` Scheduled Task/Job: Scheduled Task |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Immediate — Sysmon EID 1 captures `schtasks.exe` creation/invocation; Task Scheduler EID 110 captures launch |
| Time to Triage | 02:00 (from alert to task definition review and baseline comparison) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ [AGC-016](../AGC-016-wmi-process-creation/README.md) · next [AGC-018](../AGC-018-eicar-detection-test/README.md) ▶ |
| One-line Summary | Unknown scheduled task `AGC017Test` created and triggered, configured to execute `cmd.exe` — not present in any known-good task inventory. Companion to AGC-020 (task persistence focus). |

## Attacker Perspective

### Tradecraft

**What:** The attacker creates a Windows Scheduled Task via `schtasks.exe /create` and immediately triggers it with `schtasks.exe /run`. Scheduled tasks execute commands through the Task Scheduler service (`svchost.exe -k netsvcs -p -s Schedule`), which provides:

1. **Execution indirection** — the spawned process's parent is `svchost.exe` (Task Scheduler service), not the attacker's shell.
2. **Persistence option** — the same task can be configured to fire on boot, logon, or a recurring schedule (AGC-020 focuses on this persistence angle).
3. **Privilege escalation** — tasks can be configured to run as SYSTEM or another privileged account.
4. **Remote capability** — `schtasks /create /s <remote-host>` enables remote task creation for lateral movement.

**Why at this lifecycle stage:** With a foothold established, the attacker uses scheduled tasks for immediate execution (this scenario) and for persistence (AGC-020). The focus here is the trigger event: spotting that an unknown task fired and what child process it was set to launch.

**Key triage differentiator:** Compare the task name against a known-good task inventory. A managed environment documents every legitimate scheduled task. An undocumented task name is the primary indicator, because the task-fire event looks the same whether the task is legitimate or malicious.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Sysmon active.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 18:53:09 | Create scheduled task | COMPROMISED-HOST-01 | `schtasks /create /tn "AGC017Test" /tr "cmd.exe /c echo AGC017-marker > C:\Windows\Temp\agc017.txt" /sc once /st 00:00 /f` — SUCCESS |
| 2 | 2026-09-15 18:53:09 | Trigger task | COMPROMISED-HOST-01 | `schtasks /run /tn "AGC017Test"` — SUCCESS: Attempted to run |
| 3 | 2026-09-15 18:53:09 | Task launched | COMPROMISED-HOST-01 | Task Scheduler EID 110 confirms launch. Task action configured as cmd.exe. |
| 4 | 2026-09-15 18:53:14 | Query task | COMPROMISED-HOST-01 | `schtasks /query /tn AGC017Test /v` — confirmed full task definition |

**Lab note:** The task was created with "Interactive only" logon mode (default for non-interactive `schtasks /create`). In the headless guestcontrol session, the task action (cmd.exe) did not run to completion. Task Scheduler logged EID 110 (task launched) but no EID 200/201 (action started/completed) for AGC017Test. In a real attack with an interactive session or a SYSTEM-level task, the full chain would complete.

**Cleanup:** Task deleted with `schtasks /delete /tn "AGC017Test" /f`.

## SOC Perspective

### Detection

**Sysmon telemetry (COMPROMISED-HOST-01):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 18:53:09 | 1 | Process Create | **Image:** `C:\Windows\System32\schtasks.exe` (PID 4292). **CommandLine:** `schtasks.exe /create /tn AGC017Test /tr "cmd.exe /c echo AGC017-marker > C:\Windows\Temp\agc017.txt" /sc once /st 00:00 /f`. Full task definition visible in the CommandLine. |
| 2026-09-15 18:53:09 | 1 | Process Create | **Image:** `C:\Windows\System32\schtasks.exe` (PID 5916). **CommandLine:** `schtasks.exe /run /tn AGC017Test`. Task trigger event. |

**Task Scheduler operational log:**

| Timestamp | EID | Detail |
|---|---|---|
| 2026-09-15 18:53:09 | 110 | Task Scheduler launched instance of task `\AGC017Test` for user `Administrator`. |

**Key detection signals:**
1. **Sysmon EID 1** for `schtasks.exe /create` — the CommandLine reveals the full task definition including the action to execute.
2. **Task Scheduler EID 110** — independent confirmation that the task was triggered.
3. **Sysmon EID 1** for child processes with `ParentImage` of `svchost.exe` (Schedule service) or `taskhostw.exe` — the actual execution (in interactive sessions).

### Investigation

**Step 1 — Identify the task creation event:**
At 18:53:09 UTC, Sysmon EID 1 captured `schtasks.exe /create` with the full command line showing task name `AGC017Test` and action `cmd.exe /c echo AGC017-marker > C:\Windows\Temp\agc017.txt`. The creation event alone is enough to alert on: the CommandLine carries the full task definition, so the payload is visible before it ever runs.

**Step 2 — Compare against known-good task inventory:**
The task name `AGC017Test` matches no documented or expected task in the lab. Legitimate tasks here are system defaults (for example `\Microsoft\Windows\Flighting\FeatureConfig\UsageDataReceiver`), and in an enterprise they would also be listed in the CMDB.

**Step 3 — Query the full task definition:**
`schtasks /query /tn AGC017Test /v` revealed:
- **Task To Run:** `cmd.exe /c echo AGC017-marker > C:\Windows\Temp\agc017.txt`
- **Run As User:** Administrator
- **Author:** COMPROMISED-01\Administrator
- **Schedule Type:** One Time Only
- **Created by:** Local Administrator account

A local admin account (not a domain service account or GPO) created the task, scheduled it to run once, and pointed it at cmd.exe. That reads as hands-on attacker activity, not enterprise management automation.

### Report

**Verdict: True Positive** — An undocumented task, `AGC017Test`, was created and triggered with a cmd.exe action; its name, author, and schedule match no known-good configuration.

**Confidence: High** — Multiple independent evidence sources confirm the finding:
- Sysmon EID 1 captured the full task creation CommandLine with the embedded payload.
- Task Scheduler EID 110 confirmed the task was triggered.
- The task definition query showed a one-time cmd.exe action created by a local admin — not how enterprise management creates tasks.
- No matching entry in any known-good task inventory.

**Response recommendation:**
1. **Disable and investigate the task** — `schtasks /change /tn "AGC017Test" /disable` to prevent re-execution while investigating.
2. **Determine who created it** — correlate the task creation timestamp with authentication events (Windows Security EID 4624) to identify the source session.
3. **Check for similar tasks** — `schtasks /query /fo CSV | findstr /v Microsoft` to find non-Microsoft tasks across the system.
4. **Detection rule:** Alert on Sysmon EID 1 where `Image LIKE '%\schtasks.exe'` AND `CommandLine LIKE '%/create%'` AND (`CommandLine LIKE '%cmd.exe%'` OR `CommandLine LIKE '%powershell%'` OR `CommandLine LIKE '%-enc%'`).
5. **Supplementary rule:** Alert on Task Scheduler EID 110/100 where the task name does not match an enterprise allowlist.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Execution (TA0002) | T1053.005 | Scheduled Task/Job: Scheduled Task | `schtasks /create` with cmd.exe action, `schtasks /run` trigger. Sysmon EID 1 captured full CommandLine. Task Scheduler EID 110 confirmed launch. Task not in known-good inventory. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
