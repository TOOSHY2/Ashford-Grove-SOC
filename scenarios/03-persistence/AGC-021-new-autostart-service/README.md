# AGC-021 -- New Auto-Start Service Persistence

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-021` |
| Category | `03-persistence` -- Persistence |
| MITRE Technique | `T1543.003` Create or Modify System Process: Windows Service |
| Verdict | True Positive |
| Confidence | Critical |
| Time to Detect | Immediate -- System EID 7045 logs service installation with binary path and start type |
| Time to Triage | 01:00 (from alert to binary path and service account analysis) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | < AGC-020 . next AGC-022 > |
| One-line Summary | Unknown service `AGC021Svc` installed with auto-start and LocalSystem privileges, binary path points to `cmd.exe` -- no legitimate software justification. |

## Attacker Perspective

### Tradecraft

**What:** The attacker uses `sc.exe create` to install a new Windows service with `start= auto` (automatic start on boot). The service is configured to:
- **Run as LocalSystem** (default for `sc create`) -- the highest-privilege account on the machine.
- **Execute cmd.exe** with a command to write a marker file -- in a real attack, this would be a reverse shell, beacon, or malware loader.
- **Start automatically** on every boot -- the service manager restarts it even after crashes.

This provides:

1. **SYSTEM-level persistence** -- the service runs as `NT AUTHORITY\SYSTEM`, giving the attacker the highest possible local privileges automatically.
2. **Boot-time execution** -- auto-start services launch before any user logs on, before most security tools fully initialize.
3. **Service restart resilience** -- the service control manager can be configured to restart failed services automatically (recovery options).
4. **Privilege escalation** -- if the attacker initially had standard user access and compromised a local admin account, installing a SYSTEM service elevates their persistent access beyond even the admin account.

**Why at this lifecycle stage:** After simpler persistence via Run keys (AGC-019) and scheduled tasks (AGC-020), the attacker escalates to service-based persistence for SYSTEM-level access. This is the most privileged form of persistence available without kernel-level modifications.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Sysmon active, Administrator context.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 19:08:17 | Create service | COMPROMISED-HOST-01 | `sc.exe create AGC021Svc binPath= "cmd.exe /c echo AGC-021 test > C:\Windows\Temp\agc021.txt" start= auto` -- SUCCESS |
| 2 | 2026-09-15 19:08:20 | Start service | COMPROMISED-HOST-01 | `sc.exe start AGC021Svc` -- cmd.exe spawned as SYSTEM (PID 5692) but service returned error 1053 (cmd.exe is not a proper service binary) |
| 3 | 2026-09-15 19:08:23 | Verify | COMPROMISED-HOST-01 | `sc.exe qc AGC021Svc` -- confirmed AUTO_START, LocalSystem, binary path |
| 4 | 2026-09-15 19:08:51 | Cleanup | COMPROMISED-HOST-01 | `sc.exe delete AGC021Svc` |

**Cleanup:** Service stopped and deleted after evidence collection.

## SOC Perspective

### Detection

**System Event Log (COMPROMISED-HOST-01):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 19:08:17 | 7045 | Service Installed | **Service Name:** `AGC021Svc`. **Service File Name:** `cmd.exe /c echo AGC-021 test > C:\Windows\Temp\agc021.txt`. **Service Type:** user mode service. **Service Start Type:** auto start. **Service Account:** `LocalSystem`. |

**Sysmon telemetry (COMPROMISED-HOST-01):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 19:08:17 | 1 | Process Create | **Image:** `C:\Windows\System32\sc.exe` (PID 4436). **CommandLine:** `sc.exe create AGC021Svc binPath= "cmd.exe /c echo AGC-021 test > C:\Windows\Temp\agc021.txt" start= auto`. **User:** `COMPROMISED-01\Administrator`. **IntegrityLevel:** High. |
| 2026-09-15 19:08:20 | 1 | Process Create | **Image:** `C:\Windows\System32\cmd.exe` (PID 5692). **CommandLine:** `cmd.exe /c echo AGC-021 test > C:\Windows\Temp\agc021.txt`. **User:** `NT AUTHORITY\SYSTEM`. **IntegrityLevel:** System. **ParentImage:** `services.exe` (PID 804). |

**Key detection signals:**
1. **System EID 7045** is the primary detection source for new service installations. It contains the service name, binary path, start type, and service account in a single event.
2. **Binary path analysis** -- `cmd.exe /c echo ...` as a service binary is immediately suspicious. Legitimate services use dedicated executables in `C:\Program Files\` or `System32`.
3. **Service Account: LocalSystem** -- combined with an unknown service name and non-standard binary, this is the strongest persistence indicator.
4. **Sysmon EID 1** shows `cmd.exe` spawning as `NT AUTHORITY\SYSTEM` with `services.exe` as parent -- confirms the service actually executed with SYSTEM privileges.

### Investigation

**Step 1 -- Identify new service installation:**
At 19:08:17 UTC, System EID 7045 recorded the installation of a new service `AGC021Svc`. The Service File Name field reveals `cmd.exe /c echo AGC-021 test > C:\Windows\Temp\agc021.txt` -- immediately suspicious.

**Step 2 -- Analyze the binary path:**
The service binary path points to `cmd.exe` with a command-line argument, not a dedicated service executable. This is a hallmark of malicious service persistence:
- Legitimate services use purpose-built .exe or .dll files, typically in `C:\Program Files\` or `C:\Windows\System32\`.
- The command writes to `C:\Windows\Temp`, a known attacker staging location.
- No legitimate software in this environment has a service named `AGC021Svc`.

**Step 3 -- Analyze the service account and start type:**
The service runs as `LocalSystem` (the default for `sc create`) with `AUTO_START`. This means:
- It executes with the highest local privileges -- SYSTEM is more powerful than any local administrator.
- It starts automatically on every boot, before user logon.
- Sysmon confirmed the actual execution context: `cmd.exe` ran as `NT AUTHORITY\SYSTEM` spawned by `services.exe`.

**Step 4 -- Assess the persistence chain:**
This is the third persistence mechanism detected on COMPROMISED-HOST-01:
1. AGC-019: Registry Run key (user-level, logon-dependent)
2. AGC-020: Scheduled task (user-level, time-triggered)
3. AGC-021: Windows service (SYSTEM-level, boot-triggered)

The escalation from user-level to SYSTEM-level persistence indicates an attacker with local admin access establishing the most resilient foothold possible.

### Report

**Verdict: True Positive** -- An unknown service was installed with a suspicious binary path (cmd.exe), auto-start configuration, and LocalSystem privileges. No legitimate software justification exists.

**Confidence: Critical** -- The combination of indicators leaves no room for legitimate explanation:
- System EID 7045 with `cmd.exe` as the Service File Name.
- LocalSystem service account with AUTO_START.
- Sysmon confirmed SYSTEM-level execution (cmd.exe spawned by services.exe as NT AUTHORITY\SYSTEM).
- Service name `AGC021Svc` not in any known software inventory.

**Response recommendation:**
1. **Immediately stop and delete the service:** `sc stop AGC021Svc && sc delete AGC021Svc`
2. **Treat as confirmed compromise** -- the attacker has/had local admin access and established SYSTEM-level persistence.
3. **Audit all services** on the host: `sc query type= all state= all` and compare against a known-good baseline.
4. **Investigate lateral movement** -- check if the attacker used SYSTEM privileges to move to other hosts.
5. **Check other persistence mechanisms** -- the attacker likely established multiple persistence methods (Run keys, scheduled tasks, services).
6. **Detection rule:** Alert on System EID 7045 where the Service File Name does not match a whitelist of known application paths and the Service Account is `LocalSystem`.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Persistence (TA0003) | T1543.003 | Create or Modify System Process: Windows Service | System EID 7045: service `AGC021Svc` installed with binPath `cmd.exe /c echo AGC-021 test > C:\Windows\Temp\agc021.txt`, auto-start, LocalSystem. Sysmon EID 1: cmd.exe spawned as `NT AUTHORITY\SYSTEM` by `services.exe`. | Critical |

## Evidence

Screenshots: not applicable (text-based evidence collection only).
