# AGC-027 — Service Misconfiguration (Unquoted Service Path)

> **Disclosure:** Executed & documented by Claude Code under direction and review by Ali.

## Card

| Field | Value |
|---|---|
| ID | `AGC-027` |
| Category | `04-privilege-escalation` — Privilege Escalation |
| MITRE Technique | `T1574.009` Hijack Execution Flow: Path Interception by Unquoted Path |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Immediate — Sysmon EID 1 shows Image path mismatch vs configured binPath; EID 11 flags .exe file creation in Program Files |
| Time to Triage | 02:00 (requires cross-referencing Sysmon EID 1 Image with `sc qc` binPath) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ [AGC-026](../AGC-026-uac-bypass-behavior/README.md) · next [AGC-028](../AGC-028-dll-search-order-hijack/README.md) ▶ |
| One-line Summary | Unquoted service path in AGC027VulnSvc allowed hijack binary at `C:\Program Files\AGC027.exe` to execute as NT AUTHORITY\SYSTEM instead of the intended service.exe. Sysmon EID 1 confirmed Image/binPath mismatch; EID 11 flagged the .exe placement. |

## Attacker Perspective

### Tradecraft

**What:** The attacker targets a Windows service whose `binPath` contains a space and is not wrapped in quotes. When the Service Control Manager starts such a service, Windows resolves the unquoted path ambiguously. For `C:\Program Files\AGC027 Test\service.exe`, Windows tries in order:
1. `C:\Program.exe`
2. `C:\Program Files\AGC027.exe` (the hijack point)
3. `C:\Program Files\AGC027 Test\service.exe` (the intended binary)

Drop a binary at the earlier resolution point (step 2) and the attacker's code runs in place of the real service binary, under the service's configured account, usually `LocalSystem`.

This provides:
1. **SYSTEM-level execution** — a LocalSystem service runs at the highest Windows privilege level, above any administrator account.
2. **Persistence through restarts** — the hijack binary runs on every service start: boot, manual restart, crash recovery.
3. **Stealth** — `sc qc` still shows the service configured normally. Only comparing the running Image path against the configured binPath exposes the hijack.
4. **Common vulnerability** — unquoted service paths are among the most frequently found Windows privilege-escalation vectors in penetration testing.

**Why at this lifecycle stage:** Once the attacker can write to `C:\Program Files\` — which needs admin rights or an ACL misconfiguration — planting the hijack binary buys SYSTEM execution on every service start. It is privilege escalation to SYSTEM and persistence across reboots at once.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 19:34:36 | Create vulnerable service | COMPROMISED-HOST-01 | `sc.exe create AGC027VulnSvc binPath= "C:\Program Files\AGC027 Test\service.exe" start= demand` — unquoted path with space |
| 2 | 2026-09-15 19:34:38 | Verify unquoted path | COMPROMISED-HOST-01 | `sc.exe qc AGC027VulnSvc` confirmed BINARY_PATH_NAME: `C:\Program Files\AGC027 Test\service.exe` (no quotes) |
| 3 | 2026-09-15 19:34:38 | Place hijack binary | COMPROMISED-HOST-01 | Copied `cmd.exe` as `C:\Program Files\AGC027.exe` (path resolution hijack point) |
| 4 | 2026-09-15 19:34:40 | Start service | COMPROMISED-HOST-01 | `sc.exe start AGC027VulnSvc` — SCM resolved unquoted path to `C:\Program Files\AGC027.exe` (our hijack binary) instead of `C:\Program Files\AGC027 Test\service.exe` |
| 5 | 2026-09-15 19:35:10 | Cleanup | COMPROMISED-HOST-01 | Service deleted; hijack binary removed |

**Cleanup:** Service `AGC027VulnSvc` deleted and `C:\Program Files\AGC027.exe` removed.

## SOC Perspective

### Detection

**Sysmon EID 1 — Hijacked process execution (the critical evidence):**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 19:34:40 | 1 | Process Create | **Image:** `C:\Program Files\AGC027.exe` (PID 572). **OriginalFileName:** `Cmd.Exe`. **CommandLine:** `"C:\Program Files\AGC027" Test\service.exe`. **User:** `NT AUTHORITY\SYSTEM`. **IntegrityLevel:** System. **ParentImage:** `C:\Windows\System32\services.exe` (PID 804). |

**The mismatch is the detection signature:**
- **Configured binPath** (from `sc qc`): `C:\Program Files\AGC027 Test\service.exe`
- **Actual Image** (from Sysmon EID 1): `C:\Program Files\AGC027.exe`
- **CommandLine shows the split**: `"C:\Program Files\AGC027" Test\service.exe` — Windows resolved the first path segment and passed the remainder as arguments.

**Supporting evidence:**

| Timestamp (UTC) | EID | Event | Detail |
|---|---|---|---|
| 2026-09-15 19:34:38 | 11 (Sysmon) | File Create | **RuleName:** `EXE`. **TargetFilename:** `C:\Program Files\AGC027.exe`. **Image:** `powershell.exe` (PID 5860). Executable file created in Program Files. |
| 2026-09-15 19:34:36 | 7045 (System) | Service Installed | **Service Name:** AGC027VulnSvc. **Service File Name:** `C:\Program Files\AGC027 Test\service.exe`. **Service Account:** LocalSystem. |
| 2026-09-15 19:34:36 | 1 (Sysmon) | Process Create | **Image:** `sc.exe` (PID 1064). **CommandLine:** `sc.exe create AGC027VulnSvc binPath= "C:\Program Files\AGC027 Test\service.exe" start= demand`. Service creation by Administrator. |
| 2026-09-15 19:34:40 | 1 (Sysmon) | Process Create | **Image:** `sc.exe` (PID 4164). **CommandLine:** `sc.exe start AGC027VulnSvc`. Service start by Administrator. |

### Investigation

**Step 1 — Identify the Image/binPath mismatch:**
Sysmon EID 1 shows `C:\Program Files\AGC027.exe` executing as `NT AUTHORITY\SYSTEM` with `services.exe` as the parent. `sc qc AGC027VulnSvc` lists the configured binPath as `C:\Program Files\AGC027 Test\service.exe`. The Image path does NOT match the binPath — the definitive hijack indicator.

**Step 2 — Confirm unquoted path as root cause:**
The binPath `C:\Program Files\AGC027 Test\service.exe` holds a space between "AGC027" and "Test" and carries no quotes. Windows tried `C:\Program Files\AGC027.exe` before the intended path and hit the hijack binary.

**Step 3 — Trace the hijack binary placement:**
Sysmon EID 11 (File Create, RuleName: EXE) at 19:34:38 UTC shows `C:\Program Files\AGC027.exe` written by `powershell.exe` (PID 5860) as Administrator. The OriginalFileName in the hijacked process's EID 1 reads `Cmd.Exe`: a renamed copy of the command processor, not a service executable.

**Step 4 — Assess the execution context:**
The hijacked process ran as `NT AUTHORITY\SYSTEM` at IntegrityLevel System, the highest level on the host, above Administrator. Whatever the hijack binary carries has unrestricted access.

**Step 5 — Fleet-wide audit:**
Hunt this class proactively by auditing every service for unquoted paths with spaces:
```cmd
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v """
```
Any service with a space in the path and no surrounding quotes is a candidate.

### Report

**Verdict: True Positive** — The attacker exploited an unquoted service path to run a hijack binary as NT AUTHORITY\SYSTEM. The Sysmon EID 1 Image path does not match the configured binPath, confirming path interception.

**Confidence: High** — Confirming it takes two independent sources — Sysmon EID 1 Image and `sc qc` binPath — but once correlated the mismatch is conclusive:
- Sysmon EID 1: Image `C:\Program Files\AGC027.exe`, OriginalFileName `Cmd.Exe`, Parent `services.exe`, User `NT AUTHORITY\SYSTEM`.
- Service config: binPath `C:\Program Files\AGC027 Test\service.exe` (unquoted, with space).
- Sysmon EID 11: .exe file creation at the hijack path flagged by SwiftOnSecurity config (RuleName: EXE).
- System EID 7045: service installed with the vulnerable path.

**Response recommendation:**
1. **Stop the service** immediately and delete the hijack binary.
2. **Fix the binPath** — re-register the service with properly quoted path: `sc config AGC027VulnSvc binPath= "\"C:\Program Files\AGC027 Test\service.exe\""`.
3. **Audit all services** fleet-wide for unquoted paths with spaces — this is a class of vulnerability, not one instance.
4. **Detection rule:** Alert when Sysmon EID 1 shows a process with ParentImage `services.exe` whose Image path matches no registered service's binPath. This catches every service-hijack variant.
5. **Sysmon EID 11 rule:** Alert on .exe creation in `C:\Program Files\` or `C:\Program Files (x86)\` where OriginalFileName does not match the filename on disk.
6. **Investigate how the attacker gained write access** to `C:\Program Files\` — that needs admin rights or misconfigured directory ACLs.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Privilege Escalation (TA0004) | T1574.009 | Hijack Execution Flow: Path Interception by Unquoted Path | Sysmon EID 1: `C:\Program Files\AGC027.exe` (OriginalFileName: Cmd.Exe) executed by `services.exe` as SYSTEM. Configured binPath: `C:\Program Files\AGC027 Test\service.exe` (unquoted). Image/binPath mismatch confirms path interception. | High |
| Persistence (TA0003) | T1574.009 | Hijack Execution Flow: Path Interception by Unquoted Path | Same evidence. Service hijack persists across reboots — the hijack binary runs every time the service starts. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
