# AGC-027 — Service Misconfiguration (Unquoted Service Path)

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

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

**What:** The attacker exploits a Windows service whose `binPath` contains spaces but is not enclosed in quotes. When the Service Control Manager (SCM) starts such a service, Windows path-resolution logic interprets the unquoted path ambiguously. For a path like `C:\Program Files\AGC027 Test\service.exe`, Windows tries these paths in order:
1. `C:\Program.exe`
2. `C:\Program Files\AGC027.exe` (the hijack point)
3. `C:\Program Files\AGC027 Test\service.exe` (the intended binary)

By placing a malicious binary at an earlier resolution point (step 2), the attacker's code runs instead of the legitimate service binary — and it runs with the service's configured account, typically `LocalSystem`.

This provides:
1. **SYSTEM-level execution** — services configured with LocalSystem run at the highest Windows privilege level, above any administrator account.
2. **Persistence through service restarts** — the hijack binary runs every time the service starts (boot, manual restart, crash recovery).
3. **Stealth** — the service still appears configured normally in `sc qc` output. Only comparing the actual execution Image path against the configured binPath reveals the hijack.
4. **Common vulnerability** — unquoted service paths are one of the most frequently found Windows privilege escalation vectors in penetration testing.

**Why at this lifecycle stage:** After gaining write access to `C:\Program Files\` (which requires admin or specific ACL misconfiguration), the attacker plants a hijack binary to ensure SYSTEM-level execution on every service start. This is both privilege escalation (to SYSTEM) and persistence (survives reboots).

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
Sysmon EID 1 shows `C:\Program Files\AGC027.exe` executing as `NT AUTHORITY\SYSTEM` with `services.exe` as the parent. The `sc qc AGC027VulnSvc` output shows the configured binPath as `C:\Program Files\AGC027 Test\service.exe`. The Image path does NOT match the binPath — this is the definitive hijack indicator.

**Step 2 — Confirm unquoted path as root cause:**
The configured binPath `C:\Program Files\AGC027 Test\service.exe` contains a space (between "AGC027" and "Test") and is NOT enclosed in quotes. Windows path-resolution logic tried `C:\Program Files\AGC027.exe` before the intended path and found the hijack binary.

**Step 3 — Trace the hijack binary placement:**
Sysmon EID 11 (File Create, RuleName: EXE) at 19:34:38 UTC shows `C:\Program Files\AGC027.exe` was created by `powershell.exe` (PID 5860) running as Administrator. The OriginalFileName field in the EID 1 for the hijacked process reveals it is actually `Cmd.Exe` — a renamed copy of the Windows command processor, confirming the binary is not a legitimate service executable.

**Step 4 — Assess the execution context:**
The hijacked process ran as `NT AUTHORITY\SYSTEM` with IntegrityLevel: System. This is the highest privilege level on a Windows system — above Administrator. Any code in the hijack binary has unrestricted access to the system.

**Step 5 — Fleet-wide audit:**
This class of vulnerability can be detected proactively by auditing all services for unquoted paths with spaces:
```cmd
wmic service get name,displayname,pathname,startmode | findstr /i "auto" | findstr /i /v """
```
Any service with spaces in the path and no surrounding quotes is potentially vulnerable.

### Report

**Verdict: True Positive** — An unquoted service path was exploited to execute a hijack binary as NT AUTHORITY\SYSTEM. The Image path in Sysmon EID 1 does not match the configured binPath, confirming path interception.

**Confidence: High** — The evidence requires cross-referencing two independent sources (Sysmon EID 1 Image vs `sc qc` binPath), but once correlated, the mismatch is conclusive:
- Sysmon EID 1: Image `C:\Program Files\AGC027.exe`, OriginalFileName `Cmd.Exe`, Parent `services.exe`, User `NT AUTHORITY\SYSTEM`.
- Service config: binPath `C:\Program Files\AGC027 Test\service.exe` (unquoted, with space).
- Sysmon EID 11: .exe file creation at the hijack path flagged by SwiftOnSecurity config (RuleName: EXE).
- System EID 7045: service installed with the vulnerable path.

**Response recommendation:**
1. **Stop the service** immediately and delete the hijack binary.
2. **Fix the binPath** — re-register the service with properly quoted path: `sc config AGC027VulnSvc binPath= "\"C:\Program Files\AGC027 Test\service.exe\""`.
3. **Audit all services** fleet-wide for unquoted paths with spaces. This is a class of vulnerability, not a single instance.
4. **Detection rule:** Alert when Sysmon EID 1 shows a process with ParentImage `services.exe` where the Image path does not match any registered service's binPath. This catches all service hijack variants.
5. **Sysmon EID 11 rule:** Alert on .exe file creation in `C:\Program Files\` or `C:\Program Files (x86)\` where the OriginalFileName does not match the filename on disk.
6. **Investigate how the attacker gained write access** to `C:\Program Files\` — this requires admin or misconfigured directory ACLs.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Privilege Escalation (TA0004) | T1574.009 | Hijack Execution Flow: Path Interception by Unquoted Path | Sysmon EID 1: `C:\Program Files\AGC027.exe` (OriginalFileName: Cmd.Exe) executed by `services.exe` as SYSTEM. Configured binPath: `C:\Program Files\AGC027 Test\service.exe` (unquoted). Image/binPath mismatch confirms path interception. | High |
| Persistence (TA0003) | T1574.009 | Hijack Execution Flow: Path Interception by Unquoted Path | Same evidence. Service hijack persists across reboots — the hijack binary runs every time the service starts. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.
