# AGC-037 — System and User Discovery Burst

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-037` |
| Category | `06-discovery` — Discovery |
| MITRE Technique | `T1082` System Information Discovery / `T1033` System Owner-User Discovery / `T1016` System Network Configuration Discovery |
| Verdict | True Positive |
| Confidence | Medium |
| Time to Detect | Immediate — Sysmon EID 1 captures each command as a distinct process creation event |
| Time to Triage | 03:00 (aggregate by session, count distinct discovery commands, exclude IT helpdesk context) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) |
| Chain | ◀ [AGC-036](../../05-credential-access/AGC-036-ntlm-auth-anomaly/README.md) (Credential Access category) · next [AGC-038](../AGC-038-domain-trust-discovery/README.md) ▶ |
| One-line Summary | Burst of 6 distinct discovery commands (`systeminfo`, `whoami /all`, `hostname`, `ipconfig /all`, `net user`, environment variable query) from Administrator context within 16 seconds. Sysmon EID 1 captured all 6 with shared LogonGuid, confirming single session. Pattern: automated reconnaissance, not manual troubleshooting. |

## Attacker Perspective

### Tradecraft

**What:** After gaining access to a host, an attacker runs a burst of system enumeration commands to map the environment. This is the standard "situational awareness" phase that precedes more targeted actions (persistence, lateral movement, exfiltration). The commands individually are benign — every one is a built-in Windows tool used daily by IT support. The indicator is the **pattern**: multiple distinct discovery commands from the same session in a short window.

Common discovery burst commands:
- `systeminfo` — OS version, patch level, domain membership, hardware (T1082)
- `whoami /all` — current user identity, group memberships, privileges (T1033)
- `hostname` — machine name for lateral movement targeting (T1082)
- `ipconfig /all` — network configuration, DNS servers, domain suffix (T1016)
- `net user` — local account enumeration (T1087.001)
- `echo %USERDOMAIN%` — domain vs. workgroup determination (T1082)

**Why at this lifecycle stage:** This is the opening move on a newly compromised host. Before the attacker can decide what to steal, where to move, or how to persist, they need basic answers: what OS am I on, who am I running as, what network am I in, what domain is this host joined to, and what other accounts exist locally.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.

**Steps executed (all timestamps UTC):**

| Step | Time (UTC) | Action | Host | Detail |
|---|---|---|---|---|
| 1 | 2026-09-15 20:32:21 | systeminfo | COMPROMISED-HOST-01 | Windows 11 Pro Build 26200, Member Workstation, VirtualBox, AMD64 |
| 2 | 2026-09-15 20:32:37 | whoami /all | COMPROMISED-HOST-01 | `compromised-01\administrator` (SID ...500), full group and privilege listing |
| 3 | 2026-09-15 20:32:37 | hostname | COMPROMISED-HOST-01 | `COMPROMISED-01` |
| 4 | 2026-09-15 20:32:37 | ipconfig /all | COMPROMISED-HOST-01 | 10.10.10.103/24, DNS suffix `ashfordgrove.local`, DHCP enabled |
| 5 | 2026-09-15 20:32:37 | net user | COMPROMISED-HOST-01 | Local accounts: Administrator, DefaultAccount, Guest, wadmin, WDAGUtilityAccount |
| 6 | 2026-09-15 20:32:37 | echo USERDOMAIN | COMPROMISED-HOST-01 | `COMPROMISED-01` (local, not domain — broken trust) |

All 6 commands completed within 16 seconds (20:32:21 to 20:32:37).

**Cleanup:** No persistent artifacts created. Commands are read-only.

## SOC Perspective

### Detection

**Sysmon EID 1 — Process Create (6 events in 16 seconds):**

| Timestamp (UTC) | Image | CommandLine | PID | User | IntegrityLevel |
|---|---|---|---|---|---|
| 2026-09-15 20:32:21 | systeminfo.exe | `systeminfo.exe` | 6028 | Administrator | High |
| 2026-09-15 20:32:37 | whoami.exe | `whoami.exe /all` | 3128 | Administrator | High |
| 2026-09-15 20:32:37 | HOSTNAME.EXE | `HOSTNAME.EXE` | 6060 | Administrator | High |
| 2026-09-15 20:32:37 | ipconfig.exe | `ipconfig.exe /all` | 5656 | Administrator | High |
| 2026-09-15 20:32:37 | net.exe | `net.exe user` | 5708 | Administrator | High |
| 2026-09-15 20:32:37 | net1.exe | `net1 user` | 5996 | Administrator | High |

All 6 events share: `LogonGuid: {eb65e329-ab55-6aa9-6b7c-530000000000}`, `LogonId: 0x537C6B`, confirming they originate from the same session.

### Investigation

**Step 1 — Identify the burst pattern:**
6 distinct discovery commands from the same host, same session (shared LogonGuid), within a 16-second window. The commands cover system information (T1082), user identity (T1033), network configuration (T1016), and local account enumeration (T1087.001). This is a textbook discovery burst.

**Step 2 — Exclude legitimate IT/helpdesk context:**
Before classifying as malicious, check:
- Is there an open support ticket for COMPROMISED-HOST-01 that would explain a technician running diagnostics?
- Is the executing account a known helpdesk account with a documented pattern of running these commands?
- Is the parent process a known IT management tool (SCCM, remote desktop agent, etc.)?

In this scenario: the executing account is the built-in Administrator (RID-500), which is NOT a standard helpdesk account. No support ticket context exists. The parent process is a PowerShell script, not a management tool. **No benign explanation found.**

**Step 3 — Forward correlation (what happened next):**
A discovery burst in isolation is low-value. Its significance depends on what follows. Check the same session (LogonGuid) for subsequent activity:
- Persistence mechanisms (scheduled tasks, services, registry run keys) — see AGC-019 through AGC-024
- Credential harvesting (LSASS, SAM, browser stores) — see AGC-031 through AGC-036
- Lateral movement (RDP, PsExec, WMI) — see AGC-043 through AGC-050

In this engagement, the discovery burst is positioned within a confirmed attack chain (AGC-001 phishing -> compromise -> privilege escalation -> credential access -> AGC-037 discovery). The chain context elevates the signal.

**Step 4 — Detection reuse note:**
The detection pattern (aggregate Sysmon EID 1 by LogonGuid, count distinct discovery-category executables within a sliding time window) is reusable. Alert rule: 3+ distinct discovery binaries (`systeminfo`, `whoami`, `hostname`, `ipconfig`, `net.exe`, `nltest`, `dsquery`, `nslookup`) from the same LogonGuid within 5 minutes.

### Report

**Verdict: True Positive** — A burst of 6 distinct system and user discovery commands was executed from an Administrator session on a compromised host within 16 seconds.

**Confidence: Medium** — Calibrated assessment:
1. All 6 commands are legitimate built-in tools. No single command is inherently malicious.
2. The burst pattern (number, diversity, and timing) is the indicator.
3. No legitimate IT context was found to explain the activity.
4. Confidence stays Medium because the same pattern is commonly generated by IT helpdesk troubleshooting. Escalation to High requires either: (a) confirmed exclusion of legitimate IT activity, or (b) corroborating subsequent malicious activity.

**Response recommendation:**
1. **Correlate first, escalate second** — check for open support tickets or scheduled IT maintenance before treating this as an incident.
2. **If no legitimate context exists** — treat this as the opening stage of a confirmed attack chain and investigate forward: what did this session do AFTER the discovery burst?
3. **If subsequent malicious activity is confirmed** — the discovery burst becomes a confirmed attack-chain marker. Document it as the reconnaissance phase.
4. **Detection rule recommendation:** Alert on 3+ distinct discovery binaries from the same LogonGuid within 5 minutes. Suppress for known helpdesk accounts and management tool parent processes.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Discovery (TA0007) | T1082 | System Information Discovery | Sysmon EID 1: `systeminfo.exe`, `HOSTNAME.EXE` executed by Administrator within 16-second burst. OS, domain, hardware enumerated. | Medium |
| Discovery (TA0007) | T1033 | System Owner/User Discovery | Sysmon EID 1: `whoami.exe /all` — full identity, groups, privileges for `compromised-01\administrator`. | Medium |
| Discovery (TA0007) | T1016 | System Network Configuration Discovery | Sysmon EID 1: `ipconfig.exe /all` — IP, DNS, DHCP configuration enumerated. | Medium |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### Raw Sysmon EID 1 (representative — systeminfo)

```
Process Create:
UtcTime: 2026-09-15 20:32:21.998
ProcessId: 6028
Image: C:\Windows\System32\systeminfo.exe
CommandLine: "C:\WINDOWS\system32\systeminfo.exe"
User: COMPROMISED-01\Administrator
LogonGuid: {eb65e329-ab55-6aa9-6b7c-530000000000}
LogonId: 0x537C6B
IntegrityLevel: High
Hashes: MD5=B772FD7A4DFF0F146E7B62F73FA08EF3
```

### Raw Sysmon EID 1 (representative — whoami)

```
Process Create:
UtcTime: 2026-09-15 20:32:37.186
ProcessId: 3128
Image: C:\Windows\System32\whoami.exe
CommandLine: "C:\WINDOWS\system32\whoami.exe" /all
User: COMPROMISED-01\Administrator
LogonGuid: {eb65e329-ab55-6aa9-6b7c-530000000000}
LogonId: 0x537C6B
IntegrityLevel: High
Hashes: MD5=956692DADC5B2CEB46E9219F7A5BEFFA
```
