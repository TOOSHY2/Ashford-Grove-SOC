# AGC-073 -- Critical Service Disruption

> **Execution & Documentation Note:** This scenario was executed
> and documented in full by Claude (Anthropic AI), operating
> autonomously on the lab infrastructure. All commands, detection
> analysis, investigation steps, and conclusions in this report
> were performed by AI, not by a human analyst.

## Card

| Field | Value |
|---|---|
| ID | `AGC-073` |
| Category | `12-impact-recovery` -- Impact & Recovery |
| MITRE Technique | `T1489` Service Stop |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Sysmon EID 1 (sc.exe with stop argument in CommandLine) |
| Time to Triage | 04:00 (service disruption confirmed via state transition, correlated with sc.exe invocation) |
| Affected Systems | `COMPROMISED-HOST-01` (10.10.10.103) |
| Chain | < AGC-072 . next AGC-074 > |
| One-line Summary | Deliberate service disruption via `sc.exe stop` targeting Print Spooler (business-critical service proxy). Additionally, a custom service (AGC073DemoSvc) was created and installed to demonstrate attacker-deployed service manipulation. Sysmon EID 1 captured all sc.exe invocations with full command lines. Windows EID 7045 captured the new service installation. Windows EID 7036 (service state change) was NOT observed on this Windows 11 build, representing a detection gap. The atomic standalone technique exercised here is reused by AGC-080 as the impact phase of its full attack chain. |

## Attacker Perspective

### Tradecraft

**What:** Stop critical services on compromised endpoints to disrupt business operations. This can target infrastructure services (Active Directory, DNS, DHCP), security services (antivirus, SIEM agents), or business applications (databases, web servers, print services). Combined with ransomware (AGC-072), service disruption maximizes pressure on the victim.

**Why an Attacker Uses It Here:**
- Complementary to ransomware: encrypting files AND stopping services creates dual-impact pressure
- Stopping security services (covered separately in AGC-069 for Wazuh) eliminates detection capabilities
- Stopping business services creates immediate operational impact, forcing urgent response
- The `sc.exe` utility is a native Windows tool (living-off-the-land), requiring no additional tooling
- Service disruption can be automated across multiple hosts via lateral movement channels

**Distinction from AGC-069:** AGC-069 specifically targeted the Wazuh SIEM agent as a defense evasion tactic (T1562.001). AGC-073 targets business-critical services as an impact tactic (T1489) -- the goal is disruption, not stealth.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context
- Print Spooler service running (default state)

**Execution:**
```cmd
REM Phase 1: Create and install a custom demonstration service
sc create AGC073DemoSvc binPath= "C:\Windows\System32\svchost.exe -k AGC073Group" start= auto
sc start AGC073DemoSvc

REM Phase 2: Stop a real running service (Print Spooler as business-critical proxy)
sc stop Spooler

REM Phase 3: Remediation -- restart the service
sc start Spooler
```

**Result:**
- AGC073DemoSvc: Created successfully, started (svchost.exe launched as SYSTEM PID 3840), but could not properly register with SCM (expected for stub binary). Service installation captured by EID 7045.
- Print Spooler: Transitioned from Running to STOP_PENDING to Stopped. Successfully restarted afterward. Sysmon EID 1 captured `sc.exe stop Spooler`.

## SOC Perspective

### Detection

**Sysmon EID 1 -- sc.exe stop Spooler (the disruption command):**
```
Process Create:
UtcTime: 2026-09-15 23:35:20.295
ProcessGuid: {eb65e329-d638-6aa9-2b06-000000001400}
ProcessId: 2200
Image: C:\Windows\System32\sc.exe
CommandLine: "C:\WINDOWS\system32\sc.exe" stop Spooler
User: COMPROMISED-01\Administrator
LogonGuid: {eb65e329-d635-6aa9-b4ea-920000000000}
LogonId: 0x92EAB4
IntegrityLevel: High
ParentImage: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

**Sysmon EID 1 -- sc.exe create AGC073DemoSvc (attacker service installation):**
```
Process Create:
UtcTime: 2026-09-15 23:33:58.956
ProcessGuid: {eb65e329-d5e6-6aa9-2106-000000001400}
ProcessId: 5332
Image: C:\Windows\System32\sc.exe
CommandLine: "C:\WINDOWS\system32\sc.exe" create AGC073DemoSvc binPath= "C:\Windows\System32\svchost.exe -k AGC073Group" start= auto
User: COMPROMISED-01\Administrator
LogonId: 0x923C29
```

**Sysmon EID 1 -- svchost.exe spawned by the new service:**
```
Process Create:
UtcTime: 2026-09-15 23:34:01.062
ProcessGuid: {eb65e329-d5e9-6aa9-2306-000000001400}
ProcessId: 3840
Image: C:\Windows\System32\svchost.exe
CommandLine: C:\Windows\System32\svchost.exe -k AGC073Group
User: NT AUTHORITY\SYSTEM
LogonId: 0x3E7
```

**Windows EID 7045 -- New service installed:**
```
A service was installed in the system.
Service Name:  AGC073DemoSvc
Service File Name:  C:\Windows\System32\svchost.exe -k AGC073Group
Service Type:  user mode service
Service Start Type:  auto start
Service Account:  LocalSystem
```

**DETECTION GAP -- EID 7036 absent:**
Windows Event ID 7036 (Service Control Manager -- service entered the stopped/running state) was NOT observed on this Windows 11 build (26100) within 10 minutes of service state changes. This is a detection gap: the traditional EID 7036 detection strategy for service disruption may not be reliable on modern Windows 11 builds.

### Investigation

**Step 1 -- Identify the service stop commands:**
Sysmon EID 1 captured two `sc.exe stop` invocations within 76 seconds:
- 23:34:04 UTC: `sc stop AGC073DemoSvc` (PID 2204, LogonId 0x923C29)
- 23:35:20 UTC: `sc stop Spooler` (PID 2200, LogonId 0x92EAB4)

Both executed under `COMPROMISED-01\Administrator` at High integrity -- consistent with an attacker operating with elevated privileges on a compromised host.

**Step 2 -- Correlate with service installation:**
EID 7045 captured a new service installation (AGC073DemoSvc) 66 seconds before the Spooler disruption. The service used `svchost.exe` as its binary -- a legitimate Windows executable that attackers abuse to blend in with normal service host processes. The `auto start` configuration means the attacker intended this service to persist across reboots.

**Step 3 -- Assess business impact:**
- **Print Spooler (Spooler):** In a production environment, stopping the Print Spooler disrupts all printing operations. For a financial services firm like Ashford Grove Capital, this impacts compliance document printing, client report generation, and audit trail production.
- **AGC073DemoSvc:** Represents an attacker-installed service that could serve as a persistence mechanism, C2 channel, or additional disruption vector.

**Step 4 -- Cross-reference with attack chain:**
Service disruption (T1489) typically occurs alongside ransomware (AGC-072, T1486) in the impact phase. The combination of file encryption AND service disruption creates maximum business impact, consistent with modern ransomware operator playbooks (e.g., LockBit, BlackCat/ALPHV).

### Report

**Verdict: True Positive** -- Deliberate service disruption via sc.exe stop.

**Confidence: High** -- Multiple corroborating evidence sources:
1. Sysmon EID 1 captured the exact `sc.exe stop Spooler` command with Administrator context
2. The Spooler service confirmed transitioned from Running to Stopped
3. An attacker-style service (AGC073DemoSvc) was installed via EID 7045 in the same session
4. The svchost.exe process spawned by the new service ran as SYSTEM (PID 3840)
5. Context: occurs on a confirmed compromised host, following the defense evasion chain (AGC-067-071) and ransomware (AGC-072)

**Response recommendation:**
1. **Immediate service restoration** for any business-critical service found stopped outside maintenance windows
2. **Audit all sc.exe invocations** (Sysmon EID 1 with `CommandLine` containing `stop`, `delete`, or `config`) and correlate with change management records
3. **Monitor EID 7045** (service installation) as a higher-fidelity detection than EID 7036 on modern Windows builds -- new service installations outside approved deployment processes are high-confidence indicators of compromise
4. **Implement service protection policies** via Group Policy: mark critical services as non-stoppable by non-SYSTEM accounts, or use Defender Application Control to restrict `sc.exe` usage
5. **Create a documented critical-service list** and build alerting rules specifically for state changes to services on that list, reducing noise from routine service cycling
6. **Correlate with AGC-072** (ransomware) -- service disruption and file encryption in the same timeline confirm coordinated destructive intent

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Impact (TA0040) | T1489 | Service Stop | sc.exe stop Spooler (PID 2200, Sysmon EID 1) confirmed service transition Running->Stopped. sc.exe stop AGC073DemoSvc (PID 2204). EID 7045 captured attacker service installation. EID 7036 NOT observed (Windows 11 detection gap). | High |

## Evidence

Screenshots: not applicable (text-based evidence collection only).

### Service disruption timeline

```
TIME (UTC)           EVENT                                    EVIDENCE
2026-09-15 23:33:58  sc create AGC073DemoSvc (auto start)     Sysmon EID 1 PID 5332 + EID 7045
2026-09-15 23:34:01  sc start AGC073DemoSvc                   Sysmon EID 1 PID 4900
2026-09-15 23:34:01  svchost.exe -k AGC073Group spawns        Sysmon EID 1 PID 3840 (SYSTEM)
2026-09-15 23:34:04  sc stop AGC073DemoSvc                    Sysmon EID 1 PID 2204
2026-09-15 23:35:20  sc stop Spooler                          Sysmon EID 1 PID 2200
2026-09-15 23:35:25  Spooler verified Stopped                 Get-Service confirmation
2026-09-15 23:35:40  sc start Spooler (remediation)           Service restored to Running
```

### Detection gap: EID 7036 on Windows 11

```
EXPECTED: Windows Event ID 7036 fires when a service enters
the stopped or running state (Service Control Manager log).

OBSERVED: Zero EID 7036 events in the System log within 10
minutes of confirmed Spooler state transitions on Windows 11
build 26100. EID 7045 (service installed) DID fire.

IMPLICATION: SOC detection rules relying solely on EID 7036
for service disruption detection may have blind spots on
modern Windows 11 builds. Sysmon EID 1 (sc.exe CommandLine)
and EID 7045 (new service installation) remain reliable
alternatives.
```
