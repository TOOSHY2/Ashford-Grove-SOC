# AGC-055 — PowerShell Outbound Connection

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-055` |
| Category | `08-command-control` — Command & Control |
| MITRE Technique | `T1071.001` Application Layer Protocol: Web Protocols |
| Verdict | True Positive |
| Confidence | High |
| Time to Detect | Sysmon EID 3 correlation — powershell.exe initiating outbound TCP connections to external IP on web ports |
| Time to Triage | 03:00 (correlate EID 3 Image=powershell.exe with EID 1 CommandLine via ProcessGuid; compare destination against known legitimate endpoints) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) as source; `EXT-ATTACKER-SIM` (10.10.40.10) as C2 destination |
| Chain | ◀ [AGC-054](../AGC-054-rare-destination-domain/README.md) · next [AGC-056](../AGC-056-c2-process-tree/README.md) ▶ |
| One-line Summary | PowerShell (powershell.exe, PID 4104) initiated 4 outbound TCP connections to 10.10.40.10 using 3 distinct cmdlets (Invoke-WebRequest, Invoke-RestMethod, Net.WebClient) across 2 ports (443, 80) within 0.6 seconds. 4 Sysmon EID 3 events captured with Image=powershell.exe. 1 EID 1 event captured the parent process creation with CommandLine showing -ExecutionPolicy Bypass. The key detection signal is the PROCESS IDENTITY: powershell.exe making outbound network connections is itself an anomaly on a standard user workstation — administrative scripting excepted, PowerShell should not be initiating web connections from end-user machines. |

## Attacker Perspective

### Tradecraft

**What:** Attackers use PowerShell's built-in web cmdlets (Invoke-WebRequest, Invoke-RestMethod, Net.WebClient, Net.HttpClient) to establish outbound connections to C2 infrastructure. PowerShell is the preferred tool because:
1. **Pre-installed and trusted:** PowerShell is a signed Microsoft binary, present on every Windows system, and generally allowed by application whitelisting
2. **Rich networking API:** Multiple cmdlets and .NET classes provide HTTP/HTTPS/FTP capabilities without needing external tools
3. **Living-off-the-land:** No additional binaries to download or deploy — the attack uses only built-in Windows capabilities
4. **Execution policy bypass:** `-ExecutionPolicy Bypass` is a command-line parameter, not a system setting — it requires no administrative privilege to use

**Why the process identity matters more than the destination:**
While destination-based detection (known-bad IPs/domains) is valuable, process-based detection catches novel C2 infrastructure. A SOC rule that alerts on "powershell.exe outbound to any external IP" catches C2 regardless of whether the destination is known-bad.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.
- `EXT-ATTACKER-SIM` (10.10.40.10) running HTTP/HTTPS services.

**Steps executed (all timestamps UTC):**

| Step | Time | Cmdlet | URL | Port | Result |
|---|---|---|---|---|---|
| 1 | 22:09:00.433 | Invoke-WebRequest | https://10.10.40.10/beacon | 443 | SSL/TLS trust failure |
| 2 | 22:09:00.552 | Invoke-WebRequest | http://10.10.40.10/agc055-payload | 80 | HTTP 200 OK |
| 3 | 22:09:01.092 | Invoke-RestMethod | https://10.10.40.10/agc055-c2check | 443 | SSL/TLS trust failure |
| 4 | 22:09:01.118 | Net.WebClient | https://10.10.40.10/agc055-stage2 | 443 | SSL/TLS trust failure |

**Key observations:**
- All 4 connections completed TCP handshake (EID 3 captured all 4), even when SSL/TLS subsequently failed
- 3 different PowerShell networking methods used — all produce identical Sysmon EID 3 signatures (Image=powershell.exe)
- HTTP (port 80) returned 200 OK; HTTPS (port 443) reached TCP but SSL certificate trust failed
- All 4 connections within 0.6 seconds — burst pattern, not periodic beacon
- ProcessGuid `{eb65e329-c1f7-6aa9-4d04-000000001400}` links all connections to the same PowerShell process

## SOC Perspective

### Detection

**Sysmon EID 3 — Network Connection (4 events):**

**Event 1: HTTPS to 443 (Invoke-WebRequest)**
```
Network connection detected:
RuleName: -
UtcTime: 2026-09-15 22:09:00.506
ProcessGuid: {eb65e329-c1f7-6aa9-4d04-000000001400}
ProcessId: 4104
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: COMPROMISED-01\Administrator
Protocol: tcp
Initiated: true
SourceIp: 10.10.10.103
SourceHostname: COMPROMISED-01.ashfordgrove.local
SourcePort: 64775
DestinationIp: 10.10.40.10
DestinationPort: 443
DestinationPortName: https
```

**Event 2: HTTP to 80 (Invoke-WebRequest)**
```
Network connection detected:
RuleName: -
UtcTime: 2026-09-15 22:09:00.553
ProcessGuid: {eb65e329-c1f7-6aa9-4d04-000000001400}
ProcessId: 4104
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: COMPROMISED-01\Administrator
Protocol: tcp
Initiated: true
SourceIp: 10.10.10.103
SourceHostname: COMPROMISED-01.ashfordgrove.local
SourcePort: 64776
DestinationIp: 10.10.40.10
DestinationPort: 80
DestinationPortName: http
```

**Event 3: HTTPS to 443 (Invoke-RestMethod)**
```
Network connection detected:
RuleName: -
UtcTime: 2026-09-15 22:09:01.096
ProcessGuid: {eb65e329-c1f7-6aa9-4d04-000000001400}
ProcessId: 4104
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: COMPROMISED-01\Administrator
Protocol: tcp
Initiated: true
SourceIp: 10.10.10.103
SourceHostname: COMPROMISED-01.ashfordgrove.local
SourcePort: 64777
DestinationIp: 10.10.40.10
DestinationPort: 443
DestinationPortName: https
```

**Event 4: HTTPS to 443 (Net.WebClient)**
```
Network connection detected:
RuleName: -
UtcTime: 2026-09-15 22:09:01.127
ProcessGuid: {eb65e329-c1f7-6aa9-4d04-000000001400}
ProcessId: 4104
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
User: COMPROMISED-01\Administrator
Protocol: tcp
Initiated: true
SourceIp: 10.10.10.103
SourceHostname: COMPROMISED-01.ashfordgrove.local
SourcePort: 64778
DestinationIp: 10.10.40.10
DestinationPort: 443
DestinationPortName: https
```

**Sysmon EID 1 — Process Create (1 event, correlated via ProcessGuid):**
```
Process Create:
RuleName: -
UtcTime: 2026-09-15 22:08:55.942
ProcessGuid: {eb65e329-c1f7-6aa9-4d04-000000001400}
ProcessId: 4104
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
FileVersion: 10.0.26100.9278
Description: Windows PowerShell
CommandLine: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc055-sim.ps1
User: COMPROMISED-01\Administrator
```

### Investigation

**Step 1 — Process-identity anomaly detection:**
The core detection question: "Should powershell.exe be making outbound web connections from this workstation?"
- `michael.chen` is a standard user (Finance department) — not an IT administrator
- No administrative scripts are scheduled on this workstation
- PowerShell outbound connections from end-user machines are anomalous by default

**Step 2 — Correlate EID 3 with EID 1 via ProcessGuid:**
ProcessGuid `{eb65e329-c1f7-6aa9-4d04-000000001400}` links the network connections (EID 3) to the process creation (EID 1). The EID 1 CommandLine reveals:
- `-ExecutionPolicy Bypass`: deliberate policy override — a strong indicator of malicious intent on a non-admin workstation
- `-File C:\Temp\agc055-sim.ps1`: script execution from `C:\Temp\` — an unusual and suspicious location (writable by all users, not a standard script path)

**Step 3 — Destination analysis:**
- Destination 10.10.40.10 is in the External zone — confirmed C2 infrastructure from AGC-051/052/053/054
- Multiple connections to same C2 IP using different methods suggests automated C2 framework behavior (trying multiple transport options)

**Step 4 — Detection method comparison:**

| Detection Method | Coverage | What It Catches |
|---|---|---|
| Sysmon EID 3 (Image filter) | powershell.exe outbound | Process identity + destination |
| Sysmon EID 1 (CommandLine) | ExecutionPolicy Bypass | Script execution intent |
| PowerShell Script Block Logging (EID 4104) | Full script content | Actual malicious commands |
| AMSI (Antimalware Scan Interface) | In-memory content | Obfuscated/encoded payloads |

Sysmon EID 3 catches the network behavior regardless of script content. PowerShell Script Block Logging (EID 4104) would reveal the full script, but was not explicitly queried in this investigation.

### Report

**Verdict: True Positive** — PowerShell outbound C2 connections to external infrastructure.

**Confidence: High** — Calibrated assessment:
1. powershell.exe initiated 4 outbound TCP connections to an external IP (10.10.40.10) — anomalous for a standard user workstation.
2. `-ExecutionPolicy Bypass` in the command line indicates deliberate policy override.
3. Script executed from `C:\Temp\` — non-standard, user-writable location.
4. Destination is confirmed C2 infrastructure (AGC-051/052/053/054).
5. 3 different networking methods used (Invoke-WebRequest, Invoke-RestMethod, Net.WebClient) — suggests automated C2 framework probing transport options.
6. Not attributable to any legitimate administrative activity on michael.chen's workstation.

**Response recommendation:**
1. **Isolate the host** immediately — powershell.exe outbound to C2 is an active compromise indicator.
2. **Retrieve and analyze the script** (`C:\Temp\agc055-sim.ps1`) — the script content determines the scope of compromise (data exfiltration, lateral movement staging, persistence installation).
3. **Enable PowerShell Script Block Logging** (EID 4104) if not already active — this captures the full content of every PowerShell script execution, even when obfuscated.
4. **SIEM rule: powershell.exe outbound to non-whitelisted destinations** — alert on any EID 3 where Image contains `powershell.exe` (or `pwsh.exe` for PS 7+) and DestinationIp is not in the approved administrative endpoint list.
5. **Application control:** Consider restricting PowerShell execution on standard user workstations via AppLocker or WDAC, with exceptions only for documented administrative scripts.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Command and Control (TA0011) | T1071.001 | Application Layer Protocol: Web Protocols | 4 Sysmon EID 3: powershell.exe (PID 4104) outbound to 10.10.40.10 on ports 443/80. 3 cmdlets: Invoke-WebRequest, Invoke-RestMethod, Net.WebClient. EID 1: CommandLine shows -ExecutionPolicy Bypass -File C:\Temp\agc055-sim.ps1. ProcessGuid correlation confirms single session. | High |
| Execution (TA0002) | T1059.001 | Command and Scripting Interpreter: PowerShell | EID 1: powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc055-sim.ps1. Policy override + script from temp directory. | High |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### PowerShell outbound connection summary

```
Source:     10.10.10.103 (COMPROMISED-HOST-01)
Dest:       10.10.40.10 (EXT-ATTACKER-SIM)
Process:    powershell.exe (PID 4104)
GUID:       {eb65e329-c1f7-6aa9-4d04-000000001400}
User:       COMPROMISED-01\Administrator

Connection  | Time (UTC)         | Src Port | Dst Port | Method
------------|--------------------|---------:|---------:|------------------
1           | 22:09:00.506       | 64775    | 443      | Invoke-WebRequest
2           | 22:09:00.553       | 64776    | 80       | Invoke-WebRequest
3           | 22:09:01.096       | 64777    | 443      | Invoke-RestMethod
4           | 22:09:01.127       | 64778    | 443      | Net.WebClient

Total duration: 0.621 seconds (burst, not periodic)
Sysmon EID 3: 4 events (all captured -- TCP handshake completed)
Sysmon EID 1: 1 event (CommandLine: -ExecutionPolicy Bypass -File C:\Temp\...)
```

### Process creation evidence (EID 1)

```
Process Create:
UtcTime: 2026-09-15 22:08:55.942
ProcessGuid: {eb65e329-c1f7-6aa9-4d04-000000001400}
ProcessId: 4104
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: powershell.exe -ExecutionPolicy Bypass -File C:\Temp\agc055-sim.ps1
User: COMPROMISED-01\Administrator

Key indicators:
  - ExecutionPolicy Bypass: deliberate policy override
  - Script from C:\Temp\: non-standard writable location
  - Administrator context: elevated privilege
```
